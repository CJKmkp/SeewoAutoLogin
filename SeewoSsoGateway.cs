using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace SeewoAutoLogin
{
    /// <summary>
    /// 本地 HTTP 服务器，提供 SSO 网关服务。
    /// </summary>
    public class SeewoSsoGateway : IDisposable
    {
        private HttpListener _listener;
        private CancellationTokenSource _cts;
        private readonly SemaphoreSlim _loginGate = new SemaphoreSlim(1, 1);
        private readonly SeewoAuthService _authService;
        private readonly Func<PluginConfig> _getConfig;
        private readonly Func<SeewoAccount, bool> _tryRestoreQrSession;
        private readonly Func<IReadOnlyList<SeewoAccount>> _getVisibleAccounts;
        private readonly Action<SeewoAccount> _onLoginSuccess;
        private readonly Action<SeewoAccount, string> _onQrTokenValidated;
        private readonly SeewoUserListRotationService _userListRotation;

        public int Port { get; set; } = SeewoExpectedPort;
        public bool IsRunning => _listener?.IsListening == true;

        /// <summary>
        /// 希沃固定请求的端口。网关必须占用它，否则希沃拿不到账号列表，快捷登录入口不会出现。
        /// </summary>
        public const int SeewoExpectedPort = 24300;

        /// <summary>当前是否没有监听在希沃期望的端口上（此时快捷登录不会生效，需要记录告警）。</summary>
        public bool IsPortMismatched => Port != SeewoExpectedPort;

        /// <summary>实际监听端口发生变化时触发。</summary>
        public event Action<int> PortChanged;

        /// <summary>
        /// 端口确实被希沃 EasiAgent 占用时，由上层决定是否结束它（返回 true 才结束）。
        /// 未注入回调时沿用旧行为：直接结束占用端口的受信任 EasiAgent。
        /// </summary>
        public Func<int, string, bool> ConfirmStopEasiAgent { get; set; }

        private volatile bool _ucHostProxyEnabled;

        /// <summary>UcHost 接管模式下，扫码登录 auth/checkToken 成功后触发（参数为请求 token 与云端响应 JSON）。</summary>
        public event Action<string, string> ScanLoginCaptured;

        private static readonly string[] HopByHopHeaders =
        {
            "Connection", "Keep-Alive", "Proxy-Connection", "Proxy-Authenticate",
            "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade", "Host", "Date"
        };

        private static readonly HttpClient UcHostClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(130)
        };

        // SSO 高频日志节流：希沃在登录界面开着时会每 2 秒轮询一次，每次都写两行会把日志刷爆。
        // 只对成功路径做每分钟一条的节流；失败、异常、拒绝等路径不节流。
        private const int SsologinLogIntervalSeconds = 60;
        private static readonly object SsologinSourceLogGate = new object();
        private static readonly object SsologinServedLogGate = new object();
        private static DateTime _lastSsologinSourceLogUtc = DateTime.MinValue;
        private static DateTime _lastSsologinServedLogUtc = DateTime.MinValue;

        private const int MaxRequestsPerMinute = 120;
        private readonly ConcurrentDictionary<string, RequestWindow> _requestWindows = new();

        private sealed class RequestWindow
        {
            public int Count;
            public DateTime WindowStartUtc;
        }

        public void SetUcHostProxyEnabled(bool enabled) => _ucHostProxyEnabled = enabled;

        public SeewoSsoGateway(
            SeewoAuthService authService,
            Func<PluginConfig> getConfig,
            Func<SeewoAccount, bool> tryRestoreQrSession,
            Func<IReadOnlyList<SeewoAccount>> getVisibleAccounts,
            Action<SeewoAccount> onLoginSuccess,
            Action<SeewoAccount, string> onQrTokenValidated,
            SeewoUserListRotationService userListRotation)
        {
            _authService = authService;
            _getConfig = getConfig;
            _tryRestoreQrSession = tryRestoreQrSession;
            _getVisibleAccounts = getVisibleAccounts;
            _onLoginSuccess = onLoginSuccess;
            _onQrTokenValidated = onQrTokenValidated;
            _userListRotation = userListRotation;
        }

        private const string SeeSoLocalHost = "local.id.seewo.com";

        public void Start()
        {
            if (IsRunning) return;

            if (!HostsFileService.EnsureLoopbackMapping(out var hostsError))
            {
                // 不阻断网关启动：UcHost 代理只依赖 127.0.0.1。但没有 hosts 映射时，
                // 希沃请求 local.id.seewo.com 会解析到真实服务器，快捷登录不会出现，必须留痕。
                Log($"[ERROR] hosts 映射不可用（{HostsFileService.DescribeState()}：{hostsError}）；希沃快捷登录可能不会出现");
            }

            // 1) 首选端口：只有确认占用者是希沃 EasiAgent 时才结束它，并在端口释放前重试。
            if (TryStartAtPort(SeewoExpectedPort, allowEasiAgentHandoff: true, out var error))
            {
                CompleteStartup(SeewoExpectedPort);
                return;
            }

            // 权限不足等非占用类问题：如实抛出，不用备用端口掩盖。
            if (error is InvalidOperationException || !PortInspection.IsListening(SeewoExpectedPort))
                throw error ?? new InvalidOperationException($"SSO 网关无法监听端口 {SeewoExpectedPort}");

            // 2) EasiAgent 仍占着端口（用户拒绝结束或反复被希沃拉起）：必须报错而不是换端口，
            //    否则程序“看起来正常”，用户却怎么都等不到快捷登录入口。
            if (PortInspection.TryFindTrustedEasiAgent(out var easiPid, out _))
            {
                throw new InvalidOperationException(
                    $"希沃 EasiAgent（pid={easiPid}）仍占用端口 {SeewoExpectedPort}，SSO 快捷登录无法生效。",
                    error);
            }

            // 3) 首选端口被其它程序占用：退到备用端口保证网关可用（UcHost 代理仍能工作），
            //    但希沃固定请求 24300，在它释放前快捷登录入口不会出现。
            for (var port = SeewoExpectedPort + 1; port <= SeewoExpectedPort + 9; port++)
            {
                if (TryStartAtPort(port, allowEasiAgentHandoff: false, out _))
                {
                    Log($"[WARN] 首选端口 {SeewoExpectedPort} 被其它程序占用" +
                        $"（{PortInspection.DescribeListener(SeewoExpectedPort)}），SSO 网关已改用 {port}；" +
                        $"希沃固定请求 {SeewoExpectedPort}，在其被释放前不会出现快捷登录入口。");
                    CompleteStartup(port);
                    return;
                }
            }

            throw new InvalidOperationException(
                $"SSO 网关启动失败：端口 {SeewoExpectedPort}~{SeewoExpectedPort + 9} 均不可用。" +
                $"最后一次错误：{error?.Message ?? "未知"}", error);
        }

        private void CompleteStartup(int actualPort)
        {
            Port = actualPort;
            if (actualPort != SeewoExpectedPort)
            {
                try { PortChanged?.Invoke(actualPort); } catch { }
            }
            _ = Task.Run(() => ListenLoop(_listener, _cts.Token));
            Log($"SSO 网关已启动: http://localhost:{Port}");
        }

        /// <summary>
        /// 尝试在指定端口启动监听。allowEasiAgentHandoff 为 true 时，仅在端口确实被
        /// 受信任的希沃 EasiAgent 占用且允许结束它之后才重试，避免误杀其它进程。
        /// </summary>
        private bool TryStartAtPort(int port, bool allowEasiAgentHandoff, out Exception error)
        {
            error = null;
            var maxRounds = allowEasiAgentHandoff ? 3 : 1;
            bool? userApproved = null;

            for (var round = 1; round <= maxRounds; round++)
            {
                try
                {
                    ResetListener(port);
                    _listener.Start();
                    if (round > 1) Log($"已接管端口 {port}（第 {round} 轮重试成功）");
                    return true;
                }
                catch (Exception ex)
                {
                    error = ex;

                    // 权限不足（需要管理员 / URL ACL）：换端口或重试都无意义。
                    if (IsAccessDenied(ex))
                    {
                        Log($"[ERROR] SSO 网关无法监听端口 {port}：拒绝访问（需要管理员权限）");
                        throw new InvalidOperationException(
                            $"以当前权限无法监听本地 SSO 网关（拒绝访问，端口 {port}）。请以管理员身份运行 ICC-CE。", ex);
                    }

                    if (!allowEasiAgentHandoff) return false;
                    if (!PortInspection.IsListening(port)) return false; // 不是端口占用

                    Log($"SSO 网关端口 {port} 已被占用（第 {round}/{maxRounds} 轮）; 占用者={PortInspection.DescribeListener(port)}");

                    if (userApproved == null)
                    {
                        // 只询问一次，后续轮次沿用用户的选择，避免反复弹窗。
                        if (!TryAskToStopEasiAgent(port, out var askError))
                        {
                            if (!string.IsNullOrEmpty(askError)) Log(askError);
                            return false;
                        }
                        userApproved = true;
                    }

                    var deadline = DateTime.UtcNow.AddSeconds(15);
                    while (DateTime.UtcNow < deadline && PortInspection.IsListening(port))
                    {
                        var owners = PortInspection.GetListeners(port);
                        var hasEasiAgentOwner = owners.Any(owner => owner.IsTrustedEasiAgent);
                        var onlySystemHosted = owners.Count > 0 && owners.All(IsSystemHostedOwner);

                        if (owners.Count > 0 && !hasEasiAgentOwner && !onlySystemHosted)
                        {
                            // 端口已转由其它用户态程序占用，再等下去也不会变成 EasiAgent。
                            Log($"端口 {port} 已转由其它程序占用（{string.Join("; ", owners.Select(o => o.ToString()))}），停止等待");
                            break;
                        }

                        if (hasEasiAgentOwner || onlySystemHosted ||
                            (owners.Count == 0 && PortInspection.TryFindTrustedEasiAgent(out _, out _)))
                        {
                            // 希沃会重新拉起 EasiAgent：等待期间持续清理，直到端口空出来。
                            // 通过 http.sys 注册时占用者显示为 System/svchost，真正的注册者仍是 EasiAgent。
                            Log($"端口 {port} 仍被占用，结束希沃 EasiAgent");
                            PortInspection.TryStopTrustedEasiAgent(out _);
                        }
                        Thread.Sleep(500);
                    }

                    if (!PortInspection.IsListening(port))
                    {
                        Log($"端口 {port} 已释放，重新尝试绑定");
                        continue;
                    }

                    Log($"[WARN] 端口 {port} 等待 15 秒后仍被占用");
                }
            }
            return false;
        }

        /// <summary>
        /// 端口被占用时确认是否结束希沃 EasiAgent。
        /// 只有占用者确实是受信任的 EasiAgent（或权限受限但确实存在 EasiAgent）时才继续。
        /// </summary>
        private bool TryAskToStopEasiAgent(int port, out string error)
        {
            error = null;
            var owners = PortInspection.GetListeners(port);
            var easiOwner = owners.FirstOrDefault(owner => owner.IsTrustedEasiAgent);
            int pid;
            string path;

            if (easiOwner != null)
            {
                pid = easiOwner.ProcessId;
                path = easiOwner.ExecutablePath;
            }
            else if ((owners.Count == 0 || owners.All(IsSystemHostedOwner)) &&
                     PortInspection.TryFindTrustedEasiAgent(out pid, out path))
            {
                // 两种情况沿用旧行为：
                // 1) 权限不足读不到占用者；
                // 2) 端口由 http.sys 托管，占用者显示为 System/svchost，真正的注册者通常是 EasiAgent。
            }
            else
            {
                error = $"端口 {port} 被其它程序占用（{PortInspection.DescribeListener(port)}），" +
                        "未发现占用该端口的希沃 EasiAgent，将尝试备用端口";
                return false;
            }

            var approved = true;
            try
            {
                if (ConfirmStopEasiAgent != null) approved = ConfirmStopEasiAgent(pid, path);
            }
            catch (Exception ex)
            {
                Log($"询问是否结束 EasiAgent 失败: {ex.GetType().Name}");
                approved = false;
            }

            if (!approved)
            {
                error = $"未同意结束希沃 EasiAgent(pid={pid})，将尝试备用端口";
                return false;
            }

            Log($"正在结束希沃 EasiAgent; pid={pid}; path={path}");
            if (!PortInspection.TryStopTrustedEasiAgent(out var stopError))
            {
                error = $"结束希沃 EasiAgent 失败: {stopError}";
                return false;
            }
            return true;
        }

        /// <summary>
        /// 占用者是否为 http.sys / 系统进程。通过 URL 前缀注册监听的程序（包括 EasiAgent）
        /// 在 TCP 表里显示为 System(pid=4) 或 svchost，而不是注册者自身。
        /// </summary>
        private static bool IsSystemHostedOwner(PortOwnerInfo owner)
        {
            if (owner == null) return false;
            if (owner.ProcessId == 4) return true;
            if (string.IsNullOrEmpty(owner.ProcessName)) return false;
            return string.Equals(owner.ProcessName, "System", StringComparison.OrdinalIgnoreCase)
                || string.Equals(owner.ProcessName, "svchost", StringComparison.OrdinalIgnoreCase)
                || string.Equals(owner.ProcessName, "http", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>结束受信任路径的希沃 EasiAgent（供设置页显式调用）。</summary>
        public bool StopTrustedEasiAgent()
        {
            try
            {
                if (PortInspection.TryStopTrustedEasiAgent(out var error)) return true;
                if (!string.IsNullOrEmpty(error)) Log($"结束希沃 EasiAgent 失败: {error}");
                return false;
            }
            catch (Exception ex)
            {
                Log($"结束希沃 EasiAgent 异常: {ex.GetType().Name}");
                return false;
            }
        }

        private void ResetListener(int port)
        {
            try { _listener?.Close(); } catch { }
            _cts?.Dispose();
            _cts = new CancellationTokenSource();
            _listener = new HttpListener();
            _listener.Prefixes.Add($"http://localhost:{port}/");
            _listener.Prefixes.Add($"http://127.0.0.1:{port}/");
            try
            {
                _listener.Prefixes.Add($"http://{SeeSoLocalHost}:{port}/");
            }
            catch (Exception ex)
            {
                // 该前缀是希沃识别快捷登录的关键，但注册失败不应让 UcHost 代理一起不可用：
                // 记录明确错误后继续，由调用方决定是否提示。
                Log($"[ERROR] 注册 {SeeSoLocalHost} 前缀失败: {ex.GetType().Name} - {ex.Message}；" +
                    "希沃快捷登录可能不可用，UcHost 代理仍可通过 127.0.0.1 工作");
            }
        }

        private static bool IsAccessDenied(Exception ex)
        {
            for (var current = ex; current != null; current = current.InnerException)
            {
                if (current is HttpListenerException listenerEx && listenerEx.ErrorCode == 5) return true;
                var message = current.Message ?? "";
                if (message.Contains("拒绝访问") ||
                    message.IndexOf("Access is denied", StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }
            return false;
        }

        private static bool IsLocalOrigin(string origin)
        {
            if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri)) return false;
            return IsAllowedGatewayHost(uri.Host);
        }

        private static bool IsAllowedGatewayHost(string host)
        {
            if (string.IsNullOrWhiteSpace(host)) return false;
            return string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
                || host == "127.0.0.1"
                || host == "::1"
                || host == "[::1]"
                || string.Equals(host, SeeSoLocalHost, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>本地网关 API 路径（需要额外 CSRF/来源校验），与 UcHost 透明代理路径区分。</summary>
        private static bool IsGatewayApiPath(string path)
        {
            return path.StartsWith("/getData/", StringComparison.OrdinalIgnoreCase)
                || path.Equals("/savedata", StringComparison.OrdinalIgnoreCase)
                || path.Equals("/saveData", StringComparison.OrdinalIgnoreCase);
        }

        public void Stop()
        {
            var cts = _cts;
            var listener = _listener;
            _cts = null;
            _listener = null;
            try { cts?.Cancel(); } catch { }
            try { listener?.Stop(); } catch { }
            try { listener?.Close(); } catch { }
            try { cts?.Dispose(); } catch { }
            Log("SSO 网关已停止");
        }

        private async Task ListenLoop(HttpListener listener, CancellationToken ct)
        {
            while (!ct.IsCancellationRequested && listener?.IsListening == true)
            {
                try
                {
                    var context = await listener.GetContextAsync();
                    _ = Task.Run(() => HandleRequest(context), ct);
                }
                catch (HttpListenerException ex)
                {
                    if (ct.IsCancellationRequested) break;
                    // 监听异常若直接退出会导致“界面显示运行中、实际不再响应”的静默失效。
                    Log($"[ERROR] SSO 监听循环异常: {ex.ErrorCode} {ex.Message}; 1 秒后重试");
                    try { await Task.Delay(1000, ct); } catch { break; }
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    if (ct.IsCancellationRequested) break;
                    Log($"[ERROR] SSO 监听循环未知异常: {ex.GetType().Name} - {ex.Message}; 1 秒后重试");
                    try { await Task.Delay(1000, ct); } catch { break; }
                }
            }
        }

        private bool AllowRequest(string key)
        {
            var now = DateTime.UtcNow;
            var window = _requestWindows.GetOrAdd(key, _ => new RequestWindow { WindowStartUtc = now });
            lock (window)
            {
                if ((now - window.WindowStartUtc).TotalMinutes >= 1)
                {
                    window.WindowStartUtc = now;
                    window.Count = 0;
                }
                window.Count++;
                return window.Count <= MaxRequestsPerMinute;
            }
        }

        private static bool ShouldLogThrottled(object gate, ref DateTime lastUtc)
        {
            lock (gate)
            {
                if ((DateTime.UtcNow - lastUtc).TotalSeconds < SsologinLogIntervalSeconds) return false;
                lastUtc = DateTime.UtcNow;
                return true;
            }
        }

        private static bool ShouldLogSsologinSource() => ShouldLogThrottled(SsologinSourceLogGate, ref _lastSsologinSourceLogUtc);
        private static bool ShouldLogSsologinServed() => ShouldLogThrottled(SsologinServedLogGate, ref _lastSsologinServedLogUtc);

        private static string TruncateForLog(string value, int max)
            => string.IsNullOrEmpty(value) || value.Length <= max ? (value ?? "") : value.Substring(0, max);

        private async Task HandleRequest(HttpListenerContext context)
        {
            var req = context.Request;
            var resp = context.Response;
            var path = req.Url?.AbsolutePath?.TrimEnd('/') ?? "";
            var remoteAddress = req.RemoteEndPoint?.Address;
            var remoteKey = remoteAddress?.ToString() ?? "unknown";
            var isGatewayApi = IsGatewayApiPath(path);

            try
            {
                // 安全：网关只服务本机（希沃通过 hosts 映射访问 127.0.0.1）。
                // 注册 local.id.seewo.com 前缀后 http.sys 会把端口绑到所有网卡，
                // 必须显式校验来源，否则同一局域网内任何机器伪造 Host 头即可拉取账号列表并换取登录令牌。
                if (remoteAddress != null && !IPAddress.IsLoopback(remoteAddress))
                {
                    Log($"拒绝非本机来源的 SSO 请求: {remoteAddress} {req.HttpMethod} {path}");
                    resp.StatusCode = 403;
                    await WriteJson(resp, new { message = "forbidden_remote", statusCode = "403" });
                    return;
                }

                // Host 白名单：避免以后误加通配前缀时把网关暴露给任意本机进程或网页。
                if (!IsAllowedGatewayHost(req.Url?.Host))
                {
                    Log($"拒绝未知 Host 的 SSO 请求: {req.Url?.Host} {req.HttpMethod} {path}");
                    resp.StatusCode = 404;
                    await WriteJson(resp, new { message = "not_found", statusCode = "404" });
                    return;
                }

                if (!AllowRequest(remoteKey))
                {
                    Log($"SSO 网关限流：{remoteKey} 超过每分钟 {MaxRequestsPerMinute} 次，返回 429");
                    resp.StatusCode = 429;
                    await WriteJson(resp, new { message = "too_many_requests", statusCode = "429" });
                    return;
                }

                // CORS：只放行本机来源。外部网页的跨源请求不能当作 CSRF 跳板。
                var origin = req.Headers["Origin"];
                if (!string.IsNullOrEmpty(origin))
                {
                    if (IsLocalOrigin(origin))
                    {
                        resp.Headers.Add("Access-Control-Allow-Origin", origin);
                        resp.Headers.Add("Vary", "Origin");
                    }
                    else if (origin.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                          || origin.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                    {
                        if (isGatewayApi || !_ucHostProxyEnabled)
                        {
                            Log($"拒绝外部 Origin 的 SSO 请求: {origin} {req.HttpMethod} {path}");
                            resp.StatusCode = 403;
                            await WriteJson(resp, new { message = "forbidden_origin", statusCode = "403" });
                            return;
                        }
                        // UcHost 代理路径：希沃登录页可能带外部 Origin，放行但不回 CORS 头。
                    }
                }
                else
                {
                    // 不带 Origin 的请求（<img>、表单导航）浏览器照样会发。
                    // 只认 Sec-Fetch-Site，不能看 Referer：希沃自己的界面就带 easinote5.seewo.com 的 Referer。
                    if (isGatewayApi &&
                        string.Equals(req.Headers["Sec-Fetch-Site"], "cross-site", StringComparison.OrdinalIgnoreCase))
                    {
                        Log($"拒绝疑似跨站的 SSO 请求: {req.HttpMethod} {path}");
                        resp.StatusCode = 403;
                        await WriteJson(resp, new { message = "forbidden_origin", statusCode = "403" });
                        return;
                    }
                }

                resp.Headers.Add("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
                resp.Headers.Add("Access-Control-Allow-Headers", "Content-Type, Authorization");

                if (req.HttpMethod == "OPTIONS")
                {
                    resp.StatusCode = 200;
                    resp.Close();
                    return;
                }

                // GET /getData/SSOLOGIN — 返回账号列表
                if (req.HttpMethod == "GET" && path.Equals("/getData/SSOLOGIN", StringComparison.OrdinalIgnoreCase))
                {
                    if (ShouldLogSsologinSource())
                        Log($"SSOLOGIN 来源: remote={remoteKey}; ua={TruncateForLog(req.UserAgent, 80)}; " +
                            $"referer={TruncateForLog(req.Headers["Referer"], 120)}（高频请求，日志已节流为每分钟一条）");

                    var config = _getConfig();
                    var sourceAccounts = (_getVisibleAccounts?.Invoke() ?? (IReadOnlyList<SeewoAccount>)Array.Empty<SeewoAccount>())
                        .Where(a => !string.IsNullOrEmpty(a.Username))
                        .ToList();

                    List<SeewoAccount> visibleAccounts = sourceAccounts;
                    var routeIndex = 0;
                    if (config.UserListRotationEnabled && sourceAccounts.Count > SeewoUserListRotationService.NormalizeGroupSize(config.UserListRotationGroupSize) && _userListRotation != null)
                    {
                        visibleAccounts = _userListRotation.SelectAccountsForRequest(sourceAccounts, out routeIndex, config.UserListRotationGroupSize).ToList();
                    }

                    var accounts = visibleAccounts
                        .Select(a => new Dictionary<string, string>
                        {
                            { "pt_nickname", a.DisplayName ?? a.UserInfo?.NickName ?? a.Username },
                            { "pt_appid", a.Id },
                            { "pt_userid", a.Id },
                            { "pt_username", a.UserInfo?.RealName ?? a.DisplayName ?? a.Username },
                            { "pt_photourl", a.UserInfo?.PhotoUrl ?? "" }
                        })
                        .ToList();

                    await WriteJson(resp, new { message = "success", statusCode = "200", data = accounts });
                    if (ShouldLogSsologinServed())
                        Log(config.UserListRotationEnabled
                            ? $"SSOLOGIN: 返回第 {routeIndex + 1} 组 {accounts.Count} 个账号（高频请求，日志已节流为每分钟一条）"
                            : $"SSOLOGIN: 返回 {accounts.Count} 个账号（高频请求，日志已节流为每分钟一条）");
                    return;
                }

                // GET /getData/SSOLOGIN/{userid} — 用指定账号登录，设置 token cookie
                if (req.HttpMethod == "GET" && path.StartsWith("/getData/SSOLOGIN/", StringComparison.OrdinalIgnoreCase))
                {
                    var userId = path.Substring("/getData/SSOLOGIN/".Length);
                    if (ShouldLogSsologinServed())
                        Log($"SSOLOGIN/{{userid}}: 收到请求 userId={userId}（高频请求，日志已节流为每分钟一条）");

                    var config = _getConfig();
                    var account = config.Accounts.FirstOrDefault(a => a.Id == userId || a.Username == userId);

                    if (account == null)
                    {
                        resp.StatusCode = 404;
                        await WriteJson(resp, new { message = "user_not_found", statusCode = "404" });
                        return;
                    }

                    // 希沃短时间会并发发起多个 SSOLOGIN 请求，而 authService 只持有一份 token / userInfo，
                    // 并发登录会互相覆盖（A 的请求可能拿到 B 的 token），客户端表现为“登录信息过期”。
                    // 这里串行化登录/换发过程，保证每个请求返回的 token 都属于它自己的账号。
                    await _loginGate.WaitAsync().ConfigureAwait(false);
                    try
                    {
                        SeewoLoginResult loginResult;
                        if (string.IsNullOrEmpty(account.Password))
                        {
                            if (!_authService.IsSessionFor(account))
                                _tryRestoreQrSession?.Invoke(account);

                            if (_authService.IsSessionFor(account))
                            {
                                loginResult = await _authService.ExchangeCurrentTokenAsync();
                                if (!loginResult.Success)
                                {
                                    resp.StatusCode = 401;
                                    await WriteJson(resp, new { message = "qr_token_invalid", statusCode = "401", detail = loginResult.ErrorMessage });
                                    Log($"SSOLOGIN/{userId}: Token 换发失败，需要重新扫码; reason={loginResult.ErrorMessage}");
                                    return;
                                }
                                _onQrTokenValidated?.Invoke(account, loginResult.Token);
                                Log($"SSOLOGIN/{userId}: Token 换发成功，已更新持久化 Token");
                            }
                            else
                            {
                                // GetCurrentLoginResult() 会把**别人的** token 原样交出去，多人共用时会串号。
                                // 宁可要求重新扫码，也不能替别人登录。
                                resp.StatusCode = 401;
                                await WriteJson(resp, new
                                {
                                    message = "qr_credential_missing",
                                    statusCode = "401",
                                    detail = "该账号没有可用的扫码凭据，需要重新扫码添加"
                                });
                                Log($"SSOLOGIN/{userId}: 无可用扫码凭据且当前会话不属该账号，要求重新扫码");
                                return;
                            }
                        }
                        else
                        {
                            loginResult = await _authService.LoginAsync(account.Username, account.Password);
                        }

                        if (!loginResult.Success)
                        {
                            resp.StatusCode = 401;
                            await WriteJson(resp, new { message = "login_failed", statusCode = "401", detail = loginResult.ErrorMessage });
                            Log($"SSOLOGIN/{userId}: 登录失败 - {loginResult.ErrorMessage}");
                            return;
                        }

                        // 设置 token cookie（多种方式确保客户端能读取）
                        resp.Headers.Set("Set-Cookie", $"pt_token={loginResult.Token}; Path=/; HttpOnly; SameSite=Lax");
                        resp.Headers.Set("X-Auth-Token", loginResult.Token);

                        await WriteJson(resp, new { message = "success", statusCode = "200", data = new { pt_token = loginResult.Token } });

                        // 更新账号信息
                        account.UserInfo = loginResult.UserInfo;
                        _onLoginSuccess?.Invoke(account);

                        Log($"SSOLOGIN/{userId}: 登录成功 - {loginResult.UserInfo?.NickName}");
                        return;
                    }
                    finally
                    {
                        _loginGate.Release();
                    }
                }

                // GET /getData/SSOLOGOUT — 登出
                if (req.HttpMethod == "GET" && path.Equals("/getData/SSOLOGOUT", StringComparison.OrdinalIgnoreCase))
                {
                    _authService.Logout();
                    await WriteJson(resp, new { message = "success", statusCode = "200" });
                    return;
                }

                // POST /savedata — 希沃白板保存用户数据
                if (req.HttpMethod == "POST" && path.Equals("/savedata", StringComparison.OrdinalIgnoreCase))
                {
                    await WriteJson(resp, new { message = "success", statusCode = "200" });
                    return;
                }

                // POST /saveData — 别名
                if (req.HttpMethod == "POST" && path.Equals("/saveData", StringComparison.OrdinalIgnoreCase))
                {
                    await WriteJson(resp, new { message = "success", statusCode = "200" });
                    return;
                }

                // UcHost 接管代理：非 broker 路径在接管模式下透明转发到真实希沃云端
                if (_ucHostProxyEnabled)
                {
                    await ProxyToUcHost(context);
                    return;
                }

                // 404
                resp.StatusCode = 404;
                await WriteJson(resp, new { message = "not_found", statusCode = "404" });
            }
            catch (Exception ex)
            {
                try
                {
                    resp.StatusCode = 500;
                    await WriteJson(resp, new { message = "internal_error", statusCode = "500", detail = ex.Message });
                }
                catch { }
            }
        }

        private static async Task WriteJson(HttpListenerResponse resp, object data)
        {
            var json = JsonSerializer.Serialize(data);
            var bytes = Encoding.UTF8.GetBytes(json);
            resp.ContentType = "application/json; charset=utf-8";
            resp.ContentLength64 = bytes.Length;
            await resp.OutputStream.WriteAsync(bytes, 0, bytes.Length);
            resp.Close();
        }

        /// <summary>
        /// 透明转发到真实希沃云端 https://id.seewo.com。二维码请求的 qrkey 通过 Set-Cookie
        /// 回传给白板五，后续轮询与 checkToken 原样往返；auth/checkToken 成功后上报捕获事件。
        /// </summary>
        private async Task ProxyToUcHost(HttpListenerContext context)
        {
            var req = context.Request;
            var resp = context.Response;

            if ((req.Url?.AbsolutePath ?? "").EndsWith("/scan/qrcode", StringComparison.OrdinalIgnoreCase))
                Log("UcHost 代理: 希沃白板请求登录二维码，接管已生效");

            using var message = new HttpRequestMessage(new HttpMethod(req.HttpMethod), "https://id.seewo.com" + req.RawUrl);
            CopyForwardHeaders(req, message);

            byte[] body = Array.Empty<byte>();
            if (!string.IsNullOrEmpty(req.HttpMethod) && !req.HttpMethod.Equals("GET", StringComparison.OrdinalIgnoreCase))
            {
                using var input = new MemoryStream();
                await req.InputStream.CopyToAsync(input);
                body = input.ToArray();
                if (body.Length > 0)
                {
                    message.Content = new ByteArrayContent(body);
                    if (!string.IsNullOrEmpty(req.ContentType))
                        message.Content.Headers.TryAddWithoutValidation("Content-Type", req.ContentType);
                }
            }

            using var response = await UcHostClient.SendAsync(message, HttpCompletionOption.ResponseHeadersRead);
            resp.StatusCode = (int)response.StatusCode;

            foreach (var header in response.Headers)
            {
                if (IsHopByHop(header.Key)) continue;
                foreach (var value in header.Value)
                    resp.Headers.Add(header.Key, NormalizeRelayedHeader(header.Key, value));
            }

            var responseBody = await response.Content.ReadAsByteArrayAsync();
            foreach (var header in response.Content.Headers)
            {
                if (header.Key == "Content-Type")
                    resp.ContentType = string.Join(", ", header.Value);
                else if (header.Key != "Content-Length" && !IsHopByHop(header.Key))
                    foreach (var value in header.Value)
                        resp.Headers.Add(header.Key, value);
            }

            resp.ContentLength64 = responseBody.LongLength;
            await resp.OutputStream.WriteAsync(responseBody, 0, responseBody.Length);
            resp.Close();

            if (req.HttpMethod.Equals("POST", StringComparison.OrdinalIgnoreCase) &&
                (req.Url?.AbsolutePath ?? "").EndsWith("/auth/checkToken", StringComparison.OrdinalIgnoreCase) &&
                response.IsSuccessStatusCode && ScanLoginCaptured != null)
            {
                var token = ExtractToken(body);
                var json = Encoding.UTF8.GetString(responseBody);
                Log($"UcHost 代理: auth/checkToken 成功，上报扫码登录捕获; token-present={!string.IsNullOrEmpty(token)}");
                ScanLoginCaptured?.Invoke(token, json);
            }
        }

        private static void CopyForwardHeaders(HttpListenerRequest req, HttpRequestMessage message)
        {
            foreach (var key in req.Headers.AllKeys)
            {
                if (key == null || IsHopByHop(key)) continue;
                var value = req.Headers[key];
                if (string.IsNullOrEmpty(value)) continue;
                if (key.Equals("Cookie", StringComparison.OrdinalIgnoreCase))
                {
                    message.Headers.TryAddWithoutValidation("Cookie", value);
                }
                else if (string.Equals(key, "Content-Type", StringComparison.OrdinalIgnoreCase) ||
                         string.Equals(key, "Content-Length", StringComparison.OrdinalIgnoreCase))
                {
                    continue; // 由请求体内容接管
                }
                else
                {
                    message.Headers.TryAddWithoutValidation(key, value);
                }
            }
        }

        private static bool IsHopByHop(string name)
        {
            foreach (var h in HopByHopHeaders)
            {
                if (string.Equals(name, h, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        /// <summary>
        /// 回传响应头时将 Set-Cookie 里的 Domain 与 Secure 去掉：本地是 http://127.0.0.1，
        /// 云端给的 Domain/Secure 会让白板五无法按请求地址存/发 qrkey 这类 cookie。
        /// </summary>
        private static string NormalizeRelayedHeader(string name, string value)
        {
            if (!string.Equals(name, "Set-Cookie", StringComparison.OrdinalIgnoreCase) || string.IsNullOrEmpty(value))
                return value;

            var parts = value.Split(';');
            var kept = new List<string>(parts.Length);
            foreach (var part in parts)
            {
                var trimmed = part.Trim();
                var lower = trimmed.ToLowerInvariant();
                if (lower.StartsWith("domain=", StringComparison.Ordinal))
                    continue;
                if (string.Equals(lower, "secure", StringComparison.Ordinal))
                    continue;
                if (trimmed.Length > 0) kept.Add(trimmed);
            }
            return string.Join("; ", kept);
        }

        private static string ExtractToken(byte[] body)
        {
            if (body == null || body.Length == 0) return "";
            try
            {
                using var doc = JsonDocument.Parse(body);
                if (doc.RootElement.TryGetProperty("token", out var token))
                    return token.GetString() ?? "";
            }
            catch
            {
            }
            return "";
        }

        public void Dispose()
        {
            Stop();
            // 给在途请求留出退出时间，避免释放信号量时抛 ObjectDisposedException。
            try { _loginGate.Wait(TimeSpan.FromSeconds(2)); } catch { }
            try { _loginGate.Dispose(); } catch { }
        }

        public event Action<string> LogMessage;
        private void Log(string msg) => LogMessage?.Invoke(msg);
    }
}
