using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
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
        private readonly SeewoAuthService _authService;
        private readonly Func<PluginConfig> _getConfig;
        private readonly Func<SeewoAccount, bool> _tryRestoreQrSession;
        private readonly Func<IReadOnlyList<SeewoAccount>> _getVisibleAccounts;
        private readonly Action<SeewoAccount> _onLoginSuccess;
        private readonly Action<SeewoAccount, string> _onQrTokenValidated;
        private readonly SeewoUserListRotationService _userListRotation;

        public int Port { get; set; } = 24300;
        public bool IsRunning => _listener?.IsListening == true;

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
        private const string TrustedEasiAgentSuffix = @"\Seewo\EasiAgent\EasiAgent.exe";

        public void Start()
        {
            if (IsRunning) return;

            EnsureHostsMapping();
            ResetListener();

            try
            {
                _listener.Start();
            }
            catch (HttpListenerException) when (IsPortListening(Port))
            {
                Log($"SSO 网关端口 {Port} 已被占用，正在检查希沃 EasiAgent");
                if (!TryStopTrustedEasiAgent())
                    throw;

                if (!WaitForPortRelease(TimeSpan.FromSeconds(5)))
                    throw new InvalidOperationException($"结束希沃 EasiAgent 后端口 {Port} 未及时释放。");

                ResetListener();
                _listener.Start();
                Log("已结束占用端口的希沃 EasiAgent，并重新加载 SSO 网关");
            }

            _ = Task.Run(() => ListenLoop(_cts.Token));
            Log($"SSO 网关已启动: http://localhost:{Port}");
        }

        private void ResetListener()
        {
            try { _listener?.Close(); } catch { }
            _cts?.Dispose();
            _cts = new CancellationTokenSource();
            _listener = new HttpListener();
            _listener.Prefixes.Add($"http://localhost:{Port}/");
            _listener.Prefixes.Add($"http://127.0.0.1:{Port}/");
            try { _listener.Prefixes.Add($"http://{SeeSoLocalHost}:{Port}/"); }
            catch { }
        }

        public bool StopTrustedEasiAgent() => TryStopTrustedEasiAgent();

        private bool TryStopTrustedEasiAgent()
        {
            foreach (var process in Process.GetProcessesByName("EasiAgent"))
            {
                try
                {
                    var path = process.MainModule?.FileName;
                    if (!IsTrustedEasiAgentPath(path))
                    {
                        Log($"拒绝结束非受信任路径的 EasiAgent; pid={process.Id}");
                        continue;
                    }

                    Log($"正在结束希沃 EasiAgent; pid={process.Id}");
                    process.Kill();
                    process.WaitForExit(5000);
                    return process.HasExited;
                }
                catch (Exception ex)
                {
                    Log($"结束希沃 EasiAgent 失败; pid={process.Id}; error={ex.GetType().Name}");
                }
                finally
                {
                    process.Dispose();
                }
            }
            return false;
        }

        private static bool IsTrustedEasiAgentPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            try
            {
                var fullPath = Path.GetFullPath(path);
                return fullPath.EndsWith(TrustedEasiAgentSuffix, StringComparison.OrdinalIgnoreCase) &&
                       string.Equals(Path.GetFileName(fullPath), "EasiAgent.exe", StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        private bool WaitForPortRelease(TimeSpan timeout)
        {
            var deadline = DateTime.UtcNow + timeout;
            while (DateTime.UtcNow < deadline)
            {
                if (!IsPortListening(Port)) return true;
                Thread.Sleep(100);
            }
            return !IsPortListening(Port);
        }

        private static bool IsPortListening(int port)
        {
            try
            {
                return IPGlobalProperties.GetIPGlobalProperties()
                    .GetActiveTcpListeners()
                    .Any(endpoint => endpoint.Port == port);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 自动将 local.id.seewo.com 添加到 hosts 文件。
        /// </summary>
        private static void EnsureHostsMapping()
        {
            try
            {
                var hostsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                    "drivers", "etc", "hosts");
                if (!File.Exists(hostsPath)) return;

                var content = File.ReadAllText(hostsPath);
                if (content.Contains(SeeSoLocalHost)) return;

                File.AppendAllText(hostsPath,
                    Environment.NewLine + "127.0.0.1 " + SeeSoLocalHost + Environment.NewLine);
            }
            catch
            {
                // 需要管理员权限，静默失败
            }
        }

        public void Stop()
        {
            _cts?.Cancel();
            try { _listener?.Stop(); } catch { }
            _listener = null;
            Log("SSO 网关已停止");
        }

        private async Task ListenLoop(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested && _listener?.IsListening == true)
            {
                try
                {
                    var context = await _listener.GetContextAsync();
                    _ = Task.Run(() => HandleRequest(context), ct);
                }
                catch (HttpListenerException) { break; }
                catch { }
            }
        }

        private async Task HandleRequest(HttpListenerContext context)
        {
            var req = context.Request;
            var resp = context.Response;
            var path = req.Url?.AbsolutePath?.TrimEnd('/') ?? "";

            // CORS 头
            resp.Headers.Add("Access-Control-Allow-Origin", "*");
            resp.Headers.Add("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
            resp.Headers.Add("Access-Control-Allow-Headers", "Content-Type, Authorization");

            if (req.HttpMethod == "OPTIONS")
            {
                resp.StatusCode = 200;
                resp.Close();
                return;
            }

            try
            {
                // GET /getData/SSOLOGIN — 返回账号列表
                if (req.HttpMethod == "GET" && path.Equals("/getData/SSOLOGIN", StringComparison.OrdinalIgnoreCase))
                {
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
                    Log(config.UserListRotationEnabled
                        ? $"SSOLOGIN: 返回第 {routeIndex + 1} 组 {accounts.Count} 个账号"
                        : $"SSOLOGIN: 返回 {accounts.Count} 个账号");
                    return;
                }

                // GET /getData/SSOLOGIN/{userid} — 用指定账号登录，设置 token cookie
                if (req.HttpMethod == "GET" && path.StartsWith("/getData/SSOLOGIN/", StringComparison.OrdinalIgnoreCase))
                {
                    var userId = path.Substring("/getData/SSOLOGIN/".Length);
                    Log($"SSOLOGIN/{{userid}}: 收到请求 userId={userId}");
                    var config = _getConfig();
                    var account = config.Accounts.FirstOrDefault(a => a.Id == userId || a.Username == userId);

                    if (account == null)
                    {
                        resp.StatusCode = 404;
                        await WriteJson(resp, new { message = "user_not_found", statusCode = "404" });
                        return;
                    }

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
                            loginResult = _authService.GetCurrentLoginResult();
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
                    resp.Headers.Set("Set-Cookie", $"pt_token={loginResult.Token}; Path=/; SameSite=Lax");
                    resp.Headers.Set("X-Auth-Token", loginResult.Token);

                    await WriteJson(resp, new { message = "success", statusCode = "200", data = new { pt_token = loginResult.Token } });

                    // 更新账号信息
                    account.UserInfo = loginResult.UserInfo;
                    _onLoginSuccess?.Invoke(account);

                    Log($"SSOLOGIN/{userId}: 登录成功 - {loginResult.UserInfo?.NickName}");
                    return;
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
        }

        public event Action<string> LogMessage;
        private void Log(string msg) => LogMessage?.Invoke(msg);
    }
}
