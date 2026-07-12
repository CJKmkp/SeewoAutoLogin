using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace SeewoAutoLogin
{
    /// <summary>
    /// 本地 HTTP 服务器，模拟 Fast-EasiLogin 的 SSO 网关。
    /// 希沃白板 (EasiNote5) 会连接此服务器获取账号列表和登录 token。
    /// </summary>
    public class SeewoSsoGateway : IDisposable
    {
        private HttpListener _listener;
        private CancellationTokenSource _cts;
        private readonly SeewoAuthService _authService;
        private readonly Func<PluginConfig> _getConfig;
        private readonly Func<SeewoAccount, bool> _tryRestoreQrSession;
        private readonly Action<SeewoAccount> _onLoginSuccess;

        public int Port { get; set; } = 24300;
        public bool IsRunning => _listener?.IsListening == true;

        public SeewoSsoGateway(
            SeewoAuthService authService,
            Func<PluginConfig> getConfig,
            Func<SeewoAccount, bool> tryRestoreQrSession,
            Action<SeewoAccount> onLoginSuccess)
        {
            _authService = authService;
            _getConfig = getConfig;
            _tryRestoreQrSession = tryRestoreQrSession;
            _onLoginSuccess = onLoginSuccess;
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
                    var accounts = config.Accounts
                        .Where(a => !string.IsNullOrEmpty(a.Username))
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
                    Log($"SSOLOGIN: 返回 {accounts.Count} 个账号");
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
                            loginResult = _authService.GetCurrentLoginResult();
                        }
                        else
                        {
                            resp.StatusCode = 401;
                            await WriteJson(resp, new { message = "qr_session_required", statusCode = "401" });
                            Log($"SSOLOGIN/{userId}: 扫码会话不可用，需要重新扫码");
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

        public void Dispose()
        {
            Stop();
        }

        public event Action<string> LogMessage;
        private void Log(string msg) => LogMessage?.Invoke(msg);
    }
}
