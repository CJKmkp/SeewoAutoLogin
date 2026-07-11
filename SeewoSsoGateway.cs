using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
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
        private readonly Action<SeewoAccount> _onLoginSuccess;

        public int Port { get; set; } = 24300;
        public bool IsRunning => _listener?.IsListening == true;

        public SeewoSsoGateway(SeewoAuthService authService, Func<PluginConfig> getConfig, Action<SeewoAccount> onLoginSuccess)
        {
            _authService = authService;
            _getConfig = getConfig;
            _onLoginSuccess = onLoginSuccess;
        }

        private const string SeeSoLocalHost = "local.id.seewo.com";

        public void Start()
        {
            if (IsRunning) return;

            // 自动添加 hosts 映射
            EnsureHostsMapping();

            _cts = new CancellationTokenSource();
            _listener = new HttpListener();
            _listener.Prefixes.Add($"http://localhost:{Port}/");
            _listener.Prefixes.Add($"http://127.0.0.1:{Port}/");
            try { _listener.Prefixes.Add($"http://{SeeSoLocalHost}:{Port}/"); }
            catch { }

            try
            {
                _listener.Start();
            }
            catch (HttpListenerException ex) when (ex.ErrorCode == 5)
            {
                try
                {
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "netsh",
                        Arguments = $"http add urlacl url=http://+:{Port}/ user=Everyone",
                        Verb = "runas",
                        UseShellExecute = true,
                        WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden
                    })?.WaitForExit(5000);

                    _listener = new HttpListener();
                    _listener.Prefixes.Add($"http://localhost:{Port}/");
                    _listener.Prefixes.Add($"http://127.0.0.1:{Port}/");
                    try { _listener.Prefixes.Add($"http://{SeeSoLocalHost}:{Port}/"); }
                    catch { }
                    _listener.Start();
                }
                catch
                {
                    Log("SSO 网关启动失败：需要管理员权限");
                    return;
                }
            }

            _ = Task.Run(() => ListenLoop(_cts.Token));
            Log($"SSO 网关已启动: http://localhost:{Port}");
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

                    if (account == null || string.IsNullOrEmpty(account.Password))
                    {
                        resp.StatusCode = 404;
                        await WriteJson(resp, new { message = "user_not_found", statusCode = "404" });
                        return;
                    }

                    // 登录获取 token
                    var loginResult = await _authService.LoginAsync(account.Username, account.Password);

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
