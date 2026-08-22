using Ink_Canvas.Plugins;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace SeewoAutoLogin
{
    [PluginEntrance]
    public class SeewoAutoLoginPlugin : PluginBase
    {
        private SeewoAuthService _authService;
        private SeewoQrLoginClient _qrLoginClient;
        private QrLoginCoordinator _qrLoginCoordinator;
        private QrSessionStore _qrSessionStore;
        private SeewoUserListRotationService _userListRotation;
        private SeewoSsoGateway _gateway;
        private SettingsView _settingsView;
        private Timer _dailyTokenRefreshTimer;

        public PluginConfig Config { get; private set; } = new PluginConfig();

        public SeewoAccount ActiveAccount => Config.Accounts.FirstOrDefault(a => a.Id == Config.ActiveAccountId);

        public override void Initialize(IPluginHost host, IServiceCollection services)
        {
            base.Initialize(host, services);
            Log($"{Name} v{Version} 正在初始化...");
            WriteDiagnosticLog($"[Plugin] 初始化; version={Version}; process={Environment.ProcessId}");

            _authService = new SeewoAuthService();
            _authService.DiagnosticMessage += WriteDiagnosticLog;
            _qrLoginClient = new SeewoQrLoginClient();
            _qrLoginCoordinator = new QrLoginCoordinator(_qrLoginClient);
            _qrSessionStore = new QrSessionStore();
            _userListRotation = new SeewoUserListRotationService();
            _qrLoginClient.LogMessage += WriteDiagnosticLog;
            _qrLoginCoordinator.LogMessage += WriteDiagnosticLog;
            services.AddSingleton(_authService);
            services.AddSingleton(_qrLoginClient);
            services.AddSingleton(_qrLoginCoordinator);
            services.AddSingleton(_qrSessionStore);
            services.AddSingleton(_userListRotation);
            Log($"用户列表轮换器初始化; mode=request-driven; reconnect-window-seconds=10");
            _userListRotation.RotationChanged += (groupIndex, withinWindow) =>
                WriteDiagnosticLog($"[Rotation] SSO request -> group {groupIndex + 1}; within-10s={withinWindow}");

            LoadConfig();

            // 若开启了“阻止 EasiAgent 启动”，应用映像劫持（幂等），避免下次启动抢占 SSO 端口。
            if (Config.BlockEasiAgentStartup)
            {
                var blockError = EasiAgentStartupBlocker.ApplyBlock();
                if (blockError != string.Empty)
                    LogError($"阻止 EasiAgent 启动失败: {blockError}");
                else
                    WriteDiagnosticLog("[Block] 已应用 EasiAgent 启动阻止（映像劫持）");
            }

            // 启动本地 SSO 网关（希沃白板连接此服务获取账号列表和 token）
            _gateway = new SeewoSsoGateway(_authService, () => Config, TryRestoreQrSession, GetVisibleAccounts, account =>
            {
                account.UserInfo = _authService.UserInfo;
                SaveConfig();
            }, OnQrTokenValidated, _userListRotation);
            _gateway.LogMessage += msg => Log(msg);
            _gateway.ScanLoginCaptured += OnScanLoginCaptured;
            try
            {
                _gateway.Start();
                StartDailyTokenRefresh();
            }
            catch (Exception ex)
            {
                LogError($"SSO 网关启动失败: {ex.Message}");
            }

            // 若开启了“接管登录二维码”，启动后重新应用宿主覆盖（幂等）。
            if (Config.TakeOverLoginQr)
            {
                var ucError = SetTakeOverLoginQr(true);
                if (ucError != string.Empty)
                    LogError($"接管登录二维码失败: {ucError}");
                else
                    WriteDiagnosticLog("[UcHost] 已应用登录宿主接管（透明代理）");
            }
        }

        public override void Shutdown()
        {
            _qrLoginCoordinator?.Dispose();
            _dailyTokenRefreshTimer?.Dispose();
            _userListRotation?.Dispose();
            _qrLoginClient?.Dispose();
            _gateway?.Dispose();
            _authService?.Dispose();
            Log($"{Name} 已关闭");
        }

        public override object GetSettingsView()
        {
            if (_settingsView == null)
                _settingsView = new SettingsView(_authService, _qrLoginCoordinator, this);
            return _settingsView;
        }

        public IReadOnlyList<SeewoAccount> GetVisibleAccounts()
        {
            return Config.Accounts;
        }

        public string UserListRotationStatus
        {
            get
            {
                if (_userListRotation == null) return "";
                var rotation = _userListRotation;
                var totalRequests = rotation.TotalRequests;
                if (totalRequests <= 1) return "";
                return $"第 {rotation.CurrentGroupIndex + 1} 组";
            }
        }

        #region 账号管理

        public void AddQrAccount(SeewoAccount account, QrLoginOutcome outcome)
        {
            if (account == null) throw new ArgumentNullException(nameof(account));
            if (outcome == null || string.IsNullOrWhiteSpace(outcome.Token))
                throw new ArgumentException("扫码登录结果无效。", nameof(outcome));

            var existing = FindMatchingAccount(account.UserInfo);
            var credentialId = existing?.QrCredentialId;
            if (string.IsNullOrWhiteSpace(credentialId))
                credentialId = _qrSessionStore.CreateCredentialId();

            _qrSessionStore.Save(credentialId, outcome.Token, DateTimeOffset.UtcNow);
            account.QrCredentialId = credentialId;

            if (existing != null)
            {
                existing.DisplayName = account.DisplayName;
                existing.Username = account.Username;
                existing.Password = "";
                existing.UserInfo = account.UserInfo;
                existing.QrCredentialId = credentialId;
                if (Config.ActiveAccountId == "") Config.ActiveAccountId = existing.Id;
                SaveConfig();
                WriteDiagnosticLog($"[Account] 已更新扫码账号会话; account-id={existing.Id}; credential-present=True");
                return;
            }

            AddAccount(account);
        }

        public void AddAccount(SeewoAccount account)
        {
            Config.Accounts.Add(account);
            if (Config.Accounts.Count == 1)
                Config.ActiveAccountId = account.Id;
            SaveConfig();
            WriteDiagnosticLog($"[Account] 已保存扫码/密码登录账号; account-id={account.Id}; has-user-info={account.UserInfo != null}; password-backed={!string.IsNullOrEmpty(account.Password)}");
        }

        public void RemoveAccount(string accountId)
        {
            var account = Config.Accounts.FirstOrDefault(a => a.Id == accountId);
            if (!string.IsNullOrWhiteSpace(account?.QrCredentialId))
            {
                try
                {
                    _qrSessionStore.Delete(account.QrCredentialId);
                    WriteDiagnosticLog($"[Account] 已删除扫码凭据; account-id={account.Id}");
                }
                catch (Exception ex)
                {
                    WriteDiagnosticLog($"[Account] 删除扫码凭据失败; account-id={account.Id}; error={ex.GetType().Name}");
                }
            }
            Config.Accounts.RemoveAll(a => a.Id == accountId);
            if (Config.ActiveAccountId == accountId)
                Config.ActiveAccountId = Config.Accounts.FirstOrDefault()?.Id ?? "";
            SaveConfig();
        }

        public void OnQrTokenValidated(SeewoAccount account, string token)
        {
            if (account == null || string.IsNullOrWhiteSpace(account.QrCredentialId) || string.IsNullOrWhiteSpace(token))
                return;
            try
            {
                _qrSessionStore.Save(account.QrCredentialId, token, DateTimeOffset.UtcNow);
                WriteDiagnosticLog($"[Session] Token 换发返回新 Token，已更新 DPAPI 凭据; account-id={account.Id}");
            }
            catch (Exception ex)
            {
                WriteDiagnosticLog($"[Session] 更新 DPAPI 凭据失败; account-id={account.Id}; error={ex.GetType().Name}");
            }
        }

        public bool TryRestoreQrSession(SeewoAccount account)
        {
            if (account == null || string.IsNullOrWhiteSpace(account.QrCredentialId))
            {
                WriteDiagnosticLog($"[Session] 扫码账号没有可恢复的凭据; account-id={account?.Id ?? "<none>"}");
                return false;
            }

            if (!_qrSessionStore.TryLoad(account.QrCredentialId, out var session))
            {
                WriteDiagnosticLog($"[Session] 扫码凭据读取失败; account-id={account.Id}");
                return false;
            }

            _authService.RestoreQrSession(session.Token, account.UserInfo);
            var restored = _authService.IsSessionFor(account);
            WriteDiagnosticLog($"[Session] 扫码会话恢复; account-id={account.Id}; restored={restored}");
            return restored;
        }

        private SeewoAccount FindMatchingAccount(SeewoUserInfo userInfo)
        {
            if (userInfo == null) return null;
            return Config.Accounts.FirstOrDefault(account =>
                (!string.IsNullOrWhiteSpace(userInfo.AccountId) &&
                 string.Equals(account.UserInfo?.AccountId, userInfo.AccountId, StringComparison.Ordinal)) ||
                (!string.IsNullOrWhiteSpace(userInfo.UserName) &&
                 string.Equals(account.UserInfo?.UserName, userInfo.UserName, StringComparison.Ordinal)));
        }

        public void SetActiveAccount(string accountId)
        {
            Config.ActiveAccountId = accountId;
            _authService.Logout();
            SaveConfig();
        }

        /// <summary>
        /// 启用/停用“阻止 EasiAgent 启动”。返回空字符串表示成功，否则返回错误信息。
        /// 失败时不改配置，保持界面与注册表状态一致。
        /// </summary>
        public string SetEasiAgentStartupBlock(bool enabled)
        {
            var error = enabled
                ? EasiAgentStartupBlocker.ApplyBlock()
                : EasiAgentStartupBlocker.RemoveBlock();

            if (error != string.Empty)
            {
                WriteDiagnosticLog($"[Block] 设置阻止失败; enabled={enabled}; error={error}");
                return error;
            }

            Config.BlockEasiAgentStartup = enabled;
            SaveConfig();
            WriteDiagnosticLog($"[Block] {(enabled ? "已应用" : "已解除")}; enabled={enabled}");

            // 启用时顺带结束正在运行的可信 EasiAgent，若权限不足则由注册表在下次启动生效。
            if (enabled) TryStopTrustedEasiAgent();
            return string.Empty;
        }

        public bool TryStopTrustedEasiAgent()
        {
            try { return _gateway?.StopTrustedEasiAgent() ?? false; }
            catch (Exception ex)
            {
                WriteDiagnosticLog($"[Block] 结束正在运行的 EasiAgent 失败; error={ex.GetType().Name}");
                return false;
            }
        }

        /// <summary>
        /// 启用/停用“接管登录二维码”：把白板五的 UcHost 指向本地网关并开启透明代理。
        /// 失败不改配置。启用时校验网关确实在运行，避免白板五登录失联。
        /// </summary>
        public string SetTakeOverLoginQr(bool enabled)
        {
            if (enabled && (_gateway == null || !_gateway.IsRunning))
            {
                WriteDiagnosticLog("[UcHost] 网关未运行，无法接管登录二维码");
                return "SSO 网关未运行";
            }

            var error = enabled
                ? EasiNoteUcHostOverride.Apply(GetLocalUcHost(), PluginConfigFolder)
                : EasiNoteUcHostOverride.Remove(PluginConfigFolder);

            if (error != string.Empty)
            {
                WriteDiagnosticLog($"[UcHost] 设置接管失败; enabled={enabled}; error={error}");
                return error;
            }

            _gateway?.SetUcHostProxyEnabled(enabled);
            Config.TakeOverLoginQr = enabled;
            SaveConfig();
            WriteDiagnosticLog($"[UcHost] {(enabled ? "已应用" : "已解除")}登录宿主接管; enabled={enabled}; path={EasiNoteUcHostOverride.FkvPath}; value={EasiNoteUcHostOverride.GetCurrentUcHost() ?? "<default>"}");
            return string.Empty;
        }

        private string GetLocalUcHost() => $"http://127.0.0.1:{_gateway?.Port ?? 24300}";

        /// <summary>
        /// UcHost 代理把 auth/checkToken 的响应 JSON 上报后，直接解析并捕获进账号库——
        /// 不二次校验，避免白板五会话上下文下签发的 token 在独立校验时失效导致漏存。
        /// </summary>
        private void OnScanLoginCaptured(string token, string checkTokenJson)
        {
            _ = Task.Run(() =>
            {
                try
                {
                    var outcome = ParseCheckTokenOutcome(checkTokenJson, token);
                    if (outcome?.UserInfo == null || string.IsNullOrWhiteSpace(outcome.Token)) return;
                    CaptureScannedAccount(outcome);
                }
                catch (Exception ex)
                {
                    WriteDiagnosticLog($"[QRCapture] 解析扫码登录结果失败; error={ex.GetType().Name}");
                }
            });
        }

        /// <summary>
        /// 对齐 SeewoQrLoginClient 的解析：payload 取 data 对象，UserInfo 内 tokenId 为有效令牌。
        /// </summary>
        private static QrLoginOutcome ParseCheckTokenOutcome(string json, string fallbackToken)
        {
            if (string.IsNullOrWhiteSpace(json)) return null;
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            var payload = TryGetProperty(root, "data", out var data) && data.ValueKind == JsonValueKind.Object
                ? data : root;
            var user = FindObject(payload, "UserInfo") ?? FindObject(payload, "userInfo") ??
                       FindObject(root, "UserInfo") ?? FindObject(root, "userInfo");
            if (user == null) return null;

            var value = user.Value;
            var tokenId = GetString(value, "tokenId") ?? fallbackToken;
            if (string.IsNullOrWhiteSpace(tokenId)) return null;

            return new QrLoginOutcome
            {
                Token = tokenId,
                UserInfo = new SeewoUserInfo
                {
                    AccountId = GetString(value, "resourceid") ?? "",
                    Uid = GetString(value, "resourceid") ?? "",
                    UserName = GetString(value, "userName") ?? "",
                    NickName = GetString(value, "cnName") ?? "",
                    RealName = GetString(value, "cnName") ?? "",
                    PhotoUrl = GetString(value, "photoUrl") ?? "",
                    Phone = GetString(value, "phone") ?? ""
                }
            };
        }

        private static JsonElement? FindObject(JsonElement element, string name)
        {
            if (TryGetProperty(element, name, out var direct) && direct.ValueKind == JsonValueKind.Object)
                return direct;
            if (TryGetProperty(element, "data", out var data) && data.ValueKind == JsonValueKind.Object &&
                TryGetProperty(data, name, out var nested) && nested.ValueKind == JsonValueKind.Object)
                return nested;
            return null;
        }

        private static bool TryGetProperty(JsonElement element, string name, out JsonElement value)
        {
            foreach (var property in element.EnumerateObject())
            {
                if (string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase))
                {
                    value = property.Value;
                    return true;
                }
            }
            value = default;
            return false;
        }

        private static string GetString(JsonElement element, string name)
        {
            return TryGetProperty(element, name, out var value) && value.ValueKind == JsonValueKind.String
                ? value.GetString() : null;
        }

        private void CaptureScannedAccount(QrLoginOutcome outcome)
        {
            var account = new SeewoAccount
            {
                DisplayName = outcome.UserInfo.NickName ?? outcome.UserInfo.RealName
                    ?? outcome.UserInfo.UserName ?? Strings.AccountFallback,
                Username = !string.IsNullOrWhiteSpace(outcome.UserInfo.Phone)
                    ? outcome.UserInfo.Phone
                    : outcome.UserInfo.UserName ?? "",
                Password = "",
                UserInfo = outcome.UserInfo
            };
            // AddQrAccount 内含匹配去重、凭据保存与 ActiveAccount 兜底。
            AddQrAccount(account, outcome);
            WriteDiagnosticLog($"[QRCapture] 已捕获扫码登录账号; id={account.Id}; display={account.DisplayName}");
        }

        #endregion

        private void WriteDiagnosticLog(string message)
        {
            // 统一走宿主日志接口，写入 PluginLogs/<插件Id>/ 目录，不自行写文件。
            Log(message);
        }

        private void StartDailyTokenRefresh()
        {
            _dailyTokenRefreshTimer = new Timer(_ => _ = RefreshTokensAsync(), null, TimeSpan.FromDays(1), TimeSpan.FromDays(1));
        }

        private async Task RefreshTokensAsync()
        {
            foreach (var account in Config.Accounts.Where(account => string.IsNullOrEmpty(account.Password) && !string.IsNullOrWhiteSpace(account.QrCredentialId)).ToList())
            {
                try
                {
                    if (!TryRestoreQrSession(account)) continue;
                    var result = await _authService.ExchangeCurrentTokenAsync().ConfigureAwait(false);
                    if (!result.Success) continue;
                    OnQrTokenValidated(account, result.Token);
                    WriteDiagnosticLog($"[Scheduler] Token 自动刷新成功; account-id={account.Id}");
                }
                catch (Exception ex)
                {
                    WriteDiagnosticLog($"[Scheduler] Token 自动刷新失败; account-id={account.Id}; error={ex.GetType().Name}");
                }
            }
        }

        #region 配置持久化

        private string ConfigPath => Path.Combine(PluginConfigFolder, "config.json");

        public void LoadConfig()
        {
            try
            {
                if (!File.Exists(ConfigPath)) return;
                var json = File.ReadAllText(ConfigPath);
                Config = JsonSerializer.Deserialize<PluginConfig>(json) ?? new PluginConfig();
            }
            catch (Exception ex)
            {
                LogError($"加载配置失败: {ex.Message}");
                Config = new PluginConfig();
            }
        }

        public void SaveConfig()
        {
            try
            {
                if (!Directory.Exists(PluginConfigFolder))
                    Directory.CreateDirectory(PluginConfigFolder);
                var json = JsonSerializer.Serialize(Config, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(ConfigPath, json);
            }
            catch (Exception ex)
            {
                LogError($"保存配置失败: {ex.Message}");
            }
        }

        #endregion
    }
}
