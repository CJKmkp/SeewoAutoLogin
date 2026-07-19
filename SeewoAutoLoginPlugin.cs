using Ink_Canvas.Plugins;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Text.Json;

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
        private readonly object _diagnosticLogLock = new object();

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

            // 启动本地 SSO 网关（希沃白板连接此服务获取账号列表和 token）
            _gateway = new SeewoSsoGateway(_authService, () => Config, TryRestoreQrSession, GetVisibleAccounts, account =>
            {
                account.UserInfo = _authService.UserInfo;
                SaveConfig();
            }, OnQrTokenValidated, _userListRotation);
            _gateway.LogMessage += msg => Log(msg);
            try
            {
                _gateway.Start();
            }
            catch (Exception ex)
            {
                LogError($"SSO 网关启动失败: {ex.Message}");
            }
        }

        public override void Shutdown()
        {
            _qrLoginCoordinator?.Dispose();
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
                WriteDiagnosticLog($"[Session] checkToken 返回新 Token，已更新 DPAPI 凭据; account-id={account.Id}");
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

        #endregion

        private void WriteDiagnosticLog(string message)
        {
            try
            {
                var baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
                var directory = Path.Combine(baseDirectory, "PluginLogs", Id);
                var path = Path.Combine(directory, DateTime.Now.ToString("yyyy-MM-dd") + ".log");
                var line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] [INFO] {message}{Environment.NewLine}";
                lock (_diagnosticLogLock)
                {
                    Directory.CreateDirectory(directory);
                    File.AppendAllText(path, line);
                }
                Log(message);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[SeewoAutoLogin Log] {ex.GetType().Name}: {ex.Message}");
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
