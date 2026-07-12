using Ink_Canvas.Plugins;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace SeewoAutoLogin
{
    [PluginEntrance]
    public class SeewoAutoLoginPlugin : PluginBase
    {
        private SeewoAuthService _authService;
        private SeewoQrLoginClient _qrLoginClient;
        private QrLoginCoordinator _qrLoginCoordinator;
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
            _qrLoginClient = new SeewoQrLoginClient();
            _qrLoginCoordinator = new QrLoginCoordinator(_qrLoginClient);
            _qrLoginClient.LogMessage += WriteDiagnosticLog;
            _qrLoginCoordinator.LogMessage += WriteDiagnosticLog;
            services.AddSingleton(_authService);
            services.AddSingleton(_qrLoginClient);
            services.AddSingleton(_qrLoginCoordinator);

            LoadConfig();

            // 启动本地 SSO 网关（希沃白板连接此服务获取账号列表和 token）
            _gateway = new SeewoSsoGateway(_authService, () => Config, account =>
            {
                account.UserInfo = _authService.UserInfo;
                SaveConfig();
            });
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

        #region 账号管理

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
            Config.Accounts.RemoveAll(a => a.Id == accountId);
            if (Config.ActiveAccountId == accountId)
                Config.ActiveAccountId = Config.Accounts.FirstOrDefault()?.Id ?? "";
            SaveConfig();
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
