using Ink_Canvas.Plugins;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SeewoAutoLogin
{
    /// <summary>
    /// 根据主程序窗口概览模型识别希沃快捷登录窗口，并按窗口会话轮换账号分组。
    /// </summary>
    public sealed class SeewoUserListRotationService : IDisposable
    {
        private static readonly string[] LoginTitleHints = { "登录", "Login", "账号", "希沃" };
        private static readonly string[] SeewoProcessNames = { "EasiNote", "EasiNote5", "EasiNote5C" };
        private readonly IWindowOverviewService _windowOverview;
        private readonly Func<PluginConfig> _getConfig;
        private readonly object _sync = new object();
        private bool _loginWindowOpen;
        private IntPtr _loginWindowHandle;
        private DateTimeOffset? _closedAt;
        private int _groupIndex;
        private bool _disposed;

        public SeewoUserListRotationService(IWindowOverviewService windowOverview, Func<PluginConfig> getConfig)
        {
            _windowOverview = windowOverview;
            _getConfig = getConfig ?? throw new ArgumentNullException(nameof(getConfig));
            if (_windowOverview != null)
                _windowOverview.WindowsChanged += WindowOverview_WindowsChanged;
        }

        public bool IsLoginWindowOpen
        {
            get { lock (_sync) return _loginWindowOpen; }
        }

        public int CurrentGroupIndex
        {
            get { lock (_sync) return _groupIndex; }
        }

        public IReadOnlyList<SeewoAccount> SelectAccounts(IReadOnlyList<SeewoAccount> accounts)
        {
            var snapshot = (accounts ?? Array.Empty<SeewoAccount>())
                .Where(account => account != null && !string.IsNullOrWhiteSpace(account.Username))
                .ToList();
            var config = _getConfig();
            if (config == null || !config.UserListRotationEnabled || snapshot.Count <= config.UserListRotationGroupSize)
                return snapshot;

            var groupSize = NormalizeGroupSize(config.UserListRotationGroupSize);
            var groupCount = Math.Max(1, (int)Math.Ceiling(snapshot.Count / (double)groupSize));
            int groupIndex;
            lock (_sync)
            {
                groupIndex = _groupIndex % groupCount;
            }

            return snapshot.Skip(groupIndex * groupSize).Take(groupSize).ToList();
        }

        private void WindowOverview_WindowsChanged()
        {
            if (_disposed) return;
            try
            {
                var foreground = _windowOverview.ForegroundWindow;
                var isLoginWindow = IsSeewoQuickLoginWindow(foreground);
                lock (_sync)
                {
                    if (isLoginWindow && !_loginWindowOpen)
                    {
                        var now = DateTimeOffset.UtcNow;
                        var config = _getConfig();
                        var groupSize = NormalizeGroupSize(config?.UserListRotationGroupSize ?? 6);
                        var accountCount = config?.Accounts?.Count(account => account != null && !string.IsNullOrWhiteSpace(account.Username)) ?? 0;
                        var groupCount = Math.Max(1, (int)Math.Ceiling(accountCount / (double)groupSize));
                        var reopenInWindow = _closedAt.HasValue && now - _closedAt.Value <= TimeSpan.FromSeconds(10);
                        _groupIndex = reopenInWindow && groupCount > 0 ? (_groupIndex + 1) % groupCount : 0;
                        _loginWindowOpen = true;
                        _loginWindowHandle = foreground.Handle;
                        _closedAt = null;
                    }
                    else if (!isLoginWindow && _loginWindowOpen)
                    {
                        _loginWindowOpen = false;
                        _loginWindowHandle = IntPtr.Zero;
                        _closedAt = DateTimeOffset.UtcNow;
                    }
                }
            }
            catch
            {
                // 窗口模型只作为轮换提示，异常不能影响 SSO 响应。
            }
        }

        private static bool IsSeewoQuickLoginWindow(PluginWindowInfo window)
        {
            if (window == null || !window.IsVisible || window.IsMinimized) return false;
            if (!SeewoProcessNames.Any(name => string.Equals(name, window.ProcessName, StringComparison.OrdinalIgnoreCase))) return false;

            var title = window.Title ?? "";
            if (LoginTitleHints.Any(title.Contains)) return true;
            // EasiNote 登录窗口在部分版本没有窗口标题；WPF 登录窗口通常为空标题。
            return string.IsNullOrWhiteSpace(title) &&
                   (window.ClassName?.IndexOf("HwndWrapper", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    window.ClassName?.IndexOf("EasiNote", StringComparison.OrdinalIgnoreCase) >= 0);
        }

        public static int NormalizeGroupSize(int groupSize) => groupSize == 4 ? 4 : 6;

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            if (_windowOverview != null)
                _windowOverview.WindowsChanged -= WindowOverview_WindowsChanged;
        }
    }
}
