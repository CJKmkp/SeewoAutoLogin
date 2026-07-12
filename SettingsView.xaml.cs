using Ink_Canvas.Plugins;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace SeewoAutoLogin
{
    public partial class SettingsView : UserControl
    {
        private readonly SeewoAuthService _authService;
        private readonly SeewoAutoLoginPlugin _plugin;
        private bool _isUnlocked;

        public SettingsView(SeewoAuthService authService, SeewoAutoLoginPlugin plugin)
        {
            InitializeComponent();
            _authService = authService;
            _plugin = plugin;

            LoadPasswordSettings();
            CheckPasswordGate();
        }

        #region 密码门控

        private void LoadPasswordSettings()
        {
            UsePluginPasswordCheckBox.IsChecked = _plugin.Config.UsePluginPassword;
            PluginPasswordPanel.Visibility = _plugin.Config.UsePluginPassword ? Visibility.Visible : Visibility.Collapsed;
            PasswordStatus.Text = string.IsNullOrEmpty(_plugin.Config.PluginPasswordHash) ? "未设置密码" : "已设置密码";
        }

        private void CheckPasswordGate()
        {
            var needsPassword = false;
            var hint = "";

            if (_plugin.Config.UsePluginPassword && !string.IsNullOrEmpty(_plugin.Config.PluginPasswordHash))
            {
                needsPassword = true;
                hint = "请输入本插件的独立密码";
            }

            if (needsPassword && !_isUnlocked)
            {
                LockOverlay.Visibility = Visibility.Visible;
                MainContent.IsEnabled = false;
                LockHint.Text = hint;
                UnlockPasswordBox.Focus();
            }
            else
            {
                LockOverlay.Visibility = Visibility.Collapsed;
                MainContent.IsEnabled = true;
                _isUnlocked = true;
                RefreshAccountList();
            }
        }

        private void Unlock_Click(object sender, RoutedEventArgs e)
        {
            var password = UnlockPasswordBox.Password;
            if (string.IsNullOrEmpty(password))
            {
                UnlockStatus.Text = "请输入密码";
                return;
            }

            bool verified = false;

            if (_plugin.Config.UsePluginPassword && !string.IsNullOrEmpty(_plugin.Config.PluginPasswordHash))
            {
                verified = VerifyPassword(password, _plugin.Config.PluginPasswordHash, _plugin.Config.PluginPasswordSalt);
            }

            if (verified)
            {
                _isUnlocked = true;
                LockOverlay.Visibility = Visibility.Collapsed;
                MainContent.IsEnabled = true;
                UnlockPasswordBox.Password = "";
                UnlockStatus.Text = "";
                RefreshAccountList();
            }
            else
            {
                UnlockStatus.Text = "密码错误";
                UnlockPasswordBox.Password = "";
                UnlockPasswordBox.Focus();
            }
        }

        #endregion

        #region 密码设置

        private void PasswordSetting_Changed(object sender, RoutedEventArgs e)
        {
            if (!_isUnlocked) return;

            _plugin.Config.UsePluginPassword = UsePluginPasswordCheckBox.IsChecked == true;
            PluginPasswordPanel.Visibility = _plugin.Config.UsePluginPassword ? Visibility.Visible : Visibility.Collapsed;
            _plugin.SaveConfig();
        }

        private void SetPassword_Click(object sender, RoutedEventArgs e)
        {
            var password = NewPasswordBox.Password;
            if (string.IsNullOrEmpty(password))
            {
                PasswordStatus.Text = "请输入密码";
                return;
            }

            var salt = GenerateSalt();
            var hash = ComputeHash(password, salt);
            _plugin.Config.PluginPasswordHash = hash;
            _plugin.Config.PluginPasswordSalt = salt;
            _plugin.SaveConfig();

            NewPasswordBox.Password = "";
            PasswordStatus.Text = "密码已设置";
        }

        private void ClearPassword_Click(object sender, RoutedEventArgs e)
        {
            _plugin.Config.PluginPasswordHash = "";
            _plugin.Config.PluginPasswordSalt = "";
            _plugin.SaveConfig();

            NewPasswordBox.Password = "";
            PasswordStatus.Text = "密码已清除";
        }

        #endregion

        #region 账号列表

        private void RefreshAccountList()
        {
            AccountListBox.Items.Clear();
            foreach (var account in _plugin.Config.Accounts)
            {
                var item = new ListBoxItem
                {
                    Tag = account,
                    Padding = new Thickness(10),
                    Margin = new Thickness(0),
                    HorizontalContentAlignment = HorizontalAlignment.Stretch
                };

                var grid = new Grid();
                grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

                var infoPanel = new StackPanel();
                var nameText = new TextBlock
                {
                    Text = account.DisplayName ?? account.Username,
                    FontSize = 14, FontWeight = FontWeights.Normal
                };
                var statusText = new TextBlock
                {
                    Text = account.Username,
                    FontSize = 11,
                    Foreground = TryFindResource("TextFillColorSecondaryBrush") as SolidColorBrush ?? Brushes.Gray
                };
                infoPanel.Children.Add(nameText);
                infoPanel.Children.Add(statusText);
                Grid.SetColumn(infoPanel, 0);
                grid.Children.Add(infoPanel);

                var deleteBtn = new Button
                {
                    Padding = new Thickness(6, 4, 6, 4), Tag = account, ToolTip = "删除"
                };
                deleteBtn.Click += DeleteAccount_Click;
                deleteBtn.Content = new iNKORE.UI.WPF.Modern.Controls.FontIcon
                {
                    Icon = iNKORE.UI.WPF.Modern.Common.IconKeys.SegoeFluentIcons.Delete, FontSize = 12
                };
                Grid.SetColumn(deleteBtn, 1);
                grid.Children.Add(deleteBtn);

                item.Content = grid;
                AccountListBox.Items.Add(item);
            }
        }

        private void UpdateUserInfo(SeewoUserInfo info)
        {
            if (info == null)
            {
                UserInfoCard.Visibility = Visibility.Collapsed;
                return;
            }
            UserInfoCard.Visibility = Visibility.Visible;
            InfoNickName.Text = info.NickName ?? "-";
            InfoRealName.Text = info.RealName ?? "-";
            InfoUnitName.Text = info.UnitName ?? "-";
            InfoSubjectName.Text = info.SubjectName ?? "-";
        }

        #endregion

        #region 事件处理

        private void AccountListBox_SelectionChanged(object sender, SelectionChangedEventArgs e) { }

        private async void DeleteAccount_Click(object sender, RoutedEventArgs e)
        {
            var btn = sender as FrameworkElement;
            var account = btn?.Tag as SeewoAccount;
            if (account == null) return;

            var dialog = new iNKORE.UI.WPF.Modern.Controls.ContentDialog
            {
                Title = "删除账号",
                Content = $"确定删除账号「{account.DisplayName ?? account.Username}」吗？",
                PrimaryButtonText = "删除",
                SecondaryButtonText = "取消",
                Owner = Window.GetWindow(this)
            };
            var result = await dialog.ShowAsync();
            if (result != iNKORE.UI.WPF.Modern.Controls.ContentDialogResult.Primary) return;

            _plugin.RemoveAccount(account.Id);
            RefreshAccountList();
        }

        private void AddAccount_Click(object sender, RoutedEventArgs e)
        {
            LoginPanelTitle.Text = "添加账号";
            DisplayNameBox.Text = "";
            UsernameBox.Text = "";
            PasswordBox.Password = "";
            LoginStatus.Text = "";
            LoginPanel.Visibility = Visibility.Visible;
        }

        private void CancelLogin_Click(object sender, RoutedEventArgs e)
        {
            LoginPanel.Visibility = Visibility.Collapsed;
        }

        private async void LoginButton_Click(object sender, RoutedEventArgs e)
        {
            var username = UsernameBox.Text.Trim();
            var password = PasswordBox.Password;
            var displayName = DisplayNameBox.Text.Trim();

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                LoginStatus.Text = "请输入账号和密码";
                return;
            }

            LoginButton.IsEnabled = false;
            LoginButton.Content = "登录中...";
            LoginStatus.Text = "正在验证...";

            var result = await _authService.LoginAsync(username, password);

            if (result.Success)
            {
                var account = new SeewoAccount
                {
                    DisplayName = string.IsNullOrEmpty(displayName)
                        ? (result.UserInfo?.NickName ?? username) : displayName,
                    Username = username,
                    Password = password,
                    UserInfo = result.UserInfo
                };

                _plugin.AddAccount(account);
                LoginPanel.Visibility = Visibility.Collapsed;
                RefreshAccountList();
            }
            else
            {
                LoginStatus.Text = $"登录失败：{result.ErrorMessage}";
            }

            LoginButton.IsEnabled = true;
            LoginButton.Content = "登录并保存";
        }

        #endregion

        #region 密码工具

        private static string GenerateSalt()
        {
            var bytes = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }
            return Convert.ToBase64String(bytes);
        }

        private static string ComputeHash(string password, string salt)
        {
            using (var sha = SHA256.Create())
            {
                var combined = Encoding.UTF8.GetBytes(password + salt);
                var hash = sha.ComputeHash(combined);
                return Convert.ToBase64String(hash);
            }
        }

        private static bool VerifyPassword(string password, string expectedHash, string salt)
        {
            var hash = ComputeHash(password, salt);
            return hash == expectedHash;
        }

        #endregion
    }
}
