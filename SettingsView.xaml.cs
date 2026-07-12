using Ink_Canvas.Plugins;
using System;
using System.Linq;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace SeewoAutoLogin
{
    public partial class SettingsView : UserControl
    {
        private readonly SeewoAuthService _authService;
        private readonly QrLoginCoordinator _qrLoginCoordinator;
        private readonly SeewoAutoLoginPlugin _plugin;
        private readonly DispatcherTimer _qrCountdownTimer;
        private CancellationTokenSource _passwordLoginCancellation;
        private CancellationTokenSource _qrLoginCancellation;
        private DateTimeOffset _qrExpiresAt;
        private bool _qrConsentGranted;
        private bool _isUnlocked;

        public SettingsView(SeewoAuthService authService, QrLoginCoordinator qrLoginCoordinator, SeewoAutoLoginPlugin plugin)
        {
            InitializeComponent();
            _authService = authService;
            _qrLoginCoordinator = qrLoginCoordinator;
            _plugin = plugin;
            _qrLoginCoordinator.StateChanged += QrLoginCoordinator_StateChanged;
            _qrCountdownTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _qrCountdownTimer.Tick += QrCountdownTimer_Tick;
            Unloaded += SettingsView_Unloaded;
            ApplyLocalizedQrText();
            ApplyRotationSettings();

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
            _passwordLoginCancellation?.Cancel();
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

            _passwordLoginCancellation?.Cancel();
            _passwordLoginCancellation?.Dispose();
            _passwordLoginCancellation = new CancellationTokenSource();
            var loginCancellation = _passwordLoginCancellation;

            LoginButton.IsEnabled = false;
            LoginButton.Content = "登录中...";
            LoginStatus.Text = "正在验证...";

            var result = await _authService.LoginAsync(username, password, loginCancellation.Token);

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
            if (ReferenceEquals(_passwordLoginCancellation, loginCancellation))
            {
                _passwordLoginCancellation.Dispose();
                _passwordLoginCancellation = null;
            }
        }

        #endregion

        #region 扫码登录

        private void ApplyLocalizedQrText()
        {
            QrTitleText.Text = Strings.QrTitle;
            QrDescriptionText.Text = Strings.QrDescription;
            StartQrLoginButton.Content = Strings.Start;
            RefreshQrLoginButton.Content = Strings.Refresh;
            CancelQrLoginButton.Content = Strings.Cancel;
        }

        private async void StartQrLogin_Click(object sender, RoutedEventArgs e)
        {
            if (!_qrConsentGranted)
            {
                var dialog = new iNKORE.UI.WPF.Modern.Controls.ContentDialog
                {
                    Title = Strings.QrConsentTitle,
                    Content = Strings.QrConsent,
                    PrimaryButtonText = Strings.Continue,
                    SecondaryButtonText = Strings.Cancel,
                    Owner = Window.GetWindow(this)
                };
                if (await dialog.ShowAsync() != iNKORE.UI.WPF.Modern.Controls.ContentDialogResult.Primary)
                    return;
                _qrConsentGranted = true;
            }

            await StartQrLoginAsync();
        }

        private async void RefreshQrLogin_Click(object sender, RoutedEventArgs e)
        {
            await StartQrLoginAsync();
        }

        private void CancelQrLogin_Click(object sender, RoutedEventArgs e)
        {
            _qrLoginCancellation?.Cancel();
            _qrLoginCoordinator.Cancel();
        }

        private async Task StartQrLoginAsync()
        {
            _qrLoginCancellation?.Cancel();
            _qrLoginCancellation?.Dispose();
            _qrLoginCancellation = new CancellationTokenSource();
            var cancellation = _qrLoginCancellation;
            try
            {
                var outcome = await _qrLoginCoordinator.StartAsync(cancellation.Token);
                if (outcome == null || cancellation.IsCancellationRequested) return;

                _authService.AcceptQrLogin(outcome);
                var username = !string.IsNullOrWhiteSpace(outcome.UserInfo?.Phone)
                    ? outcome.UserInfo.Phone
                    : outcome.UserInfo?.UserName ?? "";
                var account = new SeewoAccount
                {
                    DisplayName = outcome.UserInfo?.NickName ?? outcome.UserInfo?.RealName ?? Strings.AccountFallback,
                    Username = username,
                    Password = "",
                    UserInfo = outcome.UserInfo
                };
                _plugin.AddQrAccount(account, outcome);
                RefreshAccountList();
                UpdateUserInfo(outcome.UserInfo);
                QrStatusText.Text = Strings.Saved;
            }
            finally
            {
                if (ReferenceEquals(_qrLoginCancellation, cancellation))
                {
                    _qrLoginCancellation.Dispose();
                    _qrLoginCancellation = null;
                }
            }
        }

        private void QrLoginCoordinator_StateChanged(object sender, QrLoginStateChangedEventArgs e)
        {
            Dispatcher.BeginInvoke(new Action(() => RenderQrState(e)));
        }

        private void RenderQrState(QrLoginStateChangedEventArgs e)
        {
            var active = e.State == QrLoginState.CreatingQrCode ||
                         e.State == QrLoginState.WaitingForScan ||
                         e.State == QrLoginState.WaitingForConfirmation ||
                         e.State == QrLoginState.Completing;
            StartQrLoginButton.Visibility = active ? Visibility.Collapsed : Visibility.Visible;
            CancelQrLoginButton.Visibility = active ? Visibility.Visible : Visibility.Collapsed;
            RefreshQrLoginButton.Visibility = e.State == QrLoginState.Expired ||
                                               e.State == QrLoginState.NetworkError ||
                                               e.State == QrLoginState.ProtocolError ||
                                               e.State == QrLoginState.Denied
                ? Visibility.Visible
                : Visibility.Collapsed;

            if (e.Session != null && e.Session.ImageBytes.Length > 0 && QrCodeImage.Source == null)
            {
                QrCodeImage.Source = LoadBitmap(e.Session.ImageBytes);
                QrCodePanel.Visibility = Visibility.Visible;
                _qrExpiresAt = e.Session.ExpiresAt;
                _qrCountdownTimer.Start();
            }

            QrStatusText.Text = e.State switch
            {
                QrLoginState.CreatingQrCode => Strings.Creating,
                QrLoginState.WaitingForScan => Strings.WaitingForScan,
                QrLoginState.WaitingForConfirmation => Strings.WaitingForConfirmation,
                QrLoginState.Completing => Strings.Completing,
                QrLoginState.Succeeded => Strings.Succeeded,
                QrLoginState.Expired => Strings.Expired,
                QrLoginState.Cancelled => Strings.Cancelled,
                QrLoginState.Denied => Strings.Denied,
                QrLoginState.NetworkError => Strings.NetworkError,
                QrLoginState.ProtocolError => string.IsNullOrWhiteSpace(e.Message) ? Strings.ProtocolError : e.Message,
                _ => ""
            };

            if (!active)
            {
                _qrCountdownTimer.Stop();
                QrCountdownText.Text = "";
                if (e.State != QrLoginState.Succeeded)
                {
                    QrCodeImage.Source = null;
                    QrCodePanel.Visibility = Visibility.Collapsed;
                }
            }
        }

        private void QrCountdownTimer_Tick(object sender, EventArgs e)
        {
            var seconds = Math.Max(0, (int)Math.Ceiling((_qrExpiresAt - DateTimeOffset.UtcNow).TotalSeconds));
            QrCountdownText.Text = Strings.SecondsRemaining(seconds);
            if (seconds == 0) _qrCountdownTimer.Stop();
        }

        private static BitmapImage LoadBitmap(byte[] bytes)
        {
            using var stream = new MemoryStream(bytes, writable: false);
            var image = new BitmapImage();
            image.BeginInit();
            image.CacheOption = BitmapCacheOption.OnLoad;
            image.StreamSource = stream;
            image.EndInit();
            image.Freeze();
            return image;
        }

        private void SettingsView_Unloaded(object sender, RoutedEventArgs e)
        {
            _passwordLoginCancellation?.Cancel();
            _qrLoginCancellation?.Cancel();
            _qrLoginCoordinator.Cancel();
            _qrCountdownTimer.Stop();
        }

        #endregion

        #region 用户列表轮换

        private void ApplyRotationSettings()
        {
            RotationTitleText.Text = Strings.RotationTitle;
            RotationEnabledCheckBox.Content = Strings.RotationEnabled;
            RotationGroupSizeLabel.Text = Strings.RotationGroupSize;
            RotationEnabledCheckBox.IsChecked = _plugin.Config.UserListRotationEnabled;
            var size = SeewoUserListRotationService.NormalizeGroupSize(_plugin.Config.UserListRotationGroupSize);
            RotationGroupSizeComboBox.SelectedIndex = size == 4 ? 0 : 1;
            RotationStatusText.Text = Strings.RotationHint;
        }

        private void RotationSetting_Changed(object sender, RoutedEventArgs e)
        {
            if (!_isUnlocked || RotationEnabledCheckBox == null) return;
            _plugin.Config.UserListRotationEnabled = RotationEnabledCheckBox.IsChecked == true;
            _plugin.SaveConfig();
            RotationStatusText.Text = Strings.RotationHint;
        }

        private void RotationGroupSize_Changed(object sender, SelectionChangedEventArgs e)
        {
            if (!_isUnlocked || RotationGroupSizeComboBox?.SelectedItem is not ComboBoxItem item) return;
            if (!int.TryParse(item.Tag?.ToString(), out var size)) return;
            _plugin.Config.UserListRotationGroupSize = SeewoUserListRotationService.NormalizeGroupSize(size);
            _plugin.SaveConfig();
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
