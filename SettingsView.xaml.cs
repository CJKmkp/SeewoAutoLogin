using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace SeewoAutoLogin
{
    public partial class SettingsView : UserControl
    {
        private readonly SeewoAuthService _authService;
        private readonly SeewoAutoLoginPlugin _plugin;

        public SettingsView(SeewoAuthService authService, SeewoAutoLoginPlugin plugin)
        {
            InitializeComponent();
            _authService = authService;
            _plugin = plugin;

            RefreshAccountList();
        }

        #region 账号列表

        private void RefreshAccountList()
        {
            AccountListBox.Items.Clear();
            foreach (var account in _plugin.Config.Accounts)
            {
                var isActive = account.Id == _plugin.Config.ActiveAccountId;
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

                // 左侧：名称 + 状态
                var infoPanel = new StackPanel();
                var nameText = new TextBlock
                {
                    Text = account.DisplayName ?? account.Username,
                    FontSize = 14, FontWeight = isActive ? FontWeights.SemiBold : FontWeights.Normal
                };
                var statusText = new TextBlock
                {
                    Text = isActive ? "✓ 当前使用" : account.Username,
                    FontSize = 11, Foreground = isActive
                        ? new SolidColorBrush((Color)Application.Current.FindResource("SystemAccentColor"))
                        : TryFindResource("TextFillColorSecondaryBrush") as SolidColorBrush ?? Brushes.Gray
                };
                infoPanel.Children.Add(nameText);
                infoPanel.Children.Add(statusText);
                Grid.SetColumn(infoPanel, 0);
                grid.Children.Add(infoPanel);

                // 右侧：操作按钮
                var btnPanel = new StackPanel { Orientation = Orientation.Horizontal };
                if (!isActive)
                {
                    var switchBtn = new Button
                    {
                        Content = "切换", Padding = new Thickness(8, 4, 8, 4),
                        Margin = new Thickness(0, 0, 4, 0), Tag = account
                    };
                    switchBtn.Click += SwitchAccount_Click;
                    btnPanel.Children.Add(switchBtn);
                }
                var deleteBtn = new Button
                {
                    Padding = new Thickness(6, 4, 6, 4), Tag = account, ToolTip = "删除"
                };
                deleteBtn.Click += DeleteAccount_Click;
                deleteBtn.Content = new iNKORE.UI.WPF.Modern.Controls.FontIcon
                {
                    Icon = iNKORE.UI.WPF.Modern.Common.IconKeys.SegoeFluentIcons.Delete, FontSize = 12
                };
                btnPanel.Children.Add(deleteBtn);
                Grid.SetColumn(btnPanel, 1);
                grid.Children.Add(btnPanel);

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

        private void AccountListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            // 点击账号列表项不做任何操作
        }

        private void SwitchAccount_Click(object sender, RoutedEventArgs e)
        {
            var btn = sender as FrameworkElement;
            var account = btn?.Tag as SeewoAccount;
            if (account == null) return;

            _plugin.SetActiveAccount(account.Id);
            _authService.Logout();
            RefreshAccountList();
        }

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
    }
}
