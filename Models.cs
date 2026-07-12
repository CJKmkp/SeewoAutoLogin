using System.Collections.Generic;

namespace SeewoAutoLogin
{
    /// <summary>
    /// 插件配置（多用户）
    /// </summary>
    public class PluginConfig
    {
        public bool UserListRotationEnabled { get; set; }
        public int UserListRotationGroupSize { get; set; } = 6;
        public List<SeewoAccount> Accounts { get; set; } = new List<SeewoAccount>();
        public string ActiveAccountId { get; set; } = "";
        public bool AutoLogin { get; set; }
        public bool UseAppPassword { get; set; }
        public bool UsePluginPassword { get; set; }
        public string PluginPasswordHash { get; set; } = "";
        public string PluginPasswordSalt { get; set; } = "";
    }

    /// <summary>
    /// 希沃账号信息
    /// </summary>
    public class SeewoAccount
    {
        public string Id { get; set; } = System.Guid.NewGuid().ToString("N")[..8];
        public string DisplayName { get; set; } = "";
        public string Username { get; set; } = "";
        public string Password { get; set; } = "";
        public string QrCredentialId { get; set; } = "";
        public SeewoUserInfo UserInfo { get; set; }
    }
}
