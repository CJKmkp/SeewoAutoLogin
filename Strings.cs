using System.Globalization;

namespace SeewoAutoLogin
{
    internal static class Strings
    {
        private static bool IsEnglish => CultureInfo.CurrentUICulture.Name.StartsWith("en", System.StringComparison.OrdinalIgnoreCase);

        public static string QrTitle => IsEnglish ? "Official Seewo QR login" : "希沃官方扫码登录";
        public static string QrDescription => IsEnglish
            ? "A QR code will be requested from Seewo Account. Scan it with the official Seewo mobile app and confirm the sign-in."
            : "将从希沃账号中心获取二维码。请使用希沃官方移动端扫码，并在手机上确认登录。";
        public static string QrConsentTitle => IsEnglish ? "Authorize Seewo sign-in" : "授权希沃账号登录";
        public static string QrConsent => IsEnglish
            ? "ICC-CE will contact id.seewo.com, create a short-lived QR session, and obtain your account profile after confirmation. The QR session and token are never written to logs. Continue?"
            : "ICC-CE 将连接 id.seewo.com 创建短时二维码会话，并在你确认后获取账号资料。二维码会话密钥和令牌不会写入日志。是否继续？";
        public static string Start => IsEnglish ? "Start QR login" : "开始扫码登录";
        public static string Refresh => IsEnglish ? "Refresh QR code" : "刷新二维码";
        public static string Cancel => IsEnglish ? "Cancel" : "取消";
        public static string Continue => IsEnglish ? "Continue" : "继续";
        public static string Creating => IsEnglish ? "Requesting QR code..." : "正在获取二维码…";
        public static string WaitingForScan => IsEnglish ? "Scan the QR code with the official Seewo mobile app." : "请使用希沃官方移动端扫描二维码。";
        public static string WaitingForConfirmation => IsEnglish ? "Scanned. Confirm the sign-in on your phone." : "已扫码，请在手机上确认登录。";
        public static string Completing => IsEnglish ? "Confirming your account..." : "正在验证账号…";
        public static string Succeeded => IsEnglish ? "Signed in successfully." : "扫码登录成功。";
        public static string Expired => IsEnglish ? "The QR code expired. Refresh it and try again." : "二维码已过期，请刷新后重试。";
        public static string Cancelled => IsEnglish ? "QR login cancelled." : "已取消扫码登录。";
        public static string Denied => IsEnglish ? "The sign-in was declined on the phone." : "手机端已取消登录。";
        public static string NetworkError => IsEnglish ? "Unable to reach Seewo Account. Check the network and retry." : "无法连接希沃账号中心，请检查网络后重试。";
        public static string ProtocolError => IsEnglish ? "Seewo Account returned an unexpected response." : "希沃账号中心返回了无法识别的响应。";
        public static string Saved => IsEnglish ? "The account was added." : "账号已添加。";
        public static string AccountFallback => IsEnglish ? "Seewo account" : "希沃账号";
        public static string SecondsRemaining(int seconds) => IsEnglish ? $"{seconds}s remaining" : $"剩余 {seconds} 秒";
        public static string RotationTitle => IsEnglish ? "User list rotation" : "用户列表轮换";
        public static string RotationEnabled => IsEnglish ? "Rotate quick-login users when the Seewo login window reopens" : "希沃快捷登录窗口重开时轮换用户列表";
        public static string RotationGroupSize => IsEnglish ? "Users per group" : "每组用户数";
        public static string RotationStatus(int group) => IsEnglish ? $"Current group: {group}" : $"当前列表：第 {group} 组";
        public static string RotationHint => IsEnglish ? "Disabled by default. Reopening within 10 seconds switches to the next group." : "默认关闭。窗口关闭后 10 秒内重新打开会切换到下一组。";
        public static string ExperimentalTokenRefreshTitle => IsEnglish ? "Experimental: refresh QR token before SSO login" : "实验功能：SSO 登录前刷新扫码 Token";
        public static string ExperimentalTokenRefreshDescription => IsEnglish ? "Exchange the QR token through Seewo Account before each SSO login and persist the returned token. Disabled by default." : "每次扫码账号 SSO 登录前通过希沃账号中心换发 Token，并保存返回的新 Token。默认关闭。";
    }
}
