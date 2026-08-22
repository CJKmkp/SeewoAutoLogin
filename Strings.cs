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
        public static string BlockEasiAgentTitle => IsEnglish ? "Seewo agent interception" : "希沃agent拦截";
        public static string BlockEasiAgentOption => IsEnglish ? "Block EasiAgent startup" : "阻止 EasiAgent 启动";
        public static string BlockEasiAgentHint => IsEnglish
            ? "Stops the Seewo agent from reopening so the local SSO port stays free for auto-login. Takes effect for the current user only. Seewo's built-in cloud login may stop working."
            : "阻止希沃agent重新启动，保持本地 SSO 端口空闲以支持自动登录。仅对当前用户生效，可能影响希沃自带云登录。";
        public static string BlockEasiAgentConfirmTitle => IsEnglish ? "Confirm change" : "确认修改";
        public static string BlockEasiAgentConfirm => IsEnglish
            ? "Enable this? The Seewo agent will no longer start for the current user, which may affect Seewo's built-in cloud login. You can turn it off here at any time."
            : "是否启用？启用后当前用户下希沃agent将无法启动，可能影响希沃自带云登录。可随时在本页关闭。";
        public static string BlockEasiAgentStatusApplied => IsEnglish
            ? "Active — EasiAgent cannot start for the current user. An already-running instance will not be affected until it exits or is ended."
            : "已生效 — 当前用户下希沃agent无法启动。正在运行的实例不受影响，待其退出或手动结束。";
        public static string BlockEasiAgentStatusRemoved => IsEnglish
            ? "Removed — EasiAgent can start again."
            : "已解除 — 希沃agent可正常启动。";
        public static string BlockEasiAgentStatusFailed => IsEnglish
            ? "Operation failed: {0}"
            : "操作失败：{0}";
        public static string QrTakeoverTitle => IsEnglish ? "Login QR takeover" : "登录二维码接管";
        public static string QrTakeoverOption => IsEnglish ? "Take over Seewo Whiteboard login QR" : "接管希沃白板登录二维码";
        public static string QrTakeoverHint => IsEnglish
            ? "Redirects Seewo Whiteboard's cloud login host to this machine so QR, password and web logins flow through the local gateway and scanned accounts are captured automatically."
            : "把希沃白板的云端登录宿主指向本机，使扫码/密码/网页登录都走本地网关代理，并自动捕获扫码账号。";
        public static string QrTakeoverConfirmTitle => IsEnglish ? "Confirm change" : "确认修改";
        public static string QrTakeoverConfirm => IsEnglish
            ? "Enable? Seewo Whiteboard login will be served through this machine's local gateway. You can turn it off here at any time."
            : "是否启用？希沃白板的登录将改走本机网关代理。可随时在本页关闭。";
        public static string QrTakeoverStatusApplied => IsEnglish
            ? "Active — Seewo Whiteboard login is served locally. Scanned accounts are captured automatically."
            : "已生效 — 希沃白板登录已走本机网关，扫码账号会自动捕获。";
        public static string QrTakeoverStatusRemoved => IsEnglish
            ? "Removed — Seewo Whiteboard returns to direct cloud login."
            : "已解除 — 希沃白板恢复直连云登录。";
        public static string QrTakeoverStatusFailed => IsEnglish
            ? "Operation failed: {0}"
            : "操作失败：{0}";
    }
}
