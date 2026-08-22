using System;
using Microsoft.Win32;

namespace SeewoAutoLogin
{
    /// <summary>
    /// 通过映像劫持（IFEO Debugger）阻止希沃 EasiAgent 启动，
    /// 让本地 SSO 网关端口不被占用。仅对当前用户生效，无需管理员权限。
    /// </summary>
    public static class EasiAgentStartupBlocker
    {
        private const string IfeoSubKey =
            @"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\EasiAgent.exe";
        private const string DebuggerValueName = "Debugger";

        // 指向一个不存在的可执行文件：当 EasiAgent 尝试启动时，系统改为启动该路径，
        // 因文件不存在而报错退出，实现“劫持”，使 EasiAgent 无法启动。
        private const string BlockStub = @"C:\Windows\System32\seewo-easiagent-blocked.exe";

        /// <summary>当前用户的 64 位与 32 位注册表视图。</summary>
        private static readonly RegistryView[] RegistryViews =
            { RegistryView.Registry64, RegistryView.Registry32 };

        /// <summary>是否已启用阻止（任一视图命中即视为已启用）。</summary>
        public static bool IsBlocked()
        {
            foreach (var view in RegistryViews)
            {
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, view);
                    using var key = baseKey?.OpenSubKey(IfeoSubKey);
                    var value = key?.GetValue(DebuggerValueName) as string;
                    if (string.Equals(value, BlockStub, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
                catch
                {
                    // 单个视图读取失败不影响判断，继续下一个视图。
                }
            }
            return false;
        }

        /// <summary>应用阻止。返回空字符串表示成功，否则返回错误信息。</summary>
        public static string ApplyBlock()
        {
            return ApplyOrRemove(apply: true);
        }

        /// <summary>解除阻止。返回空字符串表示成功，否则返回错误信息。</summary>
        public static string RemoveBlock()
        {
            return ApplyOrRemove(apply: false);
        }

        private static string ApplyOrRemove(bool apply)
        {
            foreach (var view in RegistryViews)
            {
                var error = apply ? ApplyOne(view) : RemoveOne(view);
                if (error != string.Empty) return error;
            }
            return string.Empty;
        }

        private static string ApplyOne(RegistryView view)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, view);
                using var key = baseKey.CreateSubKey(IfeoSubKey);
                key.SetValue(DebuggerValueName, BlockStub, RegistryValueKind.String);
                return string.Empty;
            }
            catch (Exception ex)
            {
                return $"[{view}] {ex.Message}";
            }
        }

        private static string RemoveOne(RegistryView view)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, view);
                using var key = baseKey.OpenSubKey(IfeoSubKey, writable: true);
                if (key == null) return string.Empty;
                var value = key.GetValue(DebuggerValueName) as string;
                // 仅在确为本插件写入的占位值时删除，避免误删该进程的其他 IFEO 配置。
                if (string.Equals(value, BlockStub, StringComparison.OrdinalIgnoreCase))
                    baseKey.DeleteSubKeyTree(IfeoSubKey, throwOnMissingSubKey: false);
                return string.Empty;
            }
            catch (Exception ex)
            {
                return $"[{view}] {ex.Message}";
            }
        }
    }
}