using System;
using System.Collections.Generic;
using Microsoft.Win32;

namespace SeewoAutoLogin
{
    /// <summary>
    /// 通过映像劫持（IFEO Debugger）阻止希沃 EasiAgent 启动，
    /// 让本地 SSO 网关端口不被占用。仅对当前用户生效，无需管理员权限。
    /// 写入按“全部视图成功或全部回滚”处理，避免配置与注册表状态不一致；
    /// 解除时只删除本插件写入的值，不碰其它工具留下的 IFEO 配置。
    /// </summary>
    public static class EasiAgentStartupBlocker
    {
        private const string IfeoSubKey =
            @"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\EasiAgent.exe";
        private const string DebuggerValueName = "Debugger";

        // 指向一个不存在的可执行文件：当 EasiAgent 尝试启动时，系统改为启动该路径，
        // 因文件不存在而报错退出，实现“劫持”，使 EasiAgent 无法启动。
        private const string BlockStub = @"C:\Windows\System32\seewo-easiagent-blocked.exe";

        /// <summary>当前用户的注册表视图；32 位系统上不存在 Registry64 视图。</summary>
        private static readonly RegistryView[] RegistryViews = Environment.Is64BitOperatingSystem
            ? new[] { RegistryView.Registry64, RegistryView.Registry32 }
            : new[] { RegistryView.Registry32 };

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
            var appliedViews = new List<RegistryView>();
            foreach (var view in RegistryViews)
            {
                var error = apply ? ApplyOne(view) : RemoveOne(view);
                if (error != string.Empty)
                {
                    // 部分视图失败时回滚已写入的视图：失败必须意味着“完全没生效”，
                    // 否则界面显示未启用、注册表里却还挂着劫持。
                    if (apply)
                    {
                        foreach (var applied in appliedViews) RemoveOne(applied);
                    }
                    return error;
                }
                if (apply) appliedViews.Add(view);
            }
            return string.Empty;
        }

        private static string ApplyOne(RegistryView view)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, view);
                using var key = baseKey.CreateSubKey(IfeoSubKey);
                if (key == null) return $"[{view}] 无法创建 IFEO 注册表键";

                var existing = key.GetValue(DebuggerValueName) as string;
                if (!string.IsNullOrEmpty(existing) &&
                    !string.Equals(existing, BlockStub, StringComparison.OrdinalIgnoreCase))
                {
                    // 不覆盖其它工具/调试器写入的 Debugger，避免互相破坏后难以排查。
                    return $"[{view}] 已存在其它 Debugger 配置，拒绝覆盖: {existing}";
                }

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
                using (var key = baseKey.OpenSubKey(IfeoSubKey, writable: true))
                {
                    if (key == null) return string.Empty;
                    var value = key.GetValue(DebuggerValueName) as string;
                    // 仅在确为本插件写入的占位值时删除，避免误删该进程的其他 IFEO 配置。
                    if (!string.Equals(value, BlockStub, StringComparison.OrdinalIgnoreCase))
                        return string.Empty;

                    key.DeleteValue(DebuggerValueName, throwOnMissingValue: false);
                    // 键里还有别人的值/子键就保留，不能整棵删掉。
                    if (key.ValueCount > 0 || key.SubKeyCount > 0) return string.Empty;
                }

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
