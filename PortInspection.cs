using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace SeewoAutoLogin
{
    /// <summary>
    /// 某个监听端口当前的占用者信息。
    /// </summary>
    internal sealed class PortOwnerInfo
    {
        public int ProcessId { get; init; }
        public string ProcessName { get; init; }
        public string ExecutablePath { get; init; }
        public bool IsTrustedEasiAgent { get; init; }

        public override string ToString()
        {
            var name = string.IsNullOrEmpty(ProcessName) ? "unknown" : ProcessName;
            var path = string.IsNullOrEmpty(ExecutablePath) ? "" : $"; path={ExecutablePath}";
            return $"{name} (pid={ProcessId}{path})";
        }
    }

    /// <summary>
    /// 端口占用进程检测。
    /// 通过 iphlpapi!GetExtendedTcpTable 拿到监听端口对应的 OwningPid（IPv4 + IPv6），
    /// 再结合进程路径判断是不是希沃 EasiAgent，避免“端口被占就打死 EasiAgent”的误伤。
    /// </summary>
    internal static class PortInspection
    {
        public const string EasiAgentProcessName = "EasiAgent";
        public const string TrustedEasiAgentSuffix = @"\Seewo\EasiAgent\EasiAgent.exe";

        private const int AfInet = 2;
        private const int AfInet6 = 23;
        private const int TcpTableOwnerPidListener = 3;
        private const uint ErrorInsufficientBuffer = 122;
        private const uint NoError = 0;

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, uint reserved);

        [StructLayout(LayoutKind.Sequential)]
        private struct MibTcpRowOwnerPid
        {
            public uint State;
            public uint LocalAddr;
            public uint LocalPort;
            public uint RemoteAddr;
            public uint RemotePort;
            public uint OwningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MibTcp6RowOwnerPid
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] LocalAddr;
            public uint LocalScopeId;
            public uint LocalPort;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] RemoteAddr;
            public uint RemoteScopeId;
            public uint RemotePort;
            public uint State;
            public uint OwningPid;
        }

        /// <summary>端口是否有监听者。带权限/非常规协议的兜底判断。</summary>
        public static bool IsListening(int port)
        {
            try
            {
                return IPGlobalProperties.GetIPGlobalProperties()
                    .GetActiveTcpListeners()
                    .Any(endpoint => endpoint.Port == port);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 找到监听指定端口的全部进程（同一端口可能同时被 IPv4/IPv6 或多个进程共享）。
        /// 返回空列表且 <see cref="IsListening"/> 为 true，表示端口确实被占但当前权限看不到占用者。
        /// </summary>
        public static IReadOnlyList<PortOwnerInfo> GetListeners(int port)
        {
            var pids = new HashSet<int>();
            try
            {
                foreach (var row in EnumerateListeners(AfInet).Concat(EnumerateListeners(AfInet6)))
                {
                    if (row.Port == port && row.Pid > 0) pids.Add(row.Pid);
                }
            }
            catch
            {
                // 枚举失败时返回空列表，由调用方结合 IsListening 判断。
            }
            return pids.Select(CreateOwnerInfo).ToList();
        }

        /// <summary>用一行文本描述端口占用者，便于写诊断日志。</summary>
        public static string DescribeListener(int port)
        {
            var owners = GetListeners(port);
            if (owners.Count > 0) return string.Join("; ", owners.Select(owner => owner.ToString()));
            return IsListening(port) ? "占用进程未知（可能权限不足）" : "无监听进程";
        }

        /// <summary>判断路径是否为受信任的希沃 EasiAgent。</summary>
        public static bool IsTrustedEasiAgentPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            try
            {
                var fullPath = Path.GetFullPath(path);
                return fullPath.EndsWith(TrustedEasiAgentSuffix, StringComparison.OrdinalIgnoreCase) &&
                       string.Equals(Path.GetFileName(fullPath), "EasiAgent.exe", StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>查找受信任路径的希沃 EasiAgent 进程（不代表它一定占用了目标端口）。</summary>
        public static bool TryFindTrustedEasiAgent(out int pid, out string path)
        {
            pid = 0;
            path = null;
            foreach (var process in Process.GetProcessesByName(EasiAgentProcessName))
            {
                try
                {
                    var file = process.MainModule?.FileName;
                    if (!IsTrustedEasiAgentPath(file)) continue;
                    pid = process.Id;
                    path = file;
                    return true;
                }
                catch
                {
                    // 无法读取模块路径时按不可信处理，继续找下一个。
                }
                finally
                {
                    process.Dispose();
                }
            }
            return false;
        }

        /// <summary>结束受信任路径的希沃 EasiAgent。调用方必须先确认端口确实被它占用并征得同意。</summary>
        public static bool TryStopTrustedEasiAgent(out string error)
        {
            error = null;
            foreach (var process in Process.GetProcessesByName(EasiAgentProcessName))
            {
                try
                {
                    var path = process.MainModule?.FileName;
                    if (!IsTrustedEasiAgentPath(path))
                    {
                        continue;
                    }

                    process.Kill();
                    process.WaitForExit(5000);
                    if (process.HasExited) return true;
                    error = "进程未在超时内退出";
                }
                catch (Exception ex)
                {
                    error = $"{ex.GetType().Name}: {ex.Message}";
                }
                finally
                {
                    process.Dispose();
                }
            }
            return false;
        }

        private static PortOwnerInfo CreateOwnerInfo(int pid)
        {
            string name = null;
            string path = null;
            try
            {
                using var process = Process.GetProcessById(pid);
                name = process.ProcessName;
                try { path = process.MainModule?.FileName; } catch { }
            }
            catch
            {
                // 进程可能已退出或拒绝访问；保留 pid，名称/路径为空。
            }

            return new PortOwnerInfo
            {
                ProcessId = pid,
                ProcessName = name,
                ExecutablePath = path,
                IsTrustedEasiAgent = IsTrustedEasiAgentPath(path)
            };
        }

        private static IEnumerable<(int Port, int Pid)> EnumerateListeners(int addressFamily)
        {
            var size = 0;
            var result = GetExtendedTcpTable(IntPtr.Zero, ref size, false, addressFamily, TcpTableOwnerPidListener, 0);
            if (result != ErrorInsufficientBuffer || size <= 0) yield break;

            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                result = GetExtendedTcpTable(buffer, ref size, false, addressFamily, TcpTableOwnerPidListener, 0);
                if (result != NoError) yield break;

                var count = Marshal.ReadInt32(buffer);
                var rowPtr = IntPtr.Add(buffer, sizeof(int));
                if (addressFamily == AfInet)
                {
                    var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
                    for (var i = 0; i < count; i++)
                    {
                        var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(IntPtr.Add(rowPtr, i * rowSize));
                        yield return (NetworkToHostPort(row.LocalPort), (int)row.OwningPid);
                    }
                }
                else
                {
                    var rowSize = Marshal.SizeOf<MibTcp6RowOwnerPid>();
                    for (var i = 0; i < count; i++)
                    {
                        var row = Marshal.PtrToStructure<MibTcp6RowOwnerPid>(IntPtr.Add(rowPtr, i * rowSize));
                        yield return (NetworkToHostPort(row.LocalPort), (int)row.OwningPid);
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        /// <summary>GetExtendedTcpTable 返回的端口号低 16 位为网络字节序。</summary>
        private static int NetworkToHostPort(uint value)
        {
            return ((int)(value & 0xFF) << 8) | (int)((value >> 8) & 0xFF);
        }
    }
}
