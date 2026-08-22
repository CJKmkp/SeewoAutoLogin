using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SeewoAutoLogin
{
    /// <summary>
    /// 接管希沃白板五的登录宿主：把 %AppData%\Seewo\EasiNote5\Data\Configs.fkv
    /// 里的 UcHost 覆盖为本地网关地址，使白板五的登录流量（扫码/密码/网页）打到本机。
    /// 格式严格对齐 Cvte.Configurations.Core.CoinConfigurationSerializer 的双行 key/value 格式，
    /// 备份原文件以便一键还原。
    /// </summary>
    public static class EasiNoteUcHostOverride
    {
        public const string UcHostKey = "Cloud.UcHost";
        private const string LegacyUcHostKey = "UcHost";

        public static string FkvPath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Seewo", "EasiNote5", "Data", "Configs.fkv");

        private const string BackupFileName = "easinote5_configs.fkv.backup";

        private static string BackupPath(string configFolder) =>
            Path.Combine(configFolder ?? "", BackupFileName);

        /// <summary>当前 fkv 的 UcHost 值；文件不存在返回 null。</summary>
        public static string GetCurrentUcHost()
        {
            try
            {
                if (!File.Exists(FkvPath)) return null;
                return ParseFkv(File.ReadAllText(FkvPath)).TryGetValue(UcHostKey, out var v) ? v : null;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>本地 UcHost 是否已生效。</summary>
        public static bool IsApplied(string localUcHost)
        {
            return string.Equals(GetCurrentUcHost(), localUcHost, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// 覆盖 UcHost 为本地地址。首次应用前先备份原文件。返回空字符串表示成功，否则返回错误信息（幂等）。
        /// </summary>
        public static string Apply(string localUcHost, string configFolder)
        {
            try
            {
                if (IsApplied(localUcHost)) return string.Empty;

                var backupPath = BackupPath(configFolder);
                if (!File.Exists(backupPath) && File.Exists(FkvPath))
                {
                    // 仅在第一次接管时备份，避免后续覆盖破坏原始状态。
                    File.WriteAllText(backupPath, File.ReadAllText(FkvPath), new UTF8Encoding(false));
                }

                var dict = ReadOrEmpty();
                dict.Remove(LegacyUcHostKey);
                dict[UcHostKey] = localUcHost;
                WriteFkv(SerializeFkv(dict));
                if (!IsApplied(localUcHost))
                    return $"配置写入后校验失败：{FkvPath}";
                return string.Empty;
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }

        /// <summary>还原 UcHost 为接管前的值（有备份则整档还原，无备份则移除该键）。返回空字符串表示成功。</summary>
        public static string Remove(string configFolder)
        {
            try
            {
                var backupPath = BackupPath(configFolder);
                if (File.Exists(backupPath))
                {
                    WriteFkv(File.ReadAllText(backupPath));
                    try { File.Delete(backupPath); } catch { }
                    return string.Empty;
                }

                if (!File.Exists(FkvPath)) return string.Empty;

                var dict = ReadOrEmpty();
                var changed = dict.Remove(UcHostKey);
                changed |= dict.Remove(LegacyUcHostKey);
                if (changed)
                    WriteFkv(SerializeFkv(dict));
                return string.Empty;
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }

        private static Dictionary<string, string> ReadOrEmpty()
        {
            if (!File.Exists(FkvPath)) return new Dictionary<string, string>(StringComparer.Ordinal);
            return ParseFkv(File.ReadAllText(FkvPath));
        }

        private static void WriteFkv(string text)
        {
            var dir = Path.GetDirectoryName(FkvPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.WriteAllText(FkvPath, text, new UTF8Encoding(false));
        }

        private static string EscapeString(string str)
        {
            if (str == null) throw new ArgumentNullException(nameof(str));
            if (str.StartsWith(">", StringComparison.Ordinal) || str.StartsWith("?", StringComparison.Ordinal))
                return "?" + str;
            return str;
        }

        /// <summary>严格对齐 CoinConfigurationSerializer.Serialize（按键排序）。</summary>
        private static string SerializeFkv(Dictionary<string, string> keyValue)
        {
            var sb = new StringBuilder();
            sb.Append("> 配置文件\n");
            sb.Append("> 版本 1.0\n");
            var keys = new List<string>(keyValue.Keys);
            keys.Sort(StringComparer.Ordinal);
            foreach (var key in keys)
            {
                sb.Append(EscapeString(key ?? "")).Append('\n');
                sb.Append(EscapeString(keyValue[key] ?? "")).Append("\n>\n");
            }
            sb.Append("> 配置文件结束");
            return sb.ToString();
        }

        /// <summary>严格对齐 CoinConfigurationSerializer.Deserialize。</summary>
        private static Dictionary<string, string> ParseFkv(string str)
        {
            var dict = new Dictionary<string, string>(StringComparer.Ordinal);
            string currentKey = null;
            foreach (var rawLine in (str ?? "").Split('\n'))
            {
                var item = rawLine.Trim();
                if (item.StartsWith(">", StringComparison.Ordinal))
                {
                    currentKey = null;
                    continue;
                }
                var value = item.StartsWith("?", StringComparison.Ordinal) ? item.Substring(1) : item;
                if (currentKey == null)
                {
                    currentKey = value;
                    if (dict.ContainsKey(currentKey)) dict.Remove(currentKey);
                }
                else if (dict.ContainsKey(currentKey))
                {
                    dict[currentKey] = dict[currentKey] + "\n" + value;
                }
                else
                {
                    dict.Add(currentKey, value);
                }
            }
            return dict;
        }
    }
}