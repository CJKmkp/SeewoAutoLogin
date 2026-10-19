using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace SeewoAutoLogin
{
    /// <summary>
    /// Stores plugin configuration with an encryption format owned by this plugin.
    /// This deliberately does not use Windows DPAPI, so the encrypted configuration
    /// remains in the plugin configuration directory and is not tied to a Windows user.
    /// </summary>
    internal static class PluginConfigStore
    {
        private const string FileHeader = "SEEWOCFG1:";
        private const int NonceLength = 12;
        private const int TagLength = 16;
        private static readonly TimeSpan WriteLockTimeout = TimeSpan.FromSeconds(5);
        private static readonly int[] WriteRetryDelaysMs = { 50, 150, 300, 500 };

        // The key is derived by the plugin rather than obtained from an operating-system
        // credential store. Keeping the format versioned allows future key rotation.
        private static readonly byte[] EncryptionKey = SHA256.HashData(
            Encoding.UTF8.GetBytes("com.icc.seewo-autologin/config-encryption/v1"));

        public static string Encrypt(string plainText)
        {
            var plainBytes = Encoding.UTF8.GetBytes(plainText);
            var nonce = RandomNumberGenerator.GetBytes(NonceLength);
            var cipherBytes = new byte[plainBytes.Length];
            var tag = new byte[TagLength];

            using (var aes = new AesGcm(EncryptionKey))
            {
                aes.Encrypt(nonce, plainBytes, cipherBytes, tag);
            }

            var payload = new byte[NonceLength + TagLength + cipherBytes.Length];
            Buffer.BlockCopy(nonce, 0, payload, 0, NonceLength);
            Buffer.BlockCopy(tag, 0, payload, NonceLength, TagLength);
            Buffer.BlockCopy(cipherBytes, 0, payload, NonceLength + TagLength, cipherBytes.Length);
            return FileHeader + Convert.ToBase64String(payload);
        }

        public static bool TryDecrypt(string content, out string plainText)
        {
            plainText = null;
            if (string.IsNullOrWhiteSpace(content) || !content.StartsWith(FileHeader, StringComparison.Ordinal))
                return false;

            try
            {
                var payload = Convert.FromBase64String(content.Substring(FileHeader.Length));
                if (payload.Length < NonceLength + TagLength)
                    return false;

                var cipherLength = payload.Length - NonceLength - TagLength;
                var plainBytes = new byte[cipherLength];
                using (var aes = new AesGcm(EncryptionKey))
                {
                    aes.Decrypt(
                        payload.AsSpan(0, NonceLength),
                        payload.AsSpan(NonceLength + TagLength, cipherLength),
                        payload.AsSpan(NonceLength, TagLength),
                        plainBytes);
                }

                plainText = Encoding.UTF8.GetString(plainBytes);
                return true;
            }
            catch (CryptographicException)
            {
                return false;
            }
            catch (FormatException)
            {
                return false;
            }
        }

        public static bool IsEncrypted(string content) =>
            !string.IsNullOrWhiteSpace(content) && content.StartsWith(FileHeader, StringComparison.Ordinal);

        public static string ReadShared(string path)
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream, Encoding.UTF8, true);
            return reader.ReadToEnd();
        }

        public static void WriteEncrypted(string path, string json)
        {
            if (string.IsNullOrWhiteSpace(path))
                throw new ArgumentException("配置文件路径不能为空。", nameof(path));

            var encrypted = Encrypt(json);
            using var mutex = new Mutex(false, BuildMutexName(path));
            var lockAcquired = false;
            try
            {
                try
                {
                    lockAcquired = mutex.WaitOne(WriteLockTimeout);
                }
                catch (AbandonedMutexException)
                {
                    lockAcquired = true;
                }

                if (!lockAcquired)
                    throw new IOException("等待配置文件写入锁超时。");

                for (var attempt = 0; ; attempt++)
                {
                    var temporaryPath = BuildTemporaryPath(path);
                    try
                    {
                        using (var stream = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                        using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
                        {
                            writer.Write(encrypted);
                        }

                        ReplaceAtomically(temporaryPath, path);
                        return;
                    }
                    catch (IOException) when (attempt < WriteRetryDelaysMs.Length)
                    {
                        TryDelete(temporaryPath);
                        Thread.Sleep(WriteRetryDelaysMs[attempt]);
                    }
                    catch (UnauthorizedAccessException) when (attempt < WriteRetryDelaysMs.Length)
                    {
                        TryDelete(temporaryPath);
                        Thread.Sleep(WriteRetryDelaysMs[attempt]);
                    }
                    catch
                    {
                        TryDelete(temporaryPath);
                        throw;
                    }
                }
            }
            finally
            {
                if (lockAcquired)
                    mutex.ReleaseMutex();
            }
        }

        private static string BuildTemporaryPath(string path)
        {
            var directory = Path.GetDirectoryName(path) ?? "";
            var fileName = Path.GetFileName(path);
            return Path.Combine(directory, $"{fileName}.{Guid.NewGuid():N}.tmp");
        }

        private static string BuildMutexName(string path)
        {
            var normalizedPath = Path.GetFullPath(path).ToUpperInvariant();
            var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(normalizedPath)));
            return $@"Local\SeewoAutoLogin.Config.{hash}";
        }

        private static void ReplaceAtomically(string temporaryPath, string path)
        {
            if (File.Exists(path))
            {
                File.Replace(temporaryPath, path, null, true);
                return;
            }

            File.Move(temporaryPath, path);
        }

        private static void TryDelete(string path)
        {
            try
            {
                if (File.Exists(path))
                    File.Delete(path);
            }
            catch
            {
            }
        }
    }
}
