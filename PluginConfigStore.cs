using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

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

        public static void WriteEncrypted(string path, string json)
        {
            var temporaryPath = path + ".tmp";
            File.WriteAllText(temporaryPath, Encrypt(json), new UTF8Encoding(false));
            File.Move(temporaryPath, path, true);
        }
    }
}
