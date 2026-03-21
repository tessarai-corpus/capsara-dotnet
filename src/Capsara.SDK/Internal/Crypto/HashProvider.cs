using System;
using System.Security.Cryptography;
using System.Text;

namespace Capsara.SDK.Internal.Crypto
{
    /// <summary>SHA-256 hashing and constant-time comparison.</summary>
    internal static class HashProvider
    {
        /// <summary>Compute SHA-256 hash. Returns lowercase hex (64 characters).</summary>
        public static string ComputeHash(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            using var sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(data);

            return BytesToHexLower(hash);
        }

#if NET6_0_OR_GREATER
        /// <summary>Compute SHA-256 hash (span version). Returns lowercase hex (64 characters).</summary>
        public static string ComputeHash(ReadOnlySpan<byte> data)
        {
            Span<byte> hash = stackalloc byte[32];
            SHA256.HashData(data, hash);
            return BytesToHexLower(hash);
        }
#endif

        /// <summary>Compute SHA-256 hash of a UTF-8 string. Returns lowercase hex (64 characters).</summary>
        public static string ComputeHash(string text)
        {
            if (text == null) throw new ArgumentNullException(nameof(text));

            byte[] data = Encoding.UTF8.GetBytes(text);
            return ComputeHash(data);
        }

        /// <summary>Verify data matches an expected hash using constant-time comparison.</summary>
        public static bool VerifyHash(byte[] data, string expectedHash)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (string.IsNullOrEmpty(expectedHash)) throw new ArgumentNullException(nameof(expectedHash));

            string actualHash = ComputeHash(data);

            // Constant-time comparison
            return ConstantTimeEquals(actualHash, expectedHash);
        }

        /// <summary>Convert bytes to lowercase hex string.</summary>
        private static string BytesToHexLower(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
        }

#if NET6_0_OR_GREATER
        /// <summary>Convert span to lowercase hex string.</summary>
        private static string BytesToHexLower(ReadOnlySpan<byte> bytes)
        {
            return Convert.ToHexString(bytes).ToLowerInvariant();
        }
#endif

        /// <summary>Constant-time byte array comparison to prevent timing attacks.</summary>
        public static bool ConstantTimeEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null) return a == b;
            if (a.Length != b.Length) return false;

#if NET6_0_OR_GREATER
            return CryptographicOperations.FixedTimeEquals(a, b);
#else
            int diff = 0;
            for (int i = 0; i < a.Length; i++)
            {
                diff |= a[i] ^ b[i];
            }
            return diff == 0;
#endif
        }

        /// <summary>Constant-time string comparison to prevent timing attacks.</summary>
        private static bool ConstantTimeEquals(string a, string b)
        {
            if (a.Length != b.Length)
                return false;

#if NET6_0_OR_GREATER
            return CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(a),
                Encoding.UTF8.GetBytes(b));
#else
            int diff = 0;
            for (int i = 0; i < a.Length; i++)
            {
                diff |= a[i] ^ b[i];
            }
            return diff == 0;
#endif
        }
    }
}
