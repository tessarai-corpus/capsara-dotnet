using System;

namespace Capsara.SDK.Internal.Crypto
{
    /// <summary>
    /// Base64url encoding/decoding. URL-safe characters (- instead of +, _ instead of /), no padding.
    /// </summary>
    internal static class Base64Url
    {
        /// <summary>Encode bytes to base64url string (no padding).</summary>
        public static string Encode(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (data.Length == 0) return string.Empty;

            return Convert.ToBase64String(data)
                .Replace('+', '-')
                .Replace('/', '_')
                .TrimEnd('=');
        }

#if NET6_0_OR_GREATER
        /// <summary>Encode span to base64url string (no padding).</summary>
        public static string Encode(ReadOnlySpan<byte> data)
        {
            if (data.IsEmpty) return string.Empty;

            return Convert.ToBase64String(data)
                .Replace('+', '-')
                .Replace('/', '_')
                .TrimEnd('=');
        }
#endif

        /// <summary>Decode base64url string to bytes.</summary>
        /// <exception cref="FormatException">Invalid base64url encoding</exception>
        public static byte[] Decode(string encoded)
        {
            if (encoded == null) throw new ArgumentNullException(nameof(encoded));
            if (encoded.Length == 0) return Array.Empty<byte>();

            string base64 = encoded
                .Replace('-', '+')
                .Replace('_', '/');

            switch (base64.Length % 4)
            {
                case 2:
                    base64 += "==";
                    break;
                case 3:
                    base64 += "=";
                    break;
                case 1:
                    throw new FormatException("Invalid base64url string length");
            }

            return Convert.FromBase64String(base64);
        }

        /// <summary>Try to decode base64url string to bytes. Returns false on failure.</summary>
        public static bool TryDecode(string encoded, out byte[]? result)
        {
            result = null;

            if (string.IsNullOrEmpty(encoded))
            {
                result = Array.Empty<byte>();
                return true;
            }

            try
            {
                result = Decode(encoded);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
