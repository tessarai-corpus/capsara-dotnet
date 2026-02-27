using System;
using System.Security.Cryptography;

namespace Capsara.SDK.Internal.Utils
{
    /// <summary>
    /// NanoID-compatible, cryptographically secure, unbiased ID generator.
    /// Uses a 64-character URL-safe alphabet (power of 2), allowing perfect
    /// uniform distribution via bitmask without rejection sampling.
    /// </summary>
    internal static class IdGenerator
    {
        /// <summary>
        /// URL-safe 64-character alphabet (2^6 = 64 characters).
        /// </summary>
        private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

        /// <summary>
        /// Default ID length (21 characters = ~126 bits of entropy).
        /// </summary>
        private const int DefaultLength = 21;

        /// <summary>
        /// Generate a cryptographically secure, URL-safe, unbiased random ID.
        /// </summary>
        /// <param name="size">Length of the ID (default 21 → ~126 bits of entropy)</param>
        /// <returns>Random ID string</returns>
        /// <remarks>
        /// Security: Uses RandomNumberGenerator (CSPRNG) with bitmask for uniform distribution.
        /// With 64 characters (2^6), each byte maps to exactly 4 alphabet indices with no bias.
        /// </remarks>
        public static string Generate(int size = DefaultLength)
        {
            if (size <= 0)
                throw new ArgumentOutOfRangeException(nameof(size), "Size must be positive");

#if NET6_0_OR_GREATER
            Span<byte> bytes = stackalloc byte[size];
            RandomNumberGenerator.Fill(bytes);

            return string.Create(size, bytes.ToArray(), static (chars, bytesArray) =>
            {
                for (int i = 0; i < chars.Length; i++)
                {
                    // Bitmask with 0x3F (63) gives uniform distribution for 64-char alphabet
                    // Each of 256 byte values maps to exactly 4 alphabet characters (256/64 = 4)
                    chars[i] = Alphabet[bytesArray[i] & 0x3F];
                }
            });
#else
            byte[] bytes = new byte[size];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }

            char[] chars = new char[size];
            for (int i = 0; i < size; i++)
            {
                // Bitmask with 0x3F (63) gives uniform distribution for 64-char alphabet
                chars[i] = Alphabet[bytes[i] & 0x3F];
            }

            return new string(chars);
#endif
        }

    }
}
