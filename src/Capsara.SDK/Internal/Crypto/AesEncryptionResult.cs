using System;

namespace Capsara.SDK.Internal.Crypto
{
    /// <summary>
    /// Result of AES-256-GCM encryption.
    /// All values are base64url-encoded for API compatibility.
    /// </summary>
    internal sealed class AesEncryptionResult
    {
        /// <summary>
        /// Base64url-encoded encrypted data (ciphertext only, no IV or tag).
        /// </summary>
        public string EncryptedData { get; }

        /// <summary>
        /// Base64url-encoded 12-byte (96-bit) initialization vector.
        /// </summary>
        public string Iv { get; }

        /// <summary>
        /// Base64url-encoded 16-byte (128-bit) authentication tag.
        /// </summary>
        public string AuthTag { get; }

        /// <summary>
        /// Raw ciphertext bytes.
        /// </summary>
        public byte[] CiphertextBytes { get; }

        /// <summary>
        /// Raw ciphertext bytes (alias for CiphertextBytes).
        /// </summary>
        public byte[] Ciphertext => CiphertextBytes;

        /// <summary>
        /// Raw IV bytes.
        /// </summary>
        public byte[] IvBytes { get; }

        /// <summary>
        /// Raw authentication tag bytes.
        /// </summary>
        public byte[] AuthTagBytes { get; }

        /// <summary>
        /// Create a new AES encryption result.
        /// </summary>
        /// <param name="ciphertext">Raw ciphertext bytes</param>
        /// <param name="iv">Raw IV bytes (must be 12 bytes)</param>
        /// <param name="authTag">Raw auth tag bytes (must be 16 bytes)</param>
        public AesEncryptionResult(byte[] ciphertext, byte[] iv, byte[] authTag)
        {
            if (ciphertext == null) throw new ArgumentNullException(nameof(ciphertext));
            if (iv == null) throw new ArgumentNullException(nameof(iv));
            if (authTag == null) throw new ArgumentNullException(nameof(authTag));

            if (iv.Length != 12)
                throw new ArgumentException("IV must be 12 bytes (96 bits)", nameof(iv));
            if (authTag.Length != 16)
                throw new ArgumentException("Auth tag must be 16 bytes (128 bits)", nameof(authTag));

            CiphertextBytes = ciphertext;
            IvBytes = iv;
            AuthTagBytes = authTag;

            EncryptedData = Base64Url.Encode(ciphertext);
            Iv = Base64Url.Encode(iv);
            AuthTag = Base64Url.Encode(authTag);
        }
    }
}
