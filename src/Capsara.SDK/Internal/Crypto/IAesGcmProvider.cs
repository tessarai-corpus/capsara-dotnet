using System;

namespace Capsara.SDK.Internal.Crypto
{
    /// <summary>
    /// Platform-agnostic AES-256-GCM provider. Native AesGcm on .NET 6+, BouncyCastle on .NET Framework 4.8.
    /// </summary>
    internal interface IAesGcmProvider : IDisposable
    {
        /// <summary>
        /// Encrypt data with AES-256-GCM, generating a random 12-byte IV.
        /// </summary>
        /// <exception cref="ArgumentException">Key is not 32 bytes</exception>
        AesEncryptionResult Encrypt(byte[] plaintext, byte[] key);

        /// <summary>
        /// Encrypt data with AES-256-GCM using a specified IV (must not be reused with same key).
        /// </summary>
        AesEncryptionResult Encrypt(byte[] plaintext, byte[] key, byte[] iv);

        /// <summary>
        /// Decrypt base64url-encoded data with AES-256-GCM.
        /// </summary>
        /// <exception cref="System.Security.Cryptography.CryptographicException">Decryption or authentication failed</exception>
        byte[] Decrypt(string ciphertext, byte[] key, string iv, string authTag);

        /// <summary>
        /// Decrypt raw byte data with AES-256-GCM.
        /// </summary>
        byte[] Decrypt(byte[] ciphertext, byte[] key, byte[] iv, byte[] authTag);
    }
}
