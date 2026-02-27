#if NET6_0_OR_GREATER

using System;
using System.Security.Cryptography;

namespace Capsara.SDK.Internal.Crypto
{
    /// <summary>
    /// Native .NET AES-GCM implementation. Available in .NET Core 3.0+ / .NET 5+.
    /// </summary>
    internal sealed class NativeAesGcmProvider : IAesGcmProvider
    {
        private const int KeySizeBytes = 32;   // 256 bits
        private const int IvSizeBytes = 12;    // 96 bits (GCM standard)
        private const int TagSizeBytes = 16;   // 128 bits

        private bool _disposed;

        /// <inheritdoc />
        public AesEncryptionResult Encrypt(byte[] plaintext, byte[] key)
        {
            ThrowIfDisposed();

            if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (key.Length != KeySizeBytes)
                throw new ArgumentException($"Key must be {KeySizeBytes} bytes (256 bits)", nameof(key));

            byte[] iv = new byte[IvSizeBytes];
            RandomNumberGenerator.Fill(iv);

            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[TagSizeBytes];

            using var aesGcm = new AesGcm(key, TagSizeBytes);
            aesGcm.Encrypt(iv, plaintext, ciphertext, tag);

            return new AesEncryptionResult(ciphertext, iv, tag);
        }

        /// <inheritdoc />
        public AesEncryptionResult Encrypt(byte[] plaintext, byte[] key, byte[] iv)
        {
            ThrowIfDisposed();

            if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (iv == null) throw new ArgumentNullException(nameof(iv));
            if (key.Length != KeySizeBytes)
                throw new ArgumentException($"Key must be {KeySizeBytes} bytes (256 bits)", nameof(key));
            if (iv.Length != IvSizeBytes)
                throw new ArgumentException($"IV must be {IvSizeBytes} bytes (96 bits)", nameof(iv));

            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[TagSizeBytes];

            using var aesGcm = new AesGcm(key, TagSizeBytes);
            aesGcm.Encrypt(iv, plaintext, ciphertext, tag);

            return new AesEncryptionResult(ciphertext, iv, tag);
        }

        /// <inheritdoc />
        public byte[] Decrypt(string ciphertext, byte[] key, string iv, string authTag)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(ciphertext)) throw new ArgumentNullException(nameof(ciphertext));
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (string.IsNullOrEmpty(iv)) throw new ArgumentNullException(nameof(iv));
            if (string.IsNullOrEmpty(authTag)) throw new ArgumentNullException(nameof(authTag));

            byte[] ciphertextBytes = Base64Url.Decode(ciphertext);
            byte[] ivBytes = Base64Url.Decode(iv);
            byte[] tagBytes = Base64Url.Decode(authTag);

            return Decrypt(ciphertextBytes, key, ivBytes, tagBytes);
        }

        /// <inheritdoc />
        public byte[] Decrypt(byte[] ciphertext, byte[] key, byte[] iv, byte[] authTag)
        {
            ThrowIfDisposed();

            if (ciphertext == null) throw new ArgumentNullException(nameof(ciphertext));
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (iv == null) throw new ArgumentNullException(nameof(iv));
            if (authTag == null) throw new ArgumentNullException(nameof(authTag));

            if (key.Length != KeySizeBytes)
                throw new ArgumentException($"Key must be {KeySizeBytes} bytes (256 bits)", nameof(key));
            if (iv.Length != IvSizeBytes)
                throw new ArgumentException($"IV must be {IvSizeBytes} bytes (96 bits)", nameof(iv));
            if (authTag.Length != TagSizeBytes)
                throw new ArgumentException($"Auth tag must be {TagSizeBytes} bytes (128 bits)", nameof(authTag));

            byte[] plaintext = new byte[ciphertext.Length];

            using var aesGcm = new AesGcm(key, TagSizeBytes);
            aesGcm.Decrypt(iv, ciphertext, authTag, plaintext);

            return plaintext;
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(NativeAesGcmProvider));
        }

        public void Dispose()
        {
            _disposed = true;
        }
    }
}

#endif
