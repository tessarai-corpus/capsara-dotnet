#if NETFRAMEWORK

using System;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Capsara.SDK.Internal.Crypto
{
    /// <summary>
    /// BouncyCastle AES-GCM fallback for .NET Framework 4.8 where native AesGcm is unavailable.
    /// </summary>
    internal sealed class BouncyCastleAesGcmProvider : IAesGcmProvider
    {
        private const int KeySizeBytes = 32;   // 256 bits
        private const int IvSizeBytes = 12;    // 96 bits (GCM standard)
        private const int TagSizeBits = 128;   // 128 bits auth tag
        private const int TagSizeBytes = 16;

        private readonly SecureRandom _secureRandom;
        private bool _disposed;

        public BouncyCastleAesGcmProvider()
        {
            _secureRandom = new SecureRandom();
        }

        /// <inheritdoc />
        public AesEncryptionResult Encrypt(byte[] plaintext, byte[] key)
        {
            ThrowIfDisposed();

            if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (key.Length != KeySizeBytes)
                throw new ArgumentException($"Key must be {KeySizeBytes} bytes (256 bits)", nameof(key));

            byte[] iv = new byte[IvSizeBytes];
            _secureRandom.NextBytes(iv);

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(
                new KeyParameter(key),
                TagSizeBits,
                iv);

            cipher.Init(forEncryption: true, parameters);

            // BouncyCastle appends the auth tag to the ciphertext
            byte[] output = new byte[cipher.GetOutputSize(plaintext.Length)];
            int len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
            cipher.DoFinal(output, len);

            // Output format: [ciphertext][tag] where tag is last 16 bytes
            byte[] ciphertext = new byte[output.Length - TagSizeBytes];
            byte[] tag = new byte[TagSizeBytes];
            Array.Copy(output, 0, ciphertext, 0, ciphertext.Length);
            Array.Copy(output, ciphertext.Length, tag, 0, TagSizeBytes);

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

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(
                new KeyParameter(key),
                TagSizeBits,
                iv);

            cipher.Init(forEncryption: true, parameters);

            // BouncyCastle appends the auth tag to the ciphertext
            byte[] output = new byte[cipher.GetOutputSize(plaintext.Length)];
            int len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
            cipher.DoFinal(output, len);

            byte[] ciphertext = new byte[output.Length - TagSizeBytes];
            byte[] tag = new byte[TagSizeBytes];
            Array.Copy(output, 0, ciphertext, 0, ciphertext.Length);
            Array.Copy(output, ciphertext.Length, tag, 0, TagSizeBytes);

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

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(
                new KeyParameter(key),
                TagSizeBits,
                iv);

            cipher.Init(forEncryption: false, parameters);

            // BouncyCastle expects ciphertext + authTag concatenated for decryption
            byte[] combined = new byte[ciphertext.Length + authTag.Length];
            Array.Copy(ciphertext, 0, combined, 0, ciphertext.Length);
            Array.Copy(authTag, 0, combined, ciphertext.Length, authTag.Length);

            byte[] plaintext = new byte[cipher.GetOutputSize(combined.Length)];
            int len = cipher.ProcessBytes(combined, 0, combined.Length, plaintext, 0);
            cipher.DoFinal(plaintext, len);

            // Trim to actual length (BouncyCastle may over-allocate output buffer)
            if (plaintext.Length != ciphertext.Length)
            {
                byte[] trimmed = new byte[ciphertext.Length];
                Array.Copy(plaintext, 0, trimmed, 0, ciphertext.Length);
                return trimmed;
            }

            return plaintext;
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(BouncyCastleAesGcmProvider));
        }

        public void Dispose()
        {
            _disposed = true;
        }
    }
}

#endif
