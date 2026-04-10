using System;
using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Capsara.SDK.Internal.Crypto
{
    /// <summary>
    /// Thread-safe cache for parsed RSA public key parameters.
    /// Avoids repeated PEM parsing. Keys are cached by fingerprint.
    /// </summary>
    internal sealed class RsaKeyCache : IDisposable
    {
        private readonly ConcurrentDictionary<string, CachedRsaKey> _cache = new();
        private readonly TimeSpan _ttl;
        private bool _disposed;

        /// <summary>
        /// Default cache instance for global use.
        /// </summary>
        public static RsaKeyCache Default { get; } = new RsaKeyCache(TimeSpan.FromMinutes(30));

        /// <summary>
        /// Create a new RSA key cache.
        /// </summary>
        /// <param name="ttl">Time-to-live for cache entries. Default is 30 minutes.</param>
        public RsaKeyCache(TimeSpan? ttl = null)
        {
            _ttl = ttl ?? TimeSpan.FromMinutes(30);
        }

        /// <summary>
        /// Get or create cached RSA parameters for a public key.
        /// </summary>
        /// <param name="publicKeyPem">PEM-encoded public key</param>
        /// <param name="fingerprint">Key fingerprint (used as cache key)</param>
        /// <returns>Cached RSA parameters</returns>
        public RSAParameters GetOrAdd(string publicKeyPem, string fingerprint)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(RsaKeyCache));

            // Try to get existing entry
            if (_cache.TryGetValue(fingerprint, out var existing))
            {
                if (!IsExpired(existing))
                {
                    return existing.Parameters;
                }
                // Entry expired, remove it
                _cache.TryRemove(fingerprint, out _);
            }

            // Parse and cache the key
            using var rsa = RSA.Create();
            PemHelper.ImportPublicKey(rsa, publicKeyPem);
            var parameters = rsa.ExportParameters(includePrivateParameters: false);

            var entry = new CachedRsaKey
            {
                Parameters = parameters,
                CachedAt = DateTimeOffset.UtcNow
            };

            _cache.TryAdd(fingerprint, entry);
            return parameters;
        }

        /// <summary>
        /// Get cached RSA parameters if available and not expired.
        /// </summary>
        /// <param name="fingerprint">Key fingerprint</param>
        /// <returns>RSA parameters or null if not cached/expired</returns>
        public RSAParameters? TryGet(string fingerprint)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(RsaKeyCache));

            if (_cache.TryGetValue(fingerprint, out var existing))
            {
                if (!IsExpired(existing))
                {
                    return existing.Parameters;
                }
                _cache.TryRemove(fingerprint, out _);
            }

            return null;
        }

        /// <summary>
        /// Encrypt master key using cached RSA parameters for performance.
        /// Falls back to standard encryption if fingerprint not provided.
        /// </summary>
        /// <param name="masterKey">32-byte AES-256 master key</param>
        /// <param name="publicKeyPem">PEM-encoded RSA public key</param>
        /// <param name="fingerprint">Optional key fingerprint for caching</param>
        /// <returns>Base64url-encoded encrypted key</returns>
        public string EncryptMasterKey(byte[] masterKey, string publicKeyPem, string? fingerprint)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(RsaKeyCache));

            if (masterKey == null) throw new ArgumentNullException(nameof(masterKey));
            if (string.IsNullOrEmpty(publicKeyPem)) throw new ArgumentNullException(nameof(publicKeyPem));
            if (masterKey.Length != 32)
                throw new ArgumentException("Master key must be 32 bytes (AES-256)", nameof(masterKey));

            // If no fingerprint provided, use non-cached path
            if (string.IsNullOrEmpty(fingerprint))
            {
                return RsaProvider.EncryptMasterKey(masterKey, publicKeyPem);
            }

            // Get or parse the key parameters
            var parameters = GetOrAdd(publicKeyPem, fingerprint!);

            // Create RSA instance with cached parameters
            using var rsa = RSA.Create();
            rsa.ImportParameters(parameters);

            if (rsa.KeySize < 4096)
                throw new CryptographicException(
                    $"RSA key size too small: expected at least 4096 bits, got {rsa.KeySize} bits");

#if NET6_0_OR_GREATER
            byte[] encrypted = rsa.Encrypt(masterKey, RSAEncryptionPadding.OaepSHA256);
#else
            byte[] encrypted = EncryptWithBouncyCastle(masterKey, parameters);
#endif

            if (encrypted.Length != 512)
                throw new CryptographicException(
                    $"Unexpected encrypted key size: expected 512 bytes, got {encrypted.Length}");

            return Base64Url.Encode(encrypted);
        }

#if NETFRAMEWORK
        private static byte[] EncryptWithBouncyCastle(byte[] data, RSAParameters parameters)
        {
            var publicKey = new Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters(
                isPrivate: false,
                modulus: new Org.BouncyCastle.Math.BigInteger(1, parameters.Modulus),
                exponent: new Org.BouncyCastle.Math.BigInteger(1, parameters.Exponent)
            );

            var cipher = new Org.BouncyCastle.Crypto.Encodings.OaepEncoding(
                new Org.BouncyCastle.Crypto.Engines.RsaEngine(),
                new Org.BouncyCastle.Crypto.Digests.Sha256Digest(),
                new Org.BouncyCastle.Crypto.Digests.Sha256Digest(),
                null
            );

            cipher.Init(forEncryption: true, publicKey);
            return cipher.ProcessBlock(data, 0, data.Length);
        }
#endif

        /// <summary>
        /// Clear all cached entries.
        /// </summary>
        public void Clear()
        {
            _cache.Clear();
        }

        /// <summary>
        /// Get the number of cached entries.
        /// </summary>
        public int Count => _cache.Count;

        private bool IsExpired(CachedRsaKey entry)
        {
            return DateTimeOffset.UtcNow - entry.CachedAt > _ttl;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _cache.Clear();
        }

        private sealed class CachedRsaKey
        {
            public RSAParameters Parameters { get; set; }
            public DateTimeOffset CachedAt { get; set; }
        }
    }
}
