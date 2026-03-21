using System;
using System.Security.Cryptography;
using System.Text;
#if NETFRAMEWORK
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
#endif

namespace Capsara.SDK.Internal.Crypto
{
    /// <summary>
    /// RSA-4096-OAEP-SHA256 master key encryption/decryption and key pair generation.
    /// </summary>
    internal sealed class RsaProvider : IDisposable
    {
        private const int MinKeySize = 4096;
        private const int ExpectedEncryptedKeySize = 512; // RSA-4096 output size
        private const int MasterKeySize = 32; // AES-256 key size

        private bool _disposed;

        /// <summary>
        /// Generate an RSA-4096 key pair.
        /// </summary>
        public GeneratedKeyPairResult GenerateKeyPairInstance()
        {
            ThrowIfDisposed();

            using var rsa = RSA.Create(MinKeySize);

            string publicKeyPem = PemHelper.ExportPublicKeyPem(rsa);
            string privateKeyPem = PemHelper.ExportPrivateKeyPem(rsa);
            string fingerprint = ComputeFingerprint(publicKeyPem);

            return new GeneratedKeyPairResult(
                publicKey: publicKeyPem,
                privateKey: privateKeyPem,
                fingerprint: fingerprint,
                keySize: MinKeySize
            );
        }

        /// <summary>
        /// Encrypt a master key with RSA-4096-OAEP-SHA256.
        /// </summary>
        /// <returns>Base64url-encoded encrypted key (512 bytes)</returns>
        public static string EncryptMasterKey(byte[] masterKey, string publicKeyPem)
        {
            if (masterKey == null) throw new ArgumentNullException(nameof(masterKey));
            if (string.IsNullOrEmpty(publicKeyPem)) throw new ArgumentNullException(nameof(publicKeyPem));
            if (masterKey.Length != MasterKeySize)
                throw new ArgumentException($"Master key must be {MasterKeySize} bytes (AES-256)", nameof(masterKey));

            using var rsa = RSA.Create();
            PemHelper.ImportPublicKey(rsa, publicKeyPem);
            ValidateKeySize(rsa);

#if NET6_0_OR_GREATER
            byte[] encrypted = rsa.Encrypt(masterKey, RSAEncryptionPadding.OaepSHA256);
#else
            byte[] encrypted = EncryptOaepSha256BouncyCastle(masterKey, rsa);
#endif

            if (encrypted.Length != ExpectedEncryptedKeySize)
                throw new CryptographicException(
                    $"Unexpected encrypted key size: expected {ExpectedEncryptedKeySize} bytes, got {encrypted.Length}");

            return Base64Url.Encode(encrypted);
        }

        /// <summary>
        /// Decrypt a master key with RSA-4096-OAEP-SHA256.
        /// </summary>
        /// <returns>32-byte AES-256 master key</returns>
        public static byte[] DecryptMasterKey(string encryptedKey, string privateKeyPem)
        {
            if (string.IsNullOrEmpty(encryptedKey)) throw new ArgumentNullException(nameof(encryptedKey));
            if (string.IsNullOrEmpty(privateKeyPem)) throw new ArgumentNullException(nameof(privateKeyPem));

            byte[] encrypted = Base64Url.Decode(encryptedKey);

            if (encrypted.Length != ExpectedEncryptedKeySize)
                throw new ArgumentException(
                    $"Encrypted key must be {ExpectedEncryptedKeySize} bytes (RSA-4096)", nameof(encryptedKey));

            using var rsa = RSA.Create();
            PemHelper.ImportPrivateKey(rsa, privateKeyPem);
            ValidateKeySize(rsa);

#if NET6_0_OR_GREATER
            byte[] decrypted = rsa.Decrypt(encrypted, RSAEncryptionPadding.OaepSHA256);
#else
            byte[] decrypted = DecryptOaepSha256BouncyCastle(encrypted, rsa);
#endif

            if (decrypted.Length != MasterKeySize)
                throw new CryptographicException(
                    $"Decrypted master key has unexpected size: expected {MasterKeySize} bytes, got {decrypted.Length}");

            return decrypted;
        }

        /// <summary>
        /// Compute SHA-256 fingerprint of a public key. Returns lowercase hex.
        /// </summary>
        public static string ComputeFingerprint(string publicKeyPem)
        {
            if (string.IsNullOrEmpty(publicKeyPem))
                throw new ArgumentNullException(nameof(publicKeyPem));

            using var rsa = RSA.Create();
            PemHelper.ImportPublicKey(rsa, publicKeyPem);

            byte[] derBytes = PemHelper.ExportSubjectPublicKeyInfo(rsa);

            using var sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(derBytes);

            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        /// <summary>
        /// Validate that an RSA key meets minimum size requirements (4096 bits).
        /// </summary>
        public static bool ValidateKeySize(string publicKeyPem)
        {
            if (string.IsNullOrEmpty(publicKeyPem)) return false;

            try
            {
                using var rsa = RSA.Create();
                PemHelper.ImportPublicKey(rsa, publicKeyPem);
                return rsa.KeySize >= MinKeySize;
            }
            catch
            {
                return false;
            }
        }

#if NETFRAMEWORK
        /// <summary>RSA-OAEP-SHA256 encrypt via BouncyCastle (.NET Framework 4.8 fallback).</summary>
        private static byte[] EncryptOaepSha256BouncyCastle(byte[] data, RSA rsa)
        {
            var parameters = rsa.ExportParameters(includePrivateParameters: false);

            var publicKey = new RsaKeyParameters(
                isPrivate: false,
                modulus: new BigInteger(1, parameters.Modulus),
                exponent: new BigInteger(1, parameters.Exponent)
            );

            var cipher = new OaepEncoding(
                new RsaEngine(),
                new Sha256Digest(),
                new Sha256Digest(),
                null // No label
            );

            cipher.Init(forEncryption: true, publicKey);
            return cipher.ProcessBlock(data, 0, data.Length);
        }

        /// <summary>RSA-OAEP-SHA256 decrypt via BouncyCastle (.NET Framework 4.8 fallback).</summary>
        private static byte[] DecryptOaepSha256BouncyCastle(byte[] data, RSA rsa)
        {
            var parameters = rsa.ExportParameters(includePrivateParameters: true);

            var privateKey = new RsaPrivateCrtKeyParameters(
                modulus: new BigInteger(1, parameters.Modulus),
                publicExponent: new BigInteger(1, parameters.Exponent),
                privateExponent: new BigInteger(1, parameters.D),
                p: new BigInteger(1, parameters.P),
                q: new BigInteger(1, parameters.Q),
                dP: new BigInteger(1, parameters.DP),
                dQ: new BigInteger(1, parameters.DQ),
                qInv: new BigInteger(1, parameters.InverseQ)
            );

            var cipher = new OaepEncoding(
                new RsaEngine(),
                new Sha256Digest(),
                new Sha256Digest(),
                null // No label
            );

            cipher.Init(forEncryption: false, privateKey);
            return cipher.ProcessBlock(data, 0, data.Length);
        }
#endif

        private static void ValidateKeySize(RSA rsa)
        {
            if (rsa.KeySize < MinKeySize)
                throw new CryptographicException(
                    $"RSA key size too small: expected at least {MinKeySize} bits, got {rsa.KeySize} bits");
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(RsaProvider));
        }

        /// <summary>Disposes the RSA provider and marks it as disposed.</summary>
        public void Dispose()
        {
            _disposed = true;
        }
    }

    /// <summary>
    /// Result of RSA key pair generation.
    /// </summary>
    public sealed class GeneratedKeyPairResult
    {
        /// <summary>PEM-encoded RSA public key (SPKI format).</summary>
        public string PublicKey { get; }

        /// <summary>PEM-encoded RSA private key (PKCS#8 format).</summary>
        public string PrivateKey { get; }

        /// <summary>SHA-256 fingerprint of the public key (lowercase hex).</summary>
        public string Fingerprint { get; }

        /// <summary>RSA key size in bits.</summary>
        public int KeySize { get; }
        /// <summary>Algorithm identifier (RSA-4096).</summary>
        public string Algorithm => "RSA-4096";
        /// <summary>RSA public exponent (65537).</summary>
        public int PublicExponent => 65537;
        /// <summary>Initializes a new instance of the <see cref="GeneratedKeyPairResult"/> class.</summary>
        /// <param name="publicKey">PEM-encoded public key.</param>
        /// <param name="privateKey">PEM-encoded private key.</param>
        /// <param name="fingerprint">SHA-256 fingerprint of the public key.</param>
        /// <param name="keySize">RSA key size in bits.</param>
        public GeneratedKeyPairResult(string publicKey, string privateKey, string fingerprint, int keySize)
        {
            PublicKey = publicKey;
            PrivateKey = privateKey;
            Fingerprint = fingerprint;
            KeySize = keySize;
        }
    }
}
