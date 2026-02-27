using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Capsara.SDK.Internal.Crypto
{
    /// <summary>
    /// RSA-4096 key pair generation with fingerprint calculation.
    /// </summary>
    internal static class KeyGenerator
    {
        /// <summary>Default key size in bits.</summary>
        public const int DefaultKeySize = 4096;

        /// <summary>Generate an RSA-4096 key pair.</summary>
        public static GeneratedKeyPairResult GenerateKeyPair()
        {
            return GenerateKeyPair(DefaultKeySize);
        }

        /// <summary>
        /// Generate an RSA key pair with specified key size.
        /// </summary>
        /// <param name="keySize">Key size in bits (minimum 2048)</param>
        public static GeneratedKeyPairResult GenerateKeyPair(int keySize)
        {
            if (keySize < 2048)
                throw new ArgumentOutOfRangeException(nameof(keySize), "Key size must be at least 2048 bits");

            using var rsa = RSA.Create(keySize);

            string publicKeyPem = PemHelper.ExportPublicKeyPem(rsa);
            string privateKeyPem = PemHelper.ExportPrivateKeyPem(rsa);
            string fingerprint = CalculateFingerprint(rsa);

            return new GeneratedKeyPairResult(
                publicKey: publicKeyPem,
                privateKey: privateKeyPem,
                fingerprint: fingerprint,
                keySize: keySize
            );
        }

        /// <summary>
        /// Generate an RSA-4096 key pair asynchronously.
        /// Key generation is CPU-intensive, so this runs on a thread pool thread.
        /// </summary>
        public static Task<GeneratedKeyPairResult> GenerateKeyPairAsync(CancellationToken cancellationToken = default)
        {
            return GenerateKeyPairAsync(DefaultKeySize, cancellationToken);
        }

        /// <summary>Generate an RSA key pair asynchronously with specified key size.</summary>
        public static Task<GeneratedKeyPairResult> GenerateKeyPairAsync(int keySize, CancellationToken cancellationToken = default)
        {
            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                return GenerateKeyPair(keySize);
            }, cancellationToken);
        }

        /// <summary>Calculate SHA-256 fingerprint of an RSA public key. Returns lowercase hex (64 characters).</summary>
        private static string CalculateFingerprint(RSA rsa)
        {
            byte[] derBytes = PemHelper.ExportSubjectPublicKeyInfo(rsa);
            return HashProvider.ComputeHash(derBytes);
        }

        /// <summary>Calculate fingerprint from a PEM-encoded public key. Returns lowercase hex (64 characters).</summary>
        public static string CalculateFingerprint(string publicKeyPem)
        {
            if (string.IsNullOrEmpty(publicKeyPem))
                throw new ArgumentNullException(nameof(publicKeyPem));

            using var rsa = RSA.Create();
            PemHelper.ImportPublicKey(rsa, publicKeyPem);
            return CalculateFingerprint(rsa);
        }

        /// <summary>Validate that a public key meets minimum size requirements.</summary>
        public static bool ValidateKeySize(string publicKeyPem, int minimumKeySize = DefaultKeySize)
        {
            if (string.IsNullOrEmpty(publicKeyPem)) return false;

            try
            {
                using var rsa = RSA.Create();
                PemHelper.ImportPublicKey(rsa, publicKeyPem);
                return rsa.KeySize >= minimumKeySize;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>Get the key size of a PEM-encoded public key, or -1 if invalid.</summary>
        public static int GetKeySize(string publicKeyPem)
        {
            if (string.IsNullOrEmpty(publicKeyPem)) return -1;

            try
            {
                using var rsa = RSA.Create();
                PemHelper.ImportPublicKey(rsa, publicKeyPem);
                return rsa.KeySize;
            }
            catch
            {
                return -1;
            }
        }
    }
}
