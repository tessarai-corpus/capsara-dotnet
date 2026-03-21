using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Capsara.SDK.Models;

namespace Capsara.SDK.Internal.Crypto
{
    /// <summary>File data for signature canonical string.</summary>
    internal sealed class FileHashData
    {
        public string FileId { get; }
        public string Hash { get; }
        public long Size { get; }
        public string IV { get; }
        public string FilenameIV { get; }

        public FileHashData(string fileId, string hash, long size, string iv, string filenameIV)
        {
            FileId = fileId;
            Hash = hash;
            Size = size;
            IV = iv;
            FilenameIV = filenameIV;
        }
    }

    /// <summary>JWS RS256 signature creation and verification.</summary>
    internal sealed class SignatureProvider : IDisposable
    {
        private bool _disposed;

        /// <summary>
        /// Build canonical string for signature.
        /// Format: packageId|version|totalSize|algorithm|hashes...|ivs...|filenameIVs...|structuredIV|subjectIV|bodyIV
        /// </summary>
        public static string BuildCanonicalString(
            string packageId,
            long totalSize,
            string algorithm,
            FileHashData[] files,
            string? structuredIV = null,
            string? subjectIV = null,
            string? bodyIV = null)
        {
            const string version = "1.0.0";
            var parts = new List<string>
            {
                packageId,
                version,
                totalSize.ToString(),
                algorithm
            };

            // Preserve file order - DO NOT SORT (for deterministic signatures)
            if (files.Length > 0)
            {
                foreach (var file in files)
                {
                    parts.Add(file.Hash);
                }
                foreach (var file in files)
                {
                    parts.Add(file.IV);
                }
                foreach (var file in files)
                {
                    parts.Add(file.FilenameIV);
                }
            }

            // Skip empty/undefined optional IVs
            if (!string.IsNullOrEmpty(structuredIV)) parts.Add(structuredIV!);
            if (!string.IsNullOrEmpty(subjectIV)) parts.Add(subjectIV!);
            if (!string.IsNullOrEmpty(bodyIV)) parts.Add(bodyIV!);

            return string.Join("|", parts);
        }

        /// <summary>Create JWS RS256 signature.</summary>
        public static CapsaSignature CreateJws(string canonicalString, string privateKeyPem)
        {
            if (string.IsNullOrEmpty(canonicalString))
                throw new ArgumentNullException(nameof(canonicalString));
            if (string.IsNullOrEmpty(privateKeyPem))
                throw new ArgumentNullException(nameof(privateKeyPem));

            var header = new { alg = "RS256", typ = "JWT" };
            string headerJson = JsonSerializer.Serialize(header);
            string protectedHeader = Base64Url.Encode(Encoding.UTF8.GetBytes(headerJson));
            string payload = Base64Url.Encode(Encoding.UTF8.GetBytes(canonicalString));
            string signingInput = $"{protectedHeader}.{payload}";
            byte[] signingInputBytes = Encoding.UTF8.GetBytes(signingInput);

            using var rsa = RSA.Create();
            PemHelper.ImportPrivateKey(rsa, privateKeyPem);

            byte[] signatureBytes = rsa.SignData(
                signingInputBytes,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            string signature = Base64Url.Encode(signatureBytes);

            return new CapsaSignature
            {
                Algorithm = "RS256",
                Protected = protectedHeader,
                Payload = payload,
                Signature = signature
            };
        }

        /// <summary>Verify JWS RS256 signature.</summary>
        public static bool VerifyJws(string protectedHeader, string payload, string signature, string publicKeyPem)
        {
            if (string.IsNullOrEmpty(protectedHeader)) return false;
            if (string.IsNullOrEmpty(payload)) return false;
            if (string.IsNullOrEmpty(signature)) return false;
            if (string.IsNullOrEmpty(publicKeyPem)) return false;

            try
            {
                string signingInput = $"{protectedHeader}.{payload}";
                byte[] signingInputBytes = Encoding.UTF8.GetBytes(signingInput);
                byte[] signatureBytes = Base64Url.Decode(signature);

                using var rsa = RSA.Create();
                PemHelper.ImportPublicKey(rsa, publicKeyPem);

                return rsa.VerifyData(
                    signingInputBytes,
                    signatureBytes,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>Create a JWS RS256 signature.</summary>
        public JwsSignature CreateSignature(string canonicalString, string privateKeyPem)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(canonicalString))
                throw new ArgumentNullException(nameof(canonicalString));
            if (string.IsNullOrEmpty(privateKeyPem))
                throw new ArgumentNullException(nameof(privateKeyPem));

            var header = new { alg = "RS256", typ = "JWT" };
            string headerJson = JsonSerializer.Serialize(header);
            string protectedHeader = Base64Url.Encode(Encoding.UTF8.GetBytes(headerJson));
            string payload = Base64Url.Encode(Encoding.UTF8.GetBytes(canonicalString));
            string signingInput = $"{protectedHeader}.{payload}";
            byte[] signingInputBytes = Encoding.UTF8.GetBytes(signingInput);

            using var rsa = RSA.Create();
            PemHelper.ImportPrivateKey(rsa, privateKeyPem);

            byte[] signatureBytes = rsa.SignData(
                signingInputBytes,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            string signature = Base64Url.Encode(signatureBytes);

            return new JwsSignature(
                algorithm: "RS256",
                protectedHeader: protectedHeader,
                payload: payload,
                signature: signature
            );
        }

        /// <summary>Verify a JWS RS256 signature against the expected canonical string.</summary>
        public bool VerifySignature(JwsSignature signature, string expectedCanonicalString, string publicKeyPem)
        {
            ThrowIfDisposed();

            if (signature == null) throw new ArgumentNullException(nameof(signature));
            if (string.IsNullOrEmpty(expectedCanonicalString))
                throw new ArgumentNullException(nameof(expectedCanonicalString));
            if (string.IsNullOrEmpty(publicKeyPem))
                throw new ArgumentNullException(nameof(publicKeyPem));

            try
            {
                string expectedPayload = Base64Url.Encode(Encoding.UTF8.GetBytes(expectedCanonicalString));
                if (!ConstantTimeEquals(
                    Encoding.UTF8.GetBytes(expectedPayload),
                    Encoding.UTF8.GetBytes(signature.Payload)))
                {
                    return false;
                }

                string signingInput = $"{signature.ProtectedHeader}.{signature.Payload}";
                byte[] signingInputBytes = Encoding.UTF8.GetBytes(signingInput);
                byte[] signatureBytes = Base64Url.Decode(signature.Signature);

                using var rsa = RSA.Create();
                PemHelper.ImportPublicKey(rsa, publicKeyPem);

                return rsa.VerifyData(
                    signingInputBytes,
                    signatureBytes,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>Constant-time comparison to prevent timing attacks.</summary>
        private static bool ConstantTimeEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;

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

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(SignatureProvider));
        }

        public void Dispose()
        {
            _disposed = true;
        }
    }

    /// <summary>JWS RS256 signature structure.</summary>
    internal sealed class JwsSignature
    {
        public string Algorithm { get; }
        /// <summary>Base64url-encoded.</summary>
        public string ProtectedHeader { get; }
        /// <summary>Base64url-encoded canonical string.</summary>
        public string Payload { get; }
        /// <summary>Base64url-encoded.</summary>
        public string Signature { get; }

        public JwsSignature(string algorithm, string protectedHeader, string payload, string signature)
        {
            Algorithm = algorithm ?? throw new ArgumentNullException(nameof(algorithm));
            ProtectedHeader = protectedHeader ?? throw new ArgumentNullException(nameof(protectedHeader));
            Payload = payload ?? throw new ArgumentNullException(nameof(payload));
            Signature = signature ?? throw new ArgumentNullException(nameof(signature));
        }
    }
}
