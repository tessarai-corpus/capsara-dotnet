using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using Capsara.SDK.Internal.Crypto;
using Capsara.SDK.Models;

namespace Capsara.SDK.Internal.Decryptor
{
    /// <summary>Capsa decryption utilities for client-side decryption of API responses.</summary>
    internal static class CapsaDecryptor
    {
        /// <summary>
        /// Decrypt capsa using party's private key
        /// </summary>
        /// <param name="capsa">Encrypted capsa from API</param>
        /// <param name="privateKeyPem">Party's RSA private key in PEM format</param>
        /// <param name="partyId">Party ID (optional - auto-detected from keychain if omitted)</param>
        /// <param name="creatorPublicKeyPem">Creator's RSA public key for signature verification</param>
        /// <param name="verifySignature">Whether to verify signature (default: true)</param>
        /// <returns>Decrypted capsa data</returns>
        public static DecryptedCapsa Decrypt(
            Capsa capsa,
            string privateKeyPem,
            string? partyId = null,
            string? creatorPublicKeyPem = null,
            bool verifySignature = true)
        {
            if (verifySignature)
            {
                if (string.IsNullOrEmpty(creatorPublicKeyPem))
                {
                    throw new InvalidOperationException(
                        "creatorPublicKeyPem is required for signature verification. Pass verifySignature=false to skip (not recommended).");
                }

                VerifySignature(capsa, creatorPublicKeyPem!);
            }

            var keychainEntry = FindKeychainEntry(capsa, partyId);

            if (string.IsNullOrEmpty(keychainEntry.EncryptedKey))
            {
                throw new InvalidOperationException(
                    $"Party {partyId ?? keychainEntry.Party} has no encrypted key in keychain. This party may be a delegated recipient without direct access.");
            }

            var masterKey = RsaProvider.DecryptMasterKey(keychainEntry.EncryptedKey, privateKeyPem);

            // AES-256 requires exactly 32 bytes
            if (masterKey.Length != 32)
            {
                throw new InvalidOperationException(
                    $"Master key size validation failed: expected 32 bytes (AES-256), got {masterKey.Length} bytes.");
            }

            string? subject = null;
            string? body = null;
            Dictionary<string, object>? structured = null;

            var aesProvider = AesGcmProviderFactory.Create();

            if (!string.IsNullOrEmpty(capsa.EncryptedSubject) &&
                !string.IsNullOrEmpty(capsa.SubjectIV) &&
                !string.IsNullOrEmpty(capsa.SubjectAuthTag))
            {
                var subjectBytes = aesProvider.Decrypt(
                    Base64Url.Decode(capsa.EncryptedSubject!),
                    masterKey,
                    Base64Url.Decode(capsa.SubjectIV!),
                    Base64Url.Decode(capsa.SubjectAuthTag!));
                subject = Encoding.UTF8.GetString(subjectBytes);
            }

            if (!string.IsNullOrEmpty(capsa.EncryptedBody) &&
                !string.IsNullOrEmpty(capsa.BodyIV) &&
                !string.IsNullOrEmpty(capsa.BodyAuthTag))
            {
                var bodyBytes = aesProvider.Decrypt(
                    Base64Url.Decode(capsa.EncryptedBody!),
                    masterKey,
                    Base64Url.Decode(capsa.BodyIV!),
                    Base64Url.Decode(capsa.BodyAuthTag!));
                body = Encoding.UTF8.GetString(bodyBytes);
            }

            if (!string.IsNullOrEmpty(capsa.EncryptedStructured) &&
                !string.IsNullOrEmpty(capsa.StructuredIV) &&
                !string.IsNullOrEmpty(capsa.StructuredAuthTag))
            {
                var structuredBytes = aesProvider.Decrypt(
                    Base64Url.Decode(capsa.EncryptedStructured!),
                    masterKey,
                    Base64Url.Decode(capsa.StructuredIV!),
                    Base64Url.Decode(capsa.StructuredAuthTag!));
                var json = Encoding.UTF8.GetString(structuredBytes);
                structured = JsonSerializer.Deserialize<Dictionary<string, object>>(json);
            }

            var decryptedCapsa = new DecryptedCapsa
            {
                Id = capsa.Id,
                Creator = capsa.Creator,
                CreatedAt = capsa.CreatedAt,
                UpdatedAt = capsa.UpdatedAt,
                Status = CapsaStatusExtensions.FromApiString(capsa.Status),
                Subject = subject,
                Body = body,
                Structured = structured,
                Files = capsa.Files,
                AccessControl = capsa.AccessControl,
                Keychain = capsa.Keychain,
                Signature = capsa.Signature,
                Metadata = capsa.Metadata,
                TotalSize = capsa.TotalSize,
                EncryptedCapsa = capsa
            };

            decryptedCapsa.SetMasterKey(masterKey);

            return decryptedCapsa;
        }

        /// <summary>
        /// Decrypt a file from a capsa
        /// </summary>
        /// <param name="encryptedData">Encrypted file data</param>
        /// <param name="masterKey">Decrypted master key</param>
        /// <param name="iv">Initialization vector (base64url)</param>
        /// <param name="authTag">Authentication tag (base64url)</param>
        /// <param name="compressed">Whether file was compressed before encryption</param>
        /// <returns>Decrypted file data</returns>
        public static byte[] DecryptFile(
            byte[] encryptedData,
            byte[] masterKey,
            string iv,
            string authTag,
            bool compressed = false)
        {
            if (string.IsNullOrEmpty(authTag))
            {
                throw new InvalidOperationException(
                    "SECURITY ERROR: authTag is required for file decryption. Missing authTag indicates potential tampering.");
            }

            var aesProvider = AesGcmProviderFactory.Create();
            var decrypted = aesProvider.Decrypt(
                encryptedData,
                masterKey,
                Base64Url.Decode(iv),
                Base64Url.Decode(authTag));

            if (compressed)
            {
                return CompressionProvider.Decompress(decrypted);
            }

            return decrypted;
        }

        /// <summary>
        /// Decrypt filename from capsa
        /// </summary>
        /// <param name="encryptedFilename">Encrypted filename (base64url)</param>
        /// <param name="masterKey">Decrypted master key</param>
        /// <param name="iv">Initialization vector (base64url)</param>
        /// <param name="authTag">Authentication tag (base64url)</param>
        /// <returns>Decrypted filename</returns>
        public static string DecryptFilename(
            string encryptedFilename,
            byte[] masterKey,
            string iv,
            string authTag)
        {
            if (string.IsNullOrEmpty(authTag))
            {
                throw new InvalidOperationException(
                    "SECURITY ERROR: authTag is required for filename decryption. Missing authTag indicates potential tampering.");
            }

            var aesProvider = AesGcmProviderFactory.Create();
            var decrypted = aesProvider.Decrypt(
                Base64Url.Decode(encryptedFilename),
                masterKey,
                Base64Url.Decode(iv),
                Base64Url.Decode(authTag));

            return Encoding.UTF8.GetString(decrypted);
        }

        private static KeychainEntry FindKeychainEntry(Capsa capsa, string? partyId)
        {
            if (partyId != null)
            {
                var entry = capsa.Keychain.Keys.FirstOrDefault(k => k.Party == partyId);
                if (entry != null) return entry;

                var delegateEntry = capsa.Keychain.Keys.FirstOrDefault(
                    k => k.ActingFor != null && k.ActingFor.Contains(partyId));
                if (delegateEntry != null) return delegateEntry;

                throw new InvalidOperationException(
                    $"Party {partyId} not found in capsa keychain. Cannot decrypt.");
            }

            // No partyId - use first keychain entry
            if (capsa.Keychain.Keys.Length == 0)
            {
                throw new InvalidOperationException("No keychain entries found in capsa. Cannot decrypt.");
            }

            return capsa.Keychain.Keys[0];
        }

        private static void VerifySignature(Capsa capsa, string creatorPublicKeyPem)
        {
            if (capsa.Signature == null || string.IsNullOrEmpty(capsa.Signature.Signature))
            {
                throw new InvalidOperationException(
                    $"Capsa signature is missing or invalid (capsa: {capsa.Id}).");
            }

            // Validate signature length (RSA-4096-SHA256 = 512 bytes)
            var signatureBytes = Base64Url.Decode(capsa.Signature.Signature);
            if (signatureBytes.Length != 512)
            {
                throw new InvalidOperationException(
                    $"Signature length validation failed: expected 512 bytes, got {signatureBytes.Length} bytes (capsa: {capsa.Id}).");
            }

            var canonicalString = SignatureProvider.BuildCanonicalString(
                capsa.Id,
                capsa.TotalSize,
                capsa.Keychain.Algorithm,
                capsa.Files.Select(f => new FileHashData(f.FileId, f.Hash, f.Size, f.IV, f.FilenameIV)).ToArray(),
                capsa.StructuredIV,
                capsa.SubjectIV,
                capsa.BodyIV);

            var isValid = SignatureProvider.VerifyJws(
                capsa.Signature.Protected,
                capsa.Signature.Payload,
                capsa.Signature.Signature,
                creatorPublicKeyPem);

            if (!isValid)
            {
                throw new InvalidOperationException(
                    $"Signature verification failed: capsa data does not match signature (capsa: {capsa.Id}).");
            }
        }
    }
}
