using System;
using System.Text.Json.Serialization;

namespace Capsara.SDK.Models
{
    /// <summary>Keychain containing encrypted master key copies for each authorized party.</summary>
    public sealed class CapsaKeychain
    {
        /// <summary>Key encryption algorithm (e.g., "RSA-OAEP-SHA256").</summary>
        [JsonPropertyName("algorithm")]
        public string Algorithm { get; set; } = "RSA-OAEP-SHA256";

        /// <summary>Array of keychain entries, one per authorized party.</summary>
        [JsonPropertyName("keys")]
        public KeychainEntry[] Keys { get; set; } = Array.Empty<KeychainEntry>();
    }

    /// <summary>Access control settings for a capsa.</summary>
    public sealed class CapsaAccessControl
    {
        /// <summary>ISO 8601.</summary>
        [JsonPropertyName("expiresAt")]
        public string? ExpiresAt { get; set; }
    }

    /// <summary>Matches API GET /capsas/:id response.</summary>
    public sealed class Capsa
    {
        /// <summary>Unique identifier for the capsa.</summary>
        [JsonPropertyName("id")]
        public string Id { get; set; } = string.Empty;

        /// <summary>ISO 8601.</summary>
        [JsonPropertyName("createdAt")]
        public string CreatedAt { get; set; } = string.Empty;

        /// <summary>ISO 8601.</summary>
        [JsonPropertyName("updatedAt")]
        public string UpdatedAt { get; set; } = string.Empty;

        /// <summary>Lifecycle status as an API string (e.g., "active", "soft_deleted", "expired").</summary>
        [JsonPropertyName("status")]
        public string Status { get; set; } = "active";

        /// <summary>Party ID of the capsa creator.</summary>
        [JsonPropertyName("creator")]
        public string Creator { get; set; } = string.Empty;

        /// <summary>Digital signature proving creator authenticity.</summary>
        [JsonPropertyName("signature")]
        public CapsaSignature Signature { get; set; } = new();

        /// <summary>Keychain with encrypted master key copies for each authorized party.</summary>
        [JsonPropertyName("keychain")]
        public CapsaKeychain Keychain { get; set; } = new();

        /// <summary>Array of encrypted file records in this capsa.</summary>
        [JsonPropertyName("files")]
        public EncryptedFile[] Files { get; set; } = Array.Empty<EncryptedFile>();

        /// <summary>Base64url.</summary>
        [JsonPropertyName("encryptedStructured")]
        public string? EncryptedStructured { get; set; }

        /// <summary>Base64url initialization vector for structured data encryption.</summary>
        [JsonPropertyName("structuredIV")]
        public string? StructuredIV { get; set; }

        /// <summary>Base64url GCM authentication tag for structured data.</summary>
        [JsonPropertyName("structuredAuthTag")]
        public string? StructuredAuthTag { get; set; }

        /// <summary>Base64url.</summary>
        [JsonPropertyName("encryptedSubject")]
        public string? EncryptedSubject { get; set; }

        /// <summary>Base64url initialization vector for subject encryption.</summary>
        [JsonPropertyName("subjectIV")]
        public string? SubjectIV { get; set; }

        /// <summary>Base64url GCM authentication tag for the subject.</summary>
        [JsonPropertyName("subjectAuthTag")]
        public string? SubjectAuthTag { get; set; }

        /// <summary>Base64url.</summary>
        [JsonPropertyName("encryptedBody")]
        public string? EncryptedBody { get; set; }

        /// <summary>Base64url initialization vector for body encryption.</summary>
        [JsonPropertyName("bodyIV")]
        public string? BodyIV { get; set; }

        /// <summary>Base64url GCM authentication tag for the body.</summary>
        [JsonPropertyName("bodyAuthTag")]
        public string? BodyAuthTag { get; set; }

        /// <summary>Access control settings including expiration.</summary>
        [JsonPropertyName("accessControl")]
        public CapsaAccessControl AccessControl { get; set; } = new();

        /// <summary>Unencrypted metadata (non-sensitive).</summary>
        [JsonPropertyName("metadata")]
        public CapsaMetadata? Metadata { get; set; }

        /// <summary>Total size of all files in the capsa, in bytes.</summary>
        [JsonPropertyName("totalSize")]
        public long TotalSize { get; set; }

        /// <summary>Parsed lifecycle status as a <see cref="CapsaStatus"/> enum value.</summary>
        [JsonIgnore]
        public CapsaStatus StatusEnum => CapsaStatusExtensions.FromApiString(Status);
    }
}
