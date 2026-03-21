using System;
using Capsara.SDK.Models;

namespace Capsara.SDK.Builder
{
    /// <summary>
    /// Capsa metadata ready for upload to the API.
    /// </summary>
    public sealed class CapsaUploadData
    {
        /// <summary>Unique package identifier.</summary>
        public string PackageId { get; set; } = string.Empty;

        /// <summary>Keychain containing encrypted master keys for all parties.</summary>
        public CapsaKeychain Keychain { get; set; } = new();

        /// <summary>Digital signature for authenticity verification.</summary>
        public CapsaSignature Signature { get; set; } = new();

        /// <summary>Access control settings for the capsa.</summary>
        public CapsaAccessControl AccessControl { get; set; } = new();

        /// <summary>Delivery priority (normal, high, urgent).</summary>
        public string DeliveryPriority { get; set; } = "normal";

        /// <summary>Array of encrypted file metadata.</summary>
        public EncryptedFile[] Files { get; set; } = Array.Empty<EncryptedFile>();

        /// <summary>Optional capsa metadata.</summary>
        public CapsaMetadata? Metadata { get; set; }

        /// <summary>Base64url-encoded encrypted subject.</summary>
        public string? EncryptedSubject { get; set; }

        /// <summary>Base64url-encoded IV for subject encryption.</summary>
        public string? SubjectIV { get; set; }

        /// <summary>Base64url-encoded authentication tag for subject.</summary>
        public string? SubjectAuthTag { get; set; }

        /// <summary>Base64url-encoded encrypted body.</summary>
        public string? EncryptedBody { get; set; }

        /// <summary>Base64url-encoded IV for body encryption.</summary>
        public string? BodyIV { get; set; }

        /// <summary>Base64url-encoded authentication tag for body.</summary>
        public string? BodyAuthTag { get; set; }

        /// <summary>Base64url-encoded encrypted structured data.</summary>
        public string? EncryptedStructured { get; set; }

        /// <summary>Base64url-encoded IV for structured data encryption.</summary>
        public string? StructuredIV { get; set; }

        /// <summary>Base64url-encoded authentication tag for structured data.</summary>
        public string? StructuredAuthTag { get; set; }
    }

    /// <summary>
    /// Encrypted file with data ready for upload.
    /// </summary>
    public sealed class EncryptedFileData
    {
        /// <summary>File metadata including encryption parameters.</summary>
        public EncryptedFile Metadata { get; set; } = new();

        /// <summary>Encrypted file content as bytes.</summary>
        public byte[] Data { get; set; } = Array.Empty<byte>();
    }

    /// <summary>
    /// Built capsa ready for upload to the API.
    /// </summary>
    public sealed class BuiltCapsa
    {
        /// <summary>Capsa metadata for API upload.</summary>
        public CapsaUploadData Capsa { get; set; } = new();

        /// <summary>Array of encrypted files with their data.</summary>
        public EncryptedFileData[] Files { get; set; } = Array.Empty<EncryptedFileData>();
    }
}
