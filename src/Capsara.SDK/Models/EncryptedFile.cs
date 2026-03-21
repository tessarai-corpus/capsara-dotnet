using System.Text.Json.Serialization;

namespace Capsara.SDK.Models
{
    /// <summary>Matches API response.</summary>
    public sealed class EncryptedFile
    {
        /// <summary>Server-assigned unique identifier for the file.</summary>
        [JsonPropertyName("fileId")]
        public string FileId { get; set; } = string.Empty;

        /// <summary>Base64url.</summary>
        [JsonPropertyName("encryptedFilename")]
        public string EncryptedFilename { get; set; } = string.Empty;

        /// <summary>Base64url.</summary>
        [JsonPropertyName("filenameIV")]
        public string FilenameIV { get; set; } = string.Empty;

        /// <summary>Base64url.</summary>
        [JsonPropertyName("filenameAuthTag")]
        public string FilenameAuthTag { get; set; } = string.Empty;

        /// <summary>Base64url.</summary>
        [JsonPropertyName("iv")]
        public string IV { get; set; } = string.Empty;

        /// <summary>Base64url.</summary>
        [JsonPropertyName("authTag")]
        public string AuthTag { get; set; } = string.Empty;

        /// <summary>MIME type of the original unencrypted file.</summary>
        [JsonPropertyName("mimetype")]
        public string Mimetype { get; set; } = string.Empty;

        /// <summary>Size of the encrypted file in bytes.</summary>
        [JsonPropertyName("size")]
        public long Size { get; set; }

        /// <summary>SHA-256 hex.</summary>
        [JsonPropertyName("hash")]
        public string Hash { get; set; } = string.Empty;

        /// <summary>Hash algorithm used for file integrity (e.g., "sha256").</summary>
        [JsonPropertyName("hashAlgorithm")]
        public string HashAlgorithm { get; set; } = "sha256";

        /// <summary>ISO 8601 UTC.</summary>
        [JsonPropertyName("expiresAt")]
        public string? ExpiresAt { get; set; }

        /// <summary>Whether the file was compressed before encryption.</summary>
        [JsonPropertyName("compressed")]
        public bool? Compressed { get; set; }

        /// <summary>Compression algorithm used (e.g., "gzip"), if compressed.</summary>
        [JsonPropertyName("compressionAlgorithm")]
        public string? CompressionAlgorithm { get; set; }

        /// <summary>Original uncompressed file size in bytes, if compressed.</summary>
        [JsonPropertyName("originalSize")]
        public long? OriginalSize { get; set; }

        /// <summary>One-way transform reference (URL or @partyId/id).</summary>
        [JsonPropertyName("transform")]
        public string? Transform { get; set; }
    }
}
