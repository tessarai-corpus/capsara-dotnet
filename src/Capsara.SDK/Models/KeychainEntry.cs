using System.Text.Json.Serialization;

namespace Capsara.SDK.Models
{
    /// <summary>Single entry in a capsa keychain, holding an encrypted master key copy for one party.</summary>
    public sealed class KeychainEntry
    {
        /// <summary>Party ID this keychain entry belongs to.</summary>
        [JsonPropertyName("party")]
        public string Party { get; set; } = string.Empty;

        /// <summary>Base64url-encoded.</summary>
        [JsonPropertyName("encryptedKey")]
        public string EncryptedKey { get; set; } = string.Empty;

        /// <summary>Base64url-encoded.</summary>
        [JsonPropertyName("iv")]
        public string IV { get; set; } = string.Empty;

        /// <summary>SHA-256 hex.</summary>
        [JsonPropertyName("fingerprint")]
        public string Fingerprint { get; set; } = string.Empty;

        /// <summary>Permissions granted to this party (e.g., "read", "delegate").</summary>
        [JsonPropertyName("permissions")]
        public string[] Permissions { get; set; } = System.Array.Empty<string>();

        /// <summary>Party IDs this delegate acts for (null if not a delegate).</summary>
        [JsonPropertyName("actingFor")]
        public string[]? ActingFor { get; set; }

        /// <summary>Whether this party's access has been revoked.</summary>
        [JsonPropertyName("revoked")]
        public bool? Revoked { get; set; }
    }
}
