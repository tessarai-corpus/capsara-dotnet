using System.Text.Json.Serialization;

namespace Capsara.SDK.Models
{
    /// <summary>JWS-style digital signature proving capsa creator authenticity.</summary>
    public sealed class CapsaSignature
    {
        /// <summary>Signature algorithm identifier (e.g., "RS256").</summary>
        [JsonPropertyName("algorithm")]
        public string Algorithm { get; set; } = "RS256";

        /// <summary>Base64url-encoded.</summary>
        [JsonPropertyName("protected")]
        public string Protected { get; set; } = string.Empty;

        /// <summary>Base64url-encoded.</summary>
        [JsonPropertyName("payload")]
        public string Payload { get; set; } = string.Empty;

        /// <summary>Base64url-encoded.</summary>
        [JsonPropertyName("signature")]
        public string Signature { get; set; } = string.Empty;
    }
}
