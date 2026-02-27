using System.Text.Json.Serialization;

namespace Capsara.SDK.Models
{
    /// <summary>
    /// Unencrypted metadata visible to server.
    /// Only non-sensitive operational data for routing, display, and search.
    /// </summary>
    public sealed class CapsaMetadata
    {
        /// <summary>Human-readable label for display and search.</summary>
        [JsonPropertyName("label")]
        public string? Label { get; set; }

        /// <summary>IDs of related capsas for cross-referencing.</summary>
        [JsonPropertyName("relatedPackages")]
        public string[]? RelatedPackages { get; set; }

        /// <summary>Arbitrary string tags for categorization and filtering.</summary>
        [JsonPropertyName("tags")]
        public string[]? Tags { get; set; }

        /// <summary>Free-form notes visible to all parties (unencrypted).</summary>
        [JsonPropertyName("notes")]
        public string? Notes { get; set; }
    }
}
