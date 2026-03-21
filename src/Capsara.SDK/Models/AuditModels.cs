using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Capsara.SDK.Models
{
    /// <summary>Constants for audit trail action types.</summary>
    public static class AuditActions
    {
        /// <summary>Capsa was created.</summary>
        public const string Created = "created";

        /// <summary>Capsa was accessed (metadata viewed).</summary>
        public const string Accessed = "accessed";

        /// <summary>File was downloaded from capsa.</summary>
        public const string FileDownloaded = "file_downloaded";

        /// <summary>Capsa was processed by recipient.</summary>
        public const string Processed = "processed";

        /// <summary>Capsa expired.</summary>
        public const string Expired = "expired";

        /// <summary>Capsa was deleted.</summary>
        public const string Deleted = "deleted";

        /// <summary>Custom log entry.</summary>
        public const string Log = "log";
    }

    /// <summary>Single entry in the capsa audit trail.</summary>
    public sealed class AuditEntry
    {
        /// <summary>ISO 8601 timestamp.</summary>
        [JsonPropertyName("timestamp")]
        public string Timestamp { get; set; } = string.Empty;

        /// <summary>Party ID that performed the action.</summary>
        [JsonPropertyName("party")]
        public string Party { get; set; } = string.Empty;

        /// <summary>Audit action type (e.g., "created", "accessed", "file_downloaded").</summary>
        [JsonPropertyName("action")]
        public string Action { get; set; } = string.Empty;

        /// <summary>IP address of the party at time of action, if recorded.</summary>
        [JsonPropertyName("ipAddress")]
        public string? IpAddress { get; set; }

        /// <summary>Device fingerprint of the party at time of action, if recorded.</summary>
        [JsonPropertyName("deviceFingerprint")]
        public string? DeviceFingerprint { get; set; }

        /// <summary>Additional key-value details associated with the audit entry.</summary>
        [JsonPropertyName("details")]
        public Dictionary<string, object>? Details { get; set; }
    }

    /// <summary>Filter parameters for querying audit trail entries.</summary>
    public sealed class GetAuditEntriesFilters
    {
        /// <summary>Filter by audit action type (e.g., "created", "accessed").</summary>
        public string? Action { get; set; }

        /// <summary>Filter by the party ID that performed the action.</summary>
        public string? Party { get; set; }

        /// <summary>Page number for offset-based pagination.</summary>
        public int? Page { get; set; }

        /// <summary>Maximum number of entries per page.</summary>
        public int? Limit { get; set; }
    }

    /// <summary>Only "log" or "processed" allowed via API.</summary>
    public sealed class CreateAuditEntryRequest
    {
        /// <summary>Audit action type ("log" or "processed").</summary>
        [JsonPropertyName("action")]
        public string Action { get; set; } = AuditActions.Log;

        /// <summary>Required for "log", optional for "processed".</summary>
        [JsonPropertyName("details")]
        public Dictionary<string, object>? Details { get; set; }

        /// <summary>Initializes a new instance of <see cref="CreateAuditEntryRequest"/> with action defaulting to "log".</summary>
        public CreateAuditEntryRequest() { }

        /// <summary>Initializes a new instance of <see cref="CreateAuditEntryRequest"/> with the specified action and optional details.</summary>
        /// <param name="action">Audit action type ("log" or "processed").</param>
        /// <param name="details">Additional key-value details for the audit entry.</param>
        public CreateAuditEntryRequest(string action, Dictionary<string, object>? details = null)
        {
            Action = action;
            Details = details;
        }
    }
}
