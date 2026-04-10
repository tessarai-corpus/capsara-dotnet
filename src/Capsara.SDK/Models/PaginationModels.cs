using System.Text.Json.Serialization;

namespace Capsara.SDK.Models
{
    /// <summary>Cursor-based pagination state returned by list endpoints.</summary>
    public sealed class CursorPagination
    {
        /// <summary>Maximum number of items per page.</summary>
        [JsonPropertyName("limit")]
        public int Limit { get; set; }

        /// <summary>Whether additional pages exist beyond the current result set.</summary>
        [JsonPropertyName("hasMore")]
        public bool HasMore { get; set; }

        /// <summary>Opaque cursor for fetching the next page, or null if no next page.</summary>
        [JsonPropertyName("nextCursor")]
        public string? NextCursor { get; set; }

        /// <summary>Opaque cursor for fetching the previous page, or null if no previous page.</summary>
        [JsonPropertyName("prevCursor")]
        public string? PrevCursor { get; set; }
    }

    /// <summary>Lightweight capsa summary for list responses.</summary>
    public sealed class CapsaSummary
    {
        /// <summary>Unique identifier for the capsa.</summary>
        [JsonPropertyName("id")]
        public string Id { get; set; } = string.Empty;

        /// <summary>ISO 8601.</summary>
        [JsonPropertyName("createdAt")]
        public string CreatedAt { get; set; } = string.Empty;

        /// <summary>Party ID of the capsa creator.</summary>
        [JsonPropertyName("creator")]
        public string Creator { get; set; } = string.Empty;

        /// <summary>Lifecycle status of the capsa (e.g., "active", "soft_deleted", "expired").</summary>
        [JsonPropertyName("status")]
        public string Status { get; set; } = "active";

        /// <summary>ISO 8601.</summary>
        [JsonPropertyName("expiresAt")]
        public string? ExpiresAt { get; set; }

        /// <summary>Total size of all files in the capsa, in bytes.</summary>
        [JsonPropertyName("totalSize")]
        public long TotalSize { get; set; }
    }

    /// <summary>Filter and pagination parameters for listing capsas.</summary>
    public sealed class CapsaListFilters
    {
        /// <summary>Filter by lifecycle status.</summary>
        public CapsaStatus? Status { get; set; }

        /// <summary>Filter by creator party ID.</summary>
        public string? CreatedBy { get; set; }

        /// <summary>ISO 8601.</summary>
        public string? StartDate { get; set; }

        /// <summary>ISO 8601.</summary>
        public string? EndDate { get; set; }

        /// <summary>ISO 8601.</summary>
        public string? ExpiringBefore { get; set; }

        /// <summary>Filter to capsas with or without a legal hold.</summary>
        public bool? HasLegalHold { get; set; }

        /// <summary>Maximum number of results per page.</summary>
        public int? Limit { get; set; }

        /// <summary>Cursor for forward pagination (fetch items after this cursor).</summary>
        public string? After { get; set; }

        /// <summary>Cursor for backward pagination (fetch items before this cursor).</summary>
        public string? Before { get; set; }
    }

    /// <summary>Paginated response from the list capsas endpoint.</summary>
    public sealed class CapsaListResponse
    {
        /// <summary>Array of capsa summaries for the current page.</summary>
        [JsonPropertyName("capsas")]
        public CapsaSummary[] Capsas { get; set; } = System.Array.Empty<CapsaSummary>();

        /// <summary>Cursor-based pagination state for traversing results.</summary>
        [JsonPropertyName("pagination")]
        public CursorPagination Pagination { get; set; } = new();
    }

    /// <summary>Paginated response from the audit entries endpoint.</summary>
    public sealed class GetAuditEntriesResponse
    {
        /// <summary>Array of audit entries for the current page.</summary>
        [JsonPropertyName("auditEntries")]
        public AuditEntry[] AuditEntries { get; set; } = System.Array.Empty<AuditEntry>();

        /// <summary>Cursor-based pagination state for traversing results.</summary>
        [JsonPropertyName("pagination")]
        public CursorPagination Pagination { get; set; } = new();
    }
}
