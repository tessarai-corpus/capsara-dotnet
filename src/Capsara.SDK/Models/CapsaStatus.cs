namespace Capsara.SDK.Models
{
    /// <summary>Lifecycle states for a capsa.</summary>
    public enum CapsaStatus
    {
        /// <summary>Active capsa lifecycle state.</summary>
        Active,

        /// <summary>Soft-deleted capsa, billable until billing cycle ends.</summary>
        SoftDeleted,

        /// <summary>Expired capsa, past its expiration date.</summary>
        Expired
    }

    /// <summary>Extension methods for converting between <see cref="CapsaStatus"/> and API string values.</summary>
    public static class CapsaStatusExtensions
    {
        /// <summary>Converts a <see cref="CapsaStatus"/> enum value to its API string representation.</summary>
        /// <param name="status">The status to convert.</param>
        /// <returns>API string such as "active", "soft_deleted", or "expired".</returns>
        public static string ToApiString(this CapsaStatus status)
        {
            return status switch
            {
                CapsaStatus.Active => "active",
                CapsaStatus.SoftDeleted => "soft_deleted",
                CapsaStatus.Expired => "expired",
                _ => "active"
            };
        }

        /// <summary>Parses an API status string into a <see cref="CapsaStatus"/> enum value.</summary>
        /// <param name="value">API string such as "active", "soft_deleted", or "expired". Defaults to <see cref="CapsaStatus.Active"/> if null or unrecognized.</param>
        /// <returns>The corresponding <see cref="CapsaStatus"/> value.</returns>
        public static CapsaStatus FromApiString(string? value)
        {
            return value?.ToLowerInvariant() switch
            {
                "active" => CapsaStatus.Active,
                "soft_deleted" => CapsaStatus.SoftDeleted,
                "expired" => CapsaStatus.Expired,
                _ => CapsaStatus.Active
            };
        }
    }
}
