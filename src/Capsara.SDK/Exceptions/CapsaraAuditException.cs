using System;
using System.Collections.Generic;
using System.Net;

namespace Capsara.SDK.Exceptions
{
    /// <summary>Thrown for audit trail operation errors.</summary>
    public class CapsaraAuditException : CapsaraException
    {
        /// <summary>Create a CapsaraAuditException with full error details.</summary>
        /// <param name="message">Error message.</param>
        /// <param name="code">Error code from API response.</param>
        /// <param name="statusCode">HTTP status code.</param>
        /// <param name="details">Additional error details.</param>
        /// <param name="responseBody">Raw API response body.</param>
        /// <param name="innerException">Inner exception.</param>
        public CapsaraAuditException(
            string message,
            string code,
            int statusCode,
            IReadOnlyDictionary<string, object>? details = null,
            string? responseBody = null,
            Exception? innerException = null)
            : base(message, code, statusCode, details, responseBody, innerException)
        {
        }

        /// <summary>Missing details for 'log' action.</summary>
        public static CapsaraAuditException MissingDetails()
        {
            return new CapsaraAuditException(
                "Audit 'log' action requires details",
                "MISSING_DETAILS",
                400);
        }

        /// <summary>Invalid action type.</summary>
        public static CapsaraAuditException InvalidAction(string action)
        {
            return new CapsaraAuditException(
                $"Invalid audit action: {action}. Only 'log' and 'processed' are allowed.",
                "INVALID_ACTION",
                400,
                new Dictionary<string, object> { ["action"] = action });
        }

        /// <summary>Maps an HTTP error response to the appropriate factory method.</summary>
        public static new CapsaraAuditException FromHttpResponse(
            HttpStatusCode statusCode,
            string? responseBody,
            Exception? innerException = null)
        {
            var (code, message, details) = ParseErrorResponse(responseBody);

            return code switch
            {
                "MISSING_DETAILS" => MissingDetails(),
                "INVALID_ACTION" => InvalidAction(
                    details?.ContainsKey("action") == true
                        ? details["action"]?.ToString() ?? "unknown"
                        : "unknown"),
                _ => new CapsaraAuditException(
                    message ?? $"Audit error: HTTP {(int)statusCode}",
                    code ?? "AUDIT_ERROR",
                    (int)statusCode,
                    details,
                    responseBody,
                    innerException)
            };
        }
    }
}
