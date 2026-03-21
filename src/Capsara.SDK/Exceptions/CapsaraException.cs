using System;
using System.Collections.Generic;
using System.Net;
using System.Text.Json;

namespace Capsara.SDK.Exceptions
{
    /// <summary>Base exception for all Capsara SDK errors.</summary>
    public class CapsaraException : Exception
    {
        /// <summary>Error code from API response (e.g., "CAPSA_NOT_FOUND", "UNAUTHORIZED").</summary>
        public string Code { get; }

        /// <summary>HTTP status code (0 for client-side errors).</summary>
        public int StatusCode { get; }

        /// <summary>Additional error details from API.</summary>
        public IReadOnlyDictionary<string, object>? Details { get; }

        /// <summary>Raw API response body (for debugging).</summary>
        public string? ResponseBody { get; }

        /// <summary>Create a CapsaraException with full error details.</summary>
        /// <param name="message">Error message.</param>
        /// <param name="code">Error code from API response.</param>
        /// <param name="statusCode">HTTP status code.</param>
        /// <param name="details">Additional error details.</param>
        /// <param name="responseBody">Raw API response body.</param>
        /// <param name="innerException">Inner exception.</param>
        public CapsaraException(
            string message,
            string code,
            int statusCode,
            IReadOnlyDictionary<string, object>? details = null,
            string? responseBody = null,
            Exception? innerException = null)
            : base(message, innerException)
        {
            Code = code;
            StatusCode = statusCode;
            Details = details;
            ResponseBody = responseBody != null && responseBody.Length > 1024
                ? responseBody.Substring(0, 1024) + "...[truncated]"
                : responseBody;
        }

        /// <summary>Create a CapsaraException with a message only.</summary>
        /// <param name="message">Error message.</param>
        public CapsaraException(string message)
            : this(message, "UNKNOWN_ERROR", 0)
        {
        }

        /// <summary>Create a CapsaraException wrapping another exception.</summary>
        /// <param name="message">Error message.</param>
        /// <param name="innerException">Inner exception.</param>
        public CapsaraException(string message, Exception innerException)
            : this(message, "UNKNOWN_ERROR", 0, null, null, innerException)
        {
        }

        /// <summary>Create a CapsaraException from an HTTP error response.</summary>
        /// <param name="statusCode">HTTP status code.</param>
        /// <param name="responseBody">Raw response body.</param>
        /// <param name="innerException">Inner exception.</param>
        public static CapsaraException FromHttpResponse(
            HttpStatusCode statusCode,
            string? responseBody,
            Exception? innerException = null)
        {
            var (code, message, details) = ParseErrorResponse(responseBody);

            return new CapsaraException(
                message ?? $"HTTP {(int)statusCode}: {statusCode}",
                code ?? "HTTP_ERROR",
                (int)statusCode,
                details,
                responseBody,
                innerException);
        }

        /// <summary>Create a CapsaraException for network connectivity failures.</summary>
        /// <param name="innerException">The underlying network exception.</param>
        public static CapsaraException NetworkError(Exception innerException)
        {
            return new CapsaraException(
                "Network error: Unable to reach the API",
                "NETWORK_ERROR",
                0,
                null,
                null,
                innerException);
        }

        /// <summary>Parses a JSON error response body into structured code, message, and details.</summary>
        /// <param name="responseBody">Raw JSON response body, or null.</param>
        /// <returns>Tuple of error code, message, and additional details extracted from the response.</returns>
        protected static (string? Code, string? Message, Dictionary<string, object>? Details) ParseErrorResponse(string? responseBody)
        {
            if (string.IsNullOrEmpty(responseBody))
                return (null, null, null);

            try
            {
                using var doc = JsonDocument.Parse(responseBody!);
                var root = doc.RootElement;

                string? code = null;
                string? message = null;
                Dictionary<string, object>? details = null;

                // Try { error: { code, message, details } } format
                if (root.TryGetProperty("error", out var errorElement))
                {
                    if (errorElement.TryGetProperty("code", out var codeElement))
                        code = codeElement.GetString();
                    if (errorElement.TryGetProperty("message", out var msgElement))
                        message = msgElement.GetString();
                    if (errorElement.TryGetProperty("details", out var detailsElement))
                        details = ParseDetails(detailsElement);
                }

                // Fallback to { message, details } format
                if (message == null && root.TryGetProperty("message", out var topMsgElement))
                    message = topMsgElement.GetString();

                if (details == null && root.TryGetProperty("details", out var topDetailsElement))
                    details = ParseDetails(topDetailsElement);

                return (code, message, details);
            }
            catch (JsonException)
            {
                return (null, null, null);
            }
        }

        private static Dictionary<string, object>? ParseDetails(JsonElement element)
        {
            if (element.ValueKind != JsonValueKind.Object)
                return null;

            var result = new Dictionary<string, object>();
            foreach (var prop in element.EnumerateObject())
            {
                result[prop.Name] = GetJsonValue(prop.Value);
            }
            return result.Count > 0 ? result : null;
        }

        private static object GetJsonValue(JsonElement element)
        {
            return element.ValueKind switch
            {
                JsonValueKind.String => element.GetString()!,
                JsonValueKind.Number => element.TryGetInt64(out var l) ? l : element.GetDouble(),
                JsonValueKind.True => true,
                JsonValueKind.False => false,
                JsonValueKind.Null => null!,
                JsonValueKind.Array => element.ToString(),
                JsonValueKind.Object => element.ToString(),
                _ => element.ToString()
            };
        }
    }
}
