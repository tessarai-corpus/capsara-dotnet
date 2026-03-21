using System;
using System.Collections.Generic;
using System.Net;

namespace Capsara.SDK.Exceptions
{
    /// <summary>Thrown for capsa operations (create, get, delete, file operations).</summary>
    public class CapsaraCapsaException : CapsaraException
    {
        /// <summary>Create a CapsaraCapsaException with full error details.</summary>
        /// <param name="message">Error message.</param>
        /// <param name="code">Error code from API response.</param>
        /// <param name="statusCode">HTTP status code.</param>
        /// <param name="details">Additional error details.</param>
        /// <param name="responseBody">Raw API response body.</param>
        /// <param name="innerException">Inner exception.</param>
        public CapsaraCapsaException(
            string message,
            string code,
            int statusCode,
            IReadOnlyDictionary<string, object>? details = null,
            string? responseBody = null,
            Exception? innerException = null)
            : base(message, code, statusCode, details, responseBody, innerException)
        {
        }

        /// <summary>Capsa not found or access denied.</summary>
        public static CapsaraCapsaException CapsaNotFound(string? capsaId = null)
        {
            var message = capsaId != null
                ? $"Capsa with ID {capsaId} not found or access denied"
                : "Capsa not found or access denied";

            var details = capsaId != null
                ? new Dictionary<string, object> { ["capsaId"] = capsaId }
                : null;

            return new CapsaraCapsaException(message, "CAPSA_NOT_FOUND", 404, details);
        }

        /// <summary>File not found in capsa.</summary>
        public static CapsaraCapsaException FileNotFound(string? fileId = null)
        {
            var details = fileId != null
                ? new Dictionary<string, object> { ["fileId"] = fileId }
                : null;

            return new CapsaraCapsaException("File not found in capsa", "FILE_NOT_FOUND", 404, details);
        }

        /// <summary>Access denied to capsa.</summary>
        public static CapsaraCapsaException AccessDenied(IReadOnlyDictionary<string, object>? details = null)
        {
            return new CapsaraCapsaException(
                "You do not have access to this capsa",
                "ACCESS_DENIED",
                403,
                details);
        }

        /// <summary>Authenticated party doesn't match creator in metadata.</summary>
        public static CapsaraCapsaException CreatorMismatch(string authenticated, string claimed)
        {
            return new CapsaraCapsaException(
                "Authenticated party does not match creator in metadata",
                "CREATOR_MISMATCH",
                403,
                new Dictionary<string, object>
                {
                    ["authenticated"] = authenticated,
                    ["claimed"] = claimed
                });
        }

        /// <summary>Capsa is deleted and cannot be accessed.</summary>
        public static CapsaraCapsaException CapsaDeleted(IReadOnlyDictionary<string, object>? details = null)
        {
            return new CapsaraCapsaException(
                "Cannot download files from deleted capsa",
                "CAPSA_DELETED",
                403,
                details);
        }

        /// <summary>Invalid content type - must be multipart/form-data.</summary>
        public static CapsaraCapsaException InvalidContentType()
        {
            return new CapsaraCapsaException(
                "Request must be multipart/form-data with metadata and capsa_0..N fields",
                "INVALID_CONTENT_TYPE",
                400);
        }

        /// <summary>Missing required parameters.</summary>
        public static CapsaraCapsaException MissingParams(params string[] parameters)
        {
            var message = parameters.Length > 0
                ? $"Missing required parameters: {string.Join(", ", parameters)}"
                : "Missing required parameters";

            var details = parameters.Length > 0
                ? new Dictionary<string, object> { ["missingParams"] = parameters }
                : null;

            return new CapsaraCapsaException(message, "MISSING_PARAMS", 400, details);
        }

        /// <summary>Missing capsa ID.</summary>
        public static CapsaraCapsaException MissingId()
        {
            return new CapsaraCapsaException("Capsa ID is required", "MISSING_ID", 400);
        }

        /// <summary>Invalid expiration time for download URL.</summary>
        public static CapsaraCapsaException InvalidExpiration()
        {
            return new CapsaraCapsaException(
                "URL expiration must be between 1 and 1440 minutes (24 hours)",
                "INVALID_EXPIRATION",
                400);
        }

        /// <summary>Multipart upload error.</summary>
        public static CapsaraCapsaException MultipartError(
            string message,
            int statusCode = 400,
            IReadOnlyDictionary<string, object>? details = null)
        {
            return new CapsaraCapsaException(message, "MULTIPART_ERROR", statusCode, details);
        }

        /// <summary>File download failed.</summary>
        public static CapsaraCapsaException DownloadFailed(
            string capsaId,
            string fileId,
            Exception? cause = null)
        {
            var message = cause != null
                ? $"Failed to download file {fileId} from capsa {capsaId}: {cause.Message}"
                : $"Failed to download file {fileId} from capsa {capsaId}";

            return new CapsaraCapsaException(
                message,
                "DOWNLOAD_FAILED",
                0, // Status 0 indicates client-side error
                new Dictionary<string, object>
                {
                    ["capsaId"] = capsaId,
                    ["fileId"] = fileId
                },
                null,
                cause);
        }

        /// <summary>Maps an HTTP error response to the appropriate factory method.</summary>
        public static new CapsaraCapsaException FromHttpResponse(
            HttpStatusCode statusCode,
            string? responseBody,
            Exception? innerException = null)
        {
            var (code, message, details) = ParseErrorResponse(responseBody);

            // Map known error codes (support both ENVELOPE_* and CAPSA_* for API compatibility)
            return code switch
            {
                "ENVELOPE_NOT_FOUND" or "CAPSA_NOT_FOUND" =>
                    CapsaNotFound(details?.ContainsKey("capsaId") == true
                        ? details["capsaId"]?.ToString()
                        : details?.ContainsKey("envelopeId") == true
                            ? details["envelopeId"]?.ToString()
                            : null),

                "FILE_NOT_FOUND" =>
                    FileNotFound(details?.ContainsKey("fileId") == true
                        ? details["fileId"]?.ToString()
                        : null),

                "ACCESS_DENIED" => AccessDenied(details),

                "CREATOR_MISMATCH" =>
                    CreatorMismatch(
                        details?.ContainsKey("authenticated") == true
                            ? details["authenticated"]?.ToString() ?? ""
                            : "",
                        details?.ContainsKey("claimed") == true
                            ? details["claimed"]?.ToString() ?? ""
                            : ""),

                "ENVELOPE_DELETED" or "CAPSA_DELETED" => CapsaDeleted(details),

                "INVALID_CONTENT_TYPE" => InvalidContentType(),

                "MISSING_PARAMS" when details?.ContainsKey("missingParams") == true =>
                    MissingParams(details["missingParams"]?.ToString()?.Split(',') ?? Array.Empty<string>()),

                "MISSING_PARAMS" => MissingParams(),

                "MISSING_ID" => MissingId(),

                "INVALID_EXPIRATION" => InvalidExpiration(),

                "MULTIPART_ERROR" =>
                    MultipartError(message ?? "Multipart error", (int)statusCode, details),

                _ => new CapsaraCapsaException(
                    message ?? $"Capsa error: HTTP {(int)statusCode}",
                    code ?? "CAPSA_ERROR",
                    (int)statusCode,
                    details,
                    responseBody,
                    innerException)
            };
        }
    }
}
