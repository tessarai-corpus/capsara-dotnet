using System;
using System.Collections.Generic;
using System.Net;

namespace Capsara.SDK.Exceptions
{
    /// <summary>Thrown for login, token refresh, and authorization errors.</summary>
    public class CapsaraAuthException : CapsaraException
    {
        /// <summary>Create a CapsaraAuthException with full error details.</summary>
        /// <param name="message">Error message.</param>
        /// <param name="code">Error code from API response.</param>
        /// <param name="statusCode">HTTP status code.</param>
        /// <param name="details">Additional error details.</param>
        /// <param name="responseBody">Raw API response body.</param>
        /// <param name="innerException">Inner exception.</param>
        public CapsaraAuthException(
            string message,
            string code,
            int statusCode,
            IReadOnlyDictionary<string, object>? details = null,
            string? responseBody = null,
            Exception? innerException = null)
            : base(message, code, statusCode, details, responseBody, innerException)
        {
        }

        /// <summary>Refresh token is required but not provided.</summary>
        public static CapsaraAuthException RefreshTokenRequired()
        {
            return new CapsaraAuthException(
                "Refresh token is required",
                "REFRESH_TOKEN_REQUIRED",
                401);
        }

        /// <summary>Invalid credentials (email/password don't match).</summary>
        public static CapsaraAuthException InvalidCredentials()
        {
            return new CapsaraAuthException(
                "Invalid email or password",
                "INVALID_CREDENTIALS",
                401);
        }

        /// <summary>Refresh token is invalid or expired.</summary>
        public static CapsaraAuthException InvalidRefreshToken()
        {
            return new CapsaraAuthException(
                "Refresh token is invalid or expired",
                "INVALID_REFRESH_TOKEN",
                401);
        }

        /// <summary>Access token is invalid or expired.</summary>
        public static CapsaraAuthException Unauthorized(string? message = null)
        {
            return new CapsaraAuthException(
                message ?? "Unauthorized - invalid or expired access token",
                "UNAUTHORIZED",
                401);
        }

        /// <summary>Feature not implemented yet.</summary>
        public static CapsaraAuthException NotImplemented(string feature)
        {
            return new CapsaraAuthException(
                $"{feature} endpoint not yet implemented",
                "NOT_IMPLEMENTED",
                405,
                new Dictionary<string, object> { ["feature"] = feature });
        }

        /// <summary>Invalid request validation error.</summary>
        public static CapsaraAuthException ValidationError(string message, IReadOnlyDictionary<string, object>? details = null)
        {
            return new CapsaraAuthException(
                message,
                "VALIDATION_ERROR",
                400,
                details);
        }

        /// <summary>Maps an HTTP error response to the appropriate factory method.</summary>
        public static new CapsaraAuthException FromHttpResponse(
            HttpStatusCode statusCode,
            string? responseBody,
            Exception? innerException = null)
        {
            var (code, message, details) = ParseErrorResponse(responseBody);

            // Map known error codes to factory methods
            return code switch
            {
                "REFRESH_TOKEN_REQUIRED" => RefreshTokenRequired(),
                "INVALID_CREDENTIALS" => InvalidCredentials(),
                "INVALID_REFRESH_TOKEN" => InvalidRefreshToken(),
                "UNAUTHORIZED" => Unauthorized(message),
                "NOT_IMPLEMENTED" => NotImplemented(details?.ContainsKey("feature") == true
                    ? details["feature"]?.ToString() ?? "Feature"
                    : "Feature"),
                "VALIDATION_ERROR" => ValidationError(message ?? "Validation error", details),
                _ => new CapsaraAuthException(
                    message ?? $"Authentication error: HTTP {(int)statusCode}",
                    code ?? "AUTH_ERROR",
                    (int)statusCode,
                    details,
                    responseBody,
                    innerException)
            };
        }
    }
}
