using System;
using System.Collections.Generic;
using System.Net;
using Capsara.SDK.Exceptions;
using FluentAssertions;
using Xunit;

namespace Capsara.SDK.Tests.Exceptions
{
    /// <summary>
    /// Tests for SDK exception classes and error handling.
    /// </summary>
    public class ExceptionTests
    {
        #region CapsaraException Constructor Tests

        [Fact]
        public void CapsaraException_WithMessage_SetsMessage()
        {
            // Act
            var exception = new CapsaraException("Test error message");

            // Assert
            exception.Message.Should().Be("Test error message");
            exception.Code.Should().Be("UNKNOWN_ERROR");
            exception.StatusCode.Should().Be(0);
        }

        [Fact]
        public void CapsaraException_WithEmptyMessage_SetsEmptyMessage()
        {
            // Act
            var exception = new CapsaraException("");

            // Assert
            exception.Message.Should().Be("");
            exception.Code.Should().Be("UNKNOWN_ERROR");
        }

        [Fact]
        public void CapsaraException_WithSpecialCharacters_PreservesMessage()
        {
            // Act
            var exception = new CapsaraException("Error: <script>alert('xss')</script> & \"quotes\"");

            // Assert
            exception.Message.Should().Be("Error: <script>alert('xss')</script> & \"quotes\"");
        }

        [Fact]
        public void CapsaraException_WithUnicodeMessage_PreservesMessage()
        {
            // Act
            var exception = new CapsaraException("Error: こんにちは 🎉");

            // Assert
            exception.Message.Should().Be("Error: こんにちは 🎉");
        }

        [Fact]
        public void CapsaraException_WithInnerException_SetsInnerException()
        {
            // Arrange
            var innerException = new InvalidOperationException("Inner error");

            // Act
            var exception = new CapsaraException("Outer error", innerException);

            // Assert
            exception.Message.Should().Be("Outer error");
            exception.InnerException.Should().BeSameAs(innerException);
            exception.Code.Should().Be("UNKNOWN_ERROR");
        }

        [Fact]
        public void CapsaraException_WithNullInnerException_SetsNullInnerException()
        {
            // Act
            var exception = new CapsaraException("Error", "CODE", 500, null, null, null);

            // Assert
            exception.InnerException.Should().BeNull();
        }

        [Fact]
        public void CapsaraException_WithFullDetails_SetsAllProperties()
        {
            // Arrange
            var details = new Dictionary<string, object> { ["key"] = "value" };

            // Act
            var exception = new CapsaraException(
                "Error message",
                "ERROR_CODE",
                500,
                details,
                "{\"error\": \"raw response\"}");

            // Assert
            exception.Message.Should().Be("Error message");
            exception.Code.Should().Be("ERROR_CODE");
            exception.StatusCode.Should().Be(500);
            exception.Details.Should().NotBeNull();
            exception.Details!["key"].Should().Be("value");
            exception.ResponseBody.Should().Be("{\"error\": \"raw response\"}");
        }

        [Fact]
        public void CapsaraException_WithNullDetails_SetsNullDetails()
        {
            // Act
            var exception = new CapsaraException("Error", "CODE", 500);

            // Assert
            exception.Details.Should().BeNull();
        }

        [Fact]
        public void CapsaraException_WithEmptyDetails_SetsEmptyDetails()
        {
            // Act
            var exception = new CapsaraException("Error", "CODE", 500, new Dictionary<string, object>());

            // Assert
            exception.Details.Should().NotBeNull();
            exception.Details.Should().BeEmpty();
        }

        [Fact]
        public void CapsaraException_WithMultipleDetails_SetsAllDetails()
        {
            // Arrange
            var details = new Dictionary<string, object>
            {
                ["string"] = "value",
                ["number"] = 42,
                ["boolean"] = true,
                ["nested"] = "nested value"
            };

            // Act
            var exception = new CapsaraException("Error", "CODE", 500, details);

            // Assert
            exception.Details.Should().HaveCount(4);
            exception.Details!["string"].Should().Be("value");
            exception.Details["number"].Should().Be(42);
            exception.Details["boolean"].Should().Be(true);
        }

        [Theory]
        [InlineData(200)]
        [InlineData(400)]
        [InlineData(401)]
        [InlineData(403)]
        [InlineData(404)]
        [InlineData(500)]
        [InlineData(503)]
        public void CapsaraException_WithVariousStatusCodes_SetsStatusCode(int statusCode)
        {
            // Act
            var exception = new CapsaraException("Error", "CODE", statusCode);

            // Assert
            exception.StatusCode.Should().Be(statusCode);
        }

        [Fact]
        public void CapsaraException_WithZeroStatusCode_SetsZero()
        {
            // Act
            var exception = new CapsaraException("Error", "CODE", 0);

            // Assert
            exception.StatusCode.Should().Be(0);
        }

        [Fact]
        public void CapsaraException_WithNegativeStatusCode_SetsNegative()
        {
            // Act
            var exception = new CapsaraException("Error", "CODE", -1);

            // Assert
            exception.StatusCode.Should().Be(-1);
        }

        #endregion

        #region CapsaraException FromHttpResponse Tests

        [Fact]
        public void FromHttpResponse_ParsesErrorResponse()
        {
            // Arrange
            var responseBody = "{\"error\": {\"code\": \"TEST_ERROR\", \"message\": \"Test message\"}}";

            // Act
            var exception = CapsaraException.FromHttpResponse(HttpStatusCode.BadRequest, responseBody);

            // Assert
            exception.Code.Should().Be("TEST_ERROR");
            exception.Message.Should().Be("Test message");
            exception.StatusCode.Should().Be(400);
        }

        [Fact]
        public void FromHttpResponse_WithDetails_ParsesDetails()
        {
            // Arrange
            var responseBody = "{\"error\": {\"code\": \"TEST_ERROR\", \"message\": \"Test\", \"details\": {\"field\": \"value\"}}}";

            // Act
            var exception = CapsaraException.FromHttpResponse(HttpStatusCode.BadRequest, responseBody);

            // Assert
            exception.Details.Should().NotBeNull();
            exception.Details!.ContainsKey("field").Should().BeTrue();
        }

        [Fact]
        public void FromHttpResponse_InvalidJson_UsesDefaultMessage()
        {
            // Arrange
            var responseBody = "not valid json";

            // Act
            var exception = CapsaraException.FromHttpResponse(HttpStatusCode.InternalServerError, responseBody);

            // Assert
            exception.Code.Should().Be("HTTP_ERROR");
            exception.Message.Should().Contain("500");
        }

        [Fact]
        public void FromHttpResponse_NullResponseBody_UsesDefaultMessage()
        {
            // Act
            var exception = CapsaraException.FromHttpResponse(HttpStatusCode.NotFound, null);

            // Assert
            exception.Code.Should().Be("HTTP_ERROR");
            exception.Message.Should().Contain("404");
        }

        [Fact]
        public void NetworkError_CreatesNetworkException()
        {
            // Arrange
            var innerException = new System.Net.Http.HttpRequestException("Connection refused");

            // Act
            var exception = CapsaraException.NetworkError(innerException);

            // Assert
            exception.Code.Should().Be("NETWORK_ERROR");
            exception.Message.Should().Contain("Network error");
            exception.InnerException.Should().BeSameAs(innerException);
        }

        [Fact]
        public void FromHttpResponse_WithEmptyResponseBody_UsesDefaultMessage()
        {
            // Act
            var exception = CapsaraException.FromHttpResponse(HttpStatusCode.BadRequest, "");

            // Assert
            exception.Code.Should().Be("HTTP_ERROR");
            exception.Message.Should().Contain("400");
        }

        [Fact]
        public void FromHttpResponse_WithWhitespaceResponseBody_UsesDefaultMessage()
        {
            // Act
            var exception = CapsaraException.FromHttpResponse(HttpStatusCode.BadRequest, "   ");

            // Assert
            exception.Code.Should().Be("HTTP_ERROR");
        }

        [Fact]
        public void FromHttpResponse_WithHtmlResponse_UsesDefaultMessage()
        {
            // Arrange - sometimes servers return HTML error pages
            var responseBody = "<html><body>Internal Server Error</body></html>";

            // Act
            var exception = CapsaraException.FromHttpResponse(HttpStatusCode.InternalServerError, responseBody);

            // Assert
            exception.Code.Should().Be("HTTP_ERROR");
            exception.ResponseBody.Should().Be(responseBody);
        }

        [Fact]
        public void FromHttpResponse_WithPartialJson_UsesDefaultMessage()
        {
            // Arrange - malformed JSON
            var responseBody = "{\"error\": {\"code\": \"TEST\"";

            // Act
            var exception = CapsaraException.FromHttpResponse(HttpStatusCode.BadRequest, responseBody);

            // Assert
            exception.Code.Should().Be("HTTP_ERROR");
        }

        [Fact]
        public void FromHttpResponse_WithTopLevelMessage_ExtractsMessage()
        {
            // Arrange - alternative format { message: "..." }
            var responseBody = "{\"message\": \"Top level message\"}";

            // Act
            var exception = CapsaraException.FromHttpResponse(HttpStatusCode.BadRequest, responseBody);

            // Assert
            exception.Message.Should().Be("Top level message");
        }

        [Fact]
        public void FromHttpResponse_WithTopLevelDetails_ExtractsDetails()
        {
            // Arrange - alternative format { details: {...} }
            var responseBody = "{\"message\": \"Error\", \"details\": {\"field\": \"email\"}}";

            // Act
            var exception = CapsaraException.FromHttpResponse(HttpStatusCode.BadRequest, responseBody);

            // Assert
            exception.Details.Should().NotBeNull();
            exception.Details!.ContainsKey("field").Should().BeTrue();
        }

        [Fact]
        public void FromHttpResponse_WithNestedErrorFormat_ParsesCorrectly()
        {
            // Arrange
            var responseBody = "{\"error\": {\"code\": \"NESTED_ERROR\", \"message\": \"Nested message\", \"details\": {\"nested\": true}}}";

            // Act
            var exception = CapsaraException.FromHttpResponse(HttpStatusCode.BadRequest, responseBody);

            // Assert
            exception.Code.Should().Be("NESTED_ERROR");
            exception.Message.Should().Be("Nested message");
            exception.Details.Should().ContainKey("nested");
        }

        [Theory]
        [InlineData(HttpStatusCode.BadRequest, 400)]
        [InlineData(HttpStatusCode.Unauthorized, 401)]
        [InlineData(HttpStatusCode.Forbidden, 403)]
        [InlineData(HttpStatusCode.NotFound, 404)]
        [InlineData(HttpStatusCode.MethodNotAllowed, 405)]
        [InlineData(HttpStatusCode.Conflict, 409)]
        [InlineData((HttpStatusCode)422, 422)] // UnprocessableEntity - not in .NET 4.8
        [InlineData((HttpStatusCode)429, 429)] // TooManyRequests - not in .NET 4.8
        [InlineData(HttpStatusCode.InternalServerError, 500)]
        [InlineData(HttpStatusCode.BadGateway, 502)]
        [InlineData(HttpStatusCode.ServiceUnavailable, 503)]
        [InlineData(HttpStatusCode.GatewayTimeout, 504)]
        public void FromHttpResponse_WithVariousStatusCodes_MapsStatusCode(HttpStatusCode httpStatus, int expectedCode)
        {
            // Act
            var exception = CapsaraException.FromHttpResponse(httpStatus, null);

            // Assert
            exception.StatusCode.Should().Be(expectedCode);
        }

        [Fact]
        public void FromHttpResponse_WithInnerException_SetsInnerException()
        {
            // Arrange
            var inner = new InvalidOperationException("Original error");
            var responseBody = "{\"error\": {\"code\": \"TEST\", \"message\": \"Test\"}}";

            // Act
            var exception = CapsaraException.FromHttpResponse(HttpStatusCode.BadRequest, responseBody, inner);

            // Assert
            exception.InnerException.Should().BeSameAs(inner);
        }

        #endregion

        #region CapsaraException NetworkError Tests

        [Fact]
        public void NetworkError_WithHttpRequestException_CreatesNetworkException()
        {
            // Arrange
            var innerException = new System.Net.Http.HttpRequestException("Connection refused");

            // Act
            var exception = CapsaraException.NetworkError(innerException);

            // Assert
            exception.Code.Should().Be("NETWORK_ERROR");
            exception.Message.Should().Contain("Network error");
            exception.InnerException.Should().BeSameAs(innerException);
            exception.StatusCode.Should().Be(0);
        }

        [Fact]
        public void NetworkError_WithTimeoutException_CreatesNetworkException()
        {
            // Arrange
            var innerException = new TimeoutException("Request timed out");

            // Act
            var exception = CapsaraException.NetworkError(innerException);

            // Assert
            exception.Code.Should().Be("NETWORK_ERROR");
            exception.InnerException.Should().BeSameAs(innerException);
        }

        [Fact]
        public void NetworkError_PreservesInnerExceptionMessage()
        {
            // Arrange
            var innerException = new System.Net.Http.HttpRequestException("DNS resolution failed");

            // Act
            var exception = CapsaraException.NetworkError(innerException);

            // Assert
            exception.InnerException!.Message.Should().Contain("DNS resolution failed");
        }

        #endregion

        #region CapsaraAuthException Factory Method Tests

        [Fact]
        public void InvalidCredentials_ReturnsCorrectException()
        {
            // Act
            var exception = CapsaraAuthException.InvalidCredentials();

            // Assert
            exception.Code.Should().Be("INVALID_CREDENTIALS");
            exception.StatusCode.Should().Be(401);
            exception.Message.Should().Contain("Invalid email or password");
        }

        [Fact]
        public void RefreshTokenRequired_ReturnsCorrectException()
        {
            // Act
            var exception = CapsaraAuthException.RefreshTokenRequired();

            // Assert
            exception.Code.Should().Be("REFRESH_TOKEN_REQUIRED");
            exception.StatusCode.Should().Be(401);
        }

        [Fact]
        public void InvalidRefreshToken_ReturnsCorrectException()
        {
            // Act
            var exception = CapsaraAuthException.InvalidRefreshToken();

            // Assert
            exception.Code.Should().Be("INVALID_REFRESH_TOKEN");
            exception.StatusCode.Should().Be(401);
        }

        [Fact]
        public void Unauthorized_ReturnsCorrectException()
        {
            // Act
            var exception = CapsaraAuthException.Unauthorized();

            // Assert
            exception.Code.Should().Be("UNAUTHORIZED");
            exception.StatusCode.Should().Be(401);
        }

        [Fact]
        public void Unauthorized_WithCustomMessage_UsesMessage()
        {
            // Act
            var exception = CapsaraAuthException.Unauthorized("Custom unauthorized message");

            // Assert
            exception.Message.Should().Be("Custom unauthorized message");
        }

        [Fact]
        public void NotImplemented_ReturnsCorrectException()
        {
            // Act
            var exception = CapsaraAuthException.NotImplemented("MFA");

            // Assert
            exception.Code.Should().Be("NOT_IMPLEMENTED");
            exception.StatusCode.Should().Be(405);
            exception.Message.Should().Contain("MFA");
            exception.Details.Should().ContainKey("feature");
        }

        [Fact]
        public void ValidationError_ReturnsCorrectException()
        {
            // Arrange
            var details = new Dictionary<string, object> { ["field"] = "email" };

            // Act
            var exception = CapsaraAuthException.ValidationError("Invalid email format", details);

            // Assert
            exception.Code.Should().Be("VALIDATION_ERROR");
            exception.StatusCode.Should().Be(400);
            exception.Details.Should().ContainKey("field");
        }

        [Fact]
        public void AuthException_FromHttpResponse_MapsKnownCodes()
        {
            // Arrange
            var responseBody = "{\"error\": {\"code\": \"INVALID_CREDENTIALS\", \"message\": \"Bad login\"}}";

            // Act
            var exception = CapsaraAuthException.FromHttpResponse(HttpStatusCode.Unauthorized, responseBody);

            // Assert
            exception.Code.Should().Be("INVALID_CREDENTIALS");
        }

        [Fact]
        public void AuthException_FromHttpResponse_MapsRefreshTokenRequired()
        {
            // Arrange
            var responseBody = "{\"error\": {\"code\": \"REFRESH_TOKEN_REQUIRED\", \"message\": \"Token needed\"}}";

            // Act
            var exception = CapsaraAuthException.FromHttpResponse(HttpStatusCode.Unauthorized, responseBody);

            // Assert
            exception.Code.Should().Be("REFRESH_TOKEN_REQUIRED");
        }

        [Fact]
        public void AuthException_FromHttpResponse_MapsInvalidRefreshToken()
        {
            // Arrange
            var responseBody = "{\"error\": {\"code\": \"INVALID_REFRESH_TOKEN\", \"message\": \"Token invalid\"}}";

            // Act
            var exception = CapsaraAuthException.FromHttpResponse(HttpStatusCode.Unauthorized, responseBody);

            // Assert
            exception.Code.Should().Be("INVALID_REFRESH_TOKEN");
        }

        [Fact]
        public void AuthException_FromHttpResponse_MapsUnauthorized()
        {
            // Arrange
            var responseBody = "{\"error\": {\"code\": \"UNAUTHORIZED\", \"message\": \"Access denied\"}}";

            // Act
            var exception = CapsaraAuthException.FromHttpResponse(HttpStatusCode.Unauthorized, responseBody);

            // Assert
            exception.Code.Should().Be("UNAUTHORIZED");
            exception.Message.Should().Be("Access denied");
        }

        [Fact]
        public void AuthException_FromHttpResponse_MapsNotImplemented()
        {
            // Arrange
            var responseBody = "{\"error\": {\"code\": \"NOT_IMPLEMENTED\", \"message\": \"Not supported\", \"details\": {\"feature\": \"MFA\"}}}";

            // Act
            var exception = CapsaraAuthException.FromHttpResponse(HttpStatusCode.MethodNotAllowed, responseBody);

            // Assert
            exception.Code.Should().Be("NOT_IMPLEMENTED");
            exception.Message.Should().Contain("MFA");
        }

        [Fact]
        public void AuthException_FromHttpResponse_MapsValidationError()
        {
            // Arrange
            var responseBody = "{\"error\": {\"code\": \"VALIDATION_ERROR\", \"message\": \"Invalid format\", \"details\": {\"field\": \"email\"}}}";

            // Act
            var exception = CapsaraAuthException.FromHttpResponse(HttpStatusCode.BadRequest, responseBody);

            // Assert
            exception.Code.Should().Be("VALIDATION_ERROR");
        }

        [Fact]
        public void AuthException_FromHttpResponse_UnknownCode_UsesGenericAuth()
        {
            // Arrange
            var responseBody = "{\"error\": {\"code\": \"UNKNOWN_AUTH_ERROR\", \"message\": \"Something happened\"}}";

            // Act
            var exception = CapsaraAuthException.FromHttpResponse(HttpStatusCode.Unauthorized, responseBody);

            // Assert
            exception.Code.Should().Be("UNKNOWN_AUTH_ERROR");
            exception.Message.Should().Be("Something happened");
        }

        [Fact]
        public void AuthException_FromHttpResponse_NullBody_UsesDefault()
        {
            // Act
            var exception = CapsaraAuthException.FromHttpResponse(HttpStatusCode.Unauthorized, null);

            // Assert
            exception.Code.Should().Be("AUTH_ERROR");
            exception.StatusCode.Should().Be(401);
        }

        [Fact]
        public void AuthException_FromHttpResponse_InvalidJson_UsesDefault()
        {
            // Act
            var exception = CapsaraAuthException.FromHttpResponse(HttpStatusCode.Unauthorized, "not json");

            // Assert
            exception.Code.Should().Be("AUTH_ERROR");
        }

        [Fact]
        public void NotImplemented_WithEmptyFeature_StillWorks()
        {
            // Act
            var exception = CapsaraAuthException.NotImplemented("");

            // Assert
            exception.Code.Should().Be("NOT_IMPLEMENTED");
            exception.Details.Should().ContainKey("feature");
            exception.Details!["feature"].Should().Be("");
        }

        [Fact]
        public void ValidationError_WithNullDetails_SetsNullDetails()
        {
            // Act
            var exception = CapsaraAuthException.ValidationError("Invalid input");

            // Assert
            exception.Code.Should().Be("VALIDATION_ERROR");
            exception.Message.Should().Be("Invalid input");
            exception.Details.Should().BeNull();
        }

        [Fact]
        public void ValidationError_WithEmptyMessage_SetsEmptyMessage()
        {
            // Act
            var exception = CapsaraAuthException.ValidationError("");

            // Assert
            exception.Message.Should().Be("");
        }

        #endregion

        #region CapsaraCapsaException Factory Method Tests

        [Fact]
        public void CapsaNotFound_WithId_ReturnsCorrectException()
        {
            // Act
            var exception = CapsaraCapsaException.CapsaNotFound("pkg_123");

            // Assert
            exception.Code.Should().Be("CAPSA_NOT_FOUND");
            exception.StatusCode.Should().Be(404);
            exception.Message.Should().Contain("pkg_123");
            exception.Details.Should().ContainKey("capsaId");
        }

        [Fact]
        public void CapsaNotFound_WithoutId_ReturnsCorrectException()
        {
            // Act
            var exception = CapsaraCapsaException.CapsaNotFound();

            // Assert
            exception.Code.Should().Be("CAPSA_NOT_FOUND");
            exception.StatusCode.Should().Be(404);
        }

        [Fact]
        public void FileNotFound_WithId_ReturnsCorrectException()
        {
            // Act
            var exception = CapsaraCapsaException.FileNotFound("file_456");

            // Assert
            exception.Code.Should().Be("FILE_NOT_FOUND");
            exception.StatusCode.Should().Be(404);
            exception.Details.Should().ContainKey("fileId");
        }

        [Fact]
        public void AccessDenied_ReturnsCorrectException()
        {
            // Act
            var exception = CapsaraCapsaException.AccessDenied();

            // Assert
            exception.Code.Should().Be("ACCESS_DENIED");
            exception.StatusCode.Should().Be(403);
        }

        [Fact]
        public void CreatorMismatch_ReturnsCorrectException()
        {
            // Act
            var exception = CapsaraCapsaException.CreatorMismatch("party_actual", "party_claimed");

            // Assert
            exception.Code.Should().Be("CREATOR_MISMATCH");
            exception.StatusCode.Should().Be(403);
            exception.Details.Should().ContainKey("authenticated");
            exception.Details.Should().ContainKey("claimed");
        }

        [Fact]
        public void CapsaDeleted_ReturnsCorrectException()
        {
            // Act
            var exception = CapsaraCapsaException.CapsaDeleted();

            // Assert
            exception.Code.Should().Be("CAPSA_DELETED");
            exception.StatusCode.Should().Be(403);
        }

        [Fact]
        public void InvalidContentType_ReturnsCorrectException()
        {
            // Act
            var exception = CapsaraCapsaException.InvalidContentType();

            // Assert
            exception.Code.Should().Be("INVALID_CONTENT_TYPE");
            exception.StatusCode.Should().Be(400);
        }

        [Fact]
        public void MissingParams_WithParams_ReturnsCorrectException()
        {
            // Act
            var exception = CapsaraCapsaException.MissingParams("fileId", "capsaId");

            // Assert
            exception.Code.Should().Be("MISSING_PARAMS");
            exception.StatusCode.Should().Be(400);
            exception.Message.Should().Contain("fileId");
            exception.Message.Should().Contain("capsaId");
        }

        [Fact]
        public void MissingId_ReturnsCorrectException()
        {
            // Act
            var exception = CapsaraCapsaException.MissingId();

            // Assert
            exception.Code.Should().Be("MISSING_ID");
            exception.StatusCode.Should().Be(400);
        }

        [Fact]
        public void InvalidExpiration_ReturnsCorrectException()
        {
            // Act
            var exception = CapsaraCapsaException.InvalidExpiration();

            // Assert
            exception.Code.Should().Be("INVALID_EXPIRATION");
            exception.StatusCode.Should().Be(400);
        }

        [Fact]
        public void MultipartError_ReturnsCorrectException()
        {
            // Act
            var exception = CapsaraCapsaException.MultipartError("Invalid boundary");

            // Assert
            exception.Code.Should().Be("MULTIPART_ERROR");
            exception.Message.Should().Be("Invalid boundary");
        }

        [Fact]
        public void DownloadFailed_ReturnsCorrectException()
        {
            // Arrange
            var innerException = new Exception("Storage error");

            // Act
            var exception = CapsaraCapsaException.DownloadFailed("pkg_123", "file_456", innerException);

            // Assert
            exception.Code.Should().Be("DOWNLOAD_FAILED");
            exception.StatusCode.Should().Be(0);
            exception.Details.Should().ContainKey("capsaId");
            exception.Details.Should().ContainKey("fileId");
            exception.InnerException.Should().BeSameAs(innerException);
        }

        [Fact]
        public void CapsaException_FromHttpResponse_MapsEnvelopeCodes()
        {
            // Arrange - API might return ENVELOPE_NOT_FOUND for backwards compatibility
            var responseBody = "{\"error\": {\"code\": \"ENVELOPE_NOT_FOUND\", \"message\": \"Not found\"}}";

            // Act
            var exception = CapsaraCapsaException.FromHttpResponse(HttpStatusCode.NotFound, responseBody);

            // Assert - Should map to CAPSA_NOT_FOUND
            exception.Code.Should().Be("CAPSA_NOT_FOUND");
        }

        [Fact]
        public void CapsaException_FromHttpResponse_MapsFileNotFound()
        {
            // Arrange
            var responseBody = "{\"error\": {\"code\": \"FILE_NOT_FOUND\", \"message\": \"File missing\", \"details\": {\"fileId\": \"f_123\"}}}";

            // Act
            var exception = CapsaraCapsaException.FromHttpResponse(HttpStatusCode.NotFound, responseBody);

            // Assert
            exception.Code.Should().Be("FILE_NOT_FOUND");
        }

        [Fact]
        public void CapsaException_FromHttpResponse_MapsAccessDenied()
        {
            // Arrange
            var responseBody = "{\"error\": {\"code\": \"ACCESS_DENIED\", \"message\": \"No access\"}}";

            // Act
            var exception = CapsaraCapsaException.FromHttpResponse(HttpStatusCode.Forbidden, responseBody);

            // Assert
            exception.Code.Should().Be("ACCESS_DENIED");
        }

        [Fact]
        public void CapsaException_FromHttpResponse_MapsCreatorMismatch()
        {
            // Arrange
            var responseBody = "{\"error\": {\"code\": \"CREATOR_MISMATCH\", \"message\": \"Wrong creator\", \"details\": {\"authenticated\": \"party_a\", \"claimed\": \"party_b\"}}}";

            // Act
            var exception = CapsaraCapsaException.FromHttpResponse(HttpStatusCode.Forbidden, responseBody);

            // Assert
            exception.Code.Should().Be("CREATOR_MISMATCH");
        }

        [Fact]
        public void CapsaException_FromHttpResponse_MapsCapsaDeleted()
        {
            // Arrange
            var responseBody = "{\"error\": {\"code\": \"CAPSA_DELETED\", \"message\": \"Deleted\"}}";

            // Act
            var exception = CapsaraCapsaException.FromHttpResponse(HttpStatusCode.Forbidden, responseBody);

            // Assert
            exception.Code.Should().Be("CAPSA_DELETED");
        }

        [Fact]
        public void CapsaException_FromHttpResponse_MapsEnvelopeDeleted()
        {
            // Arrange - backwards compatibility
            var responseBody = "{\"error\": {\"code\": \"ENVELOPE_DELETED\", \"message\": \"Deleted\"}}";

            // Act
            var exception = CapsaraCapsaException.FromHttpResponse(HttpStatusCode.Forbidden, responseBody);

            // Assert
            exception.Code.Should().Be("CAPSA_DELETED");
        }

        [Fact]
        public void CapsaException_FromHttpResponse_MapsInvalidContentType()
        {
            // Arrange
            var responseBody = "{\"error\": {\"code\": \"INVALID_CONTENT_TYPE\", \"message\": \"Wrong type\"}}";

            // Act
            var exception = CapsaraCapsaException.FromHttpResponse(HttpStatusCode.BadRequest, responseBody);

            // Assert
            exception.Code.Should().Be("INVALID_CONTENT_TYPE");
        }

        [Fact]
        public void CapsaException_FromHttpResponse_MapsMissingParams()
        {
            // Arrange
            var responseBody = "{\"error\": {\"code\": \"MISSING_PARAMS\", \"message\": \"Missing required\"}}";

            // Act
            var exception = CapsaraCapsaException.FromHttpResponse(HttpStatusCode.BadRequest, responseBody);

            // Assert
            exception.Code.Should().Be("MISSING_PARAMS");
        }

        [Fact]
        public void CapsaException_FromHttpResponse_MapsMissingId()
        {
            // Arrange
            var responseBody = "{\"error\": {\"code\": \"MISSING_ID\", \"message\": \"No ID\"}}";

            // Act
            var exception = CapsaraCapsaException.FromHttpResponse(HttpStatusCode.BadRequest, responseBody);

            // Assert
            exception.Code.Should().Be("MISSING_ID");
        }

        [Fact]
        public void CapsaException_FromHttpResponse_MapsInvalidExpiration()
        {
            // Arrange
            var responseBody = "{\"error\": {\"code\": \"INVALID_EXPIRATION\", \"message\": \"Bad expiration\"}}";

            // Act
            var exception = CapsaraCapsaException.FromHttpResponse(HttpStatusCode.BadRequest, responseBody);

            // Assert
            exception.Code.Should().Be("INVALID_EXPIRATION");
        }

        [Fact]
        public void CapsaException_FromHttpResponse_MapsMultipartError()
        {
            // Arrange
            var responseBody = "{\"error\": {\"code\": \"MULTIPART_ERROR\", \"message\": \"Upload failed\"}}";

            // Act
            var exception = CapsaraCapsaException.FromHttpResponse(HttpStatusCode.BadRequest, responseBody);

            // Assert
            exception.Code.Should().Be("MULTIPART_ERROR");
            exception.Message.Should().Be("Upload failed");
        }

        [Fact]
        public void CapsaException_FromHttpResponse_UnknownCode_UsesGenericCapsa()
        {
            // Arrange
            var responseBody = "{\"error\": {\"code\": \"UNKNOWN_CAPSA_ERROR\", \"message\": \"Something happened\"}}";

            // Act
            var exception = CapsaraCapsaException.FromHttpResponse(HttpStatusCode.BadRequest, responseBody);

            // Assert
            exception.Code.Should().Be("UNKNOWN_CAPSA_ERROR");
            exception.Message.Should().Be("Something happened");
        }

        [Fact]
        public void CapsaException_FromHttpResponse_NullBody_UsesDefault()
        {
            // Act
            var exception = CapsaraCapsaException.FromHttpResponse(HttpStatusCode.NotFound, null);

            // Assert
            exception.Code.Should().Be("CAPSA_ERROR");
            exception.StatusCode.Should().Be(404);
        }

        [Fact]
        public void CapsaException_FromHttpResponse_InvalidJson_UsesDefault()
        {
            // Act
            var exception = CapsaraCapsaException.FromHttpResponse(HttpStatusCode.BadRequest, "not json");

            // Assert
            exception.Code.Should().Be("CAPSA_ERROR");
        }

        [Fact]
        public void CapsaNotFound_WithEmptyId_SetsEmptyInDetails()
        {
            // Act
            var exception = CapsaraCapsaException.CapsaNotFound("");

            // Assert
            exception.Code.Should().Be("CAPSA_NOT_FOUND");
            exception.Details.Should().ContainKey("capsaId");
            exception.Details!["capsaId"].Should().Be("");
        }

        [Fact]
        public void FileNotFound_WithEmptyId_SetsEmptyInDetails()
        {
            // Act
            var exception = CapsaraCapsaException.FileNotFound("");

            // Assert
            exception.Code.Should().Be("FILE_NOT_FOUND");
            exception.Details.Should().ContainKey("fileId");
        }

        [Fact]
        public void AccessDenied_WithDetails_SetsDetails()
        {
            // Arrange
            var details = new Dictionary<string, object> { ["reason"] = "expired" };

            // Act
            var exception = CapsaraCapsaException.AccessDenied(details);

            // Assert
            exception.Code.Should().Be("ACCESS_DENIED");
            exception.Details.Should().ContainKey("reason");
        }

        [Fact]
        public void CapsaDeleted_WithDetails_SetsDetails()
        {
            // Arrange
            var details = new Dictionary<string, object> { ["deletedAt"] = "2024-01-01" };

            // Act
            var exception = CapsaraCapsaException.CapsaDeleted(details);

            // Assert
            exception.Code.Should().Be("CAPSA_DELETED");
            exception.Details.Should().ContainKey("deletedAt");
        }

        [Fact]
        public void MissingParams_WithEmptyArray_StillWorks()
        {
            // Act
            var exception = CapsaraCapsaException.MissingParams();

            // Assert
            exception.Code.Should().Be("MISSING_PARAMS");
            exception.Message.Should().Contain("Missing required parameters");
        }

        [Fact]
        public void MissingParams_WithSingleParam_FormatsCorrectly()
        {
            // Act
            var exception = CapsaraCapsaException.MissingParams("fileId");

            // Assert
            exception.Message.Should().Contain("fileId");
        }

        [Fact]
        public void MissingParams_WithMultipleParams_FormatsCorrectly()
        {
            // Act
            var exception = CapsaraCapsaException.MissingParams("fileId", "capsaId", "partyId");

            // Assert
            exception.Message.Should().Contain("fileId");
            exception.Message.Should().Contain("capsaId");
            exception.Message.Should().Contain("partyId");
        }

        [Fact]
        public void MultipartError_WithCustomStatusCode_SetsStatusCode()
        {
            // Act
            var exception = CapsaraCapsaException.MultipartError("Payload too large", 413);

            // Assert
            exception.Code.Should().Be("MULTIPART_ERROR");
            exception.StatusCode.Should().Be(413);
        }

        [Fact]
        public void MultipartError_WithDetails_SetsDetails()
        {
            // Arrange
            var details = new Dictionary<string, object> { ["maxSize"] = 10485760 };

            // Act
            var exception = CapsaraCapsaException.MultipartError("File too large", 413, details);

            // Assert
            exception.Details.Should().ContainKey("maxSize");
        }

        [Fact]
        public void DownloadFailed_WithoutCause_SetsMessageWithoutCause()
        {
            // Act
            var exception = CapsaraCapsaException.DownloadFailed("pkg_123", "file_456");

            // Assert
            exception.Code.Should().Be("DOWNLOAD_FAILED");
            exception.Message.Should().Contain("pkg_123");
            exception.Message.Should().Contain("file_456");
            exception.InnerException.Should().BeNull();
        }

        [Fact]
        public void DownloadFailed_WithCause_IncludesCauseMessage()
        {
            // Arrange
            var cause = new Exception("Network timeout");

            // Act
            var exception = CapsaraCapsaException.DownloadFailed("pkg_123", "file_456", cause);

            // Assert
            exception.Message.Should().Contain("Network timeout");
        }

        #endregion

        #region CapsaraAuditException Factory Method Tests

        [Fact]
        public void MissingDetails_ReturnsCorrectException()
        {
            // Act
            var exception = CapsaraAuditException.MissingDetails();

            // Assert
            exception.Code.Should().Be("MISSING_DETAILS");
            exception.StatusCode.Should().Be(400);
        }

        [Fact]
        public void InvalidAction_ReturnsCorrectException()
        {
            // Act
            var exception = CapsaraAuditException.InvalidAction("unknown_action");

            // Assert
            exception.Code.Should().Be("INVALID_ACTION");
            exception.StatusCode.Should().Be(400);
            exception.Message.Should().Contain("unknown_action");
            exception.Details.Should().ContainKey("action");
        }

        [Fact]
        public void AuditException_FromHttpResponse_MapsKnownCodes()
        {
            // Arrange
            var responseBody = "{\"error\": {\"code\": \"MISSING_DETAILS\", \"message\": \"Details required\"}}";

            // Act
            var exception = CapsaraAuditException.FromHttpResponse(HttpStatusCode.BadRequest, responseBody);

            // Assert
            exception.Code.Should().Be("MISSING_DETAILS");
        }

        [Fact]
        public void AuditException_FromHttpResponse_MapsInvalidAction()
        {
            // Arrange
            var responseBody = "{\"error\": {\"code\": \"INVALID_ACTION\", \"message\": \"Bad action\", \"details\": {\"action\": \"invalid\"}}}";

            // Act
            var exception = CapsaraAuditException.FromHttpResponse(HttpStatusCode.BadRequest, responseBody);

            // Assert
            exception.Code.Should().Be("INVALID_ACTION");
        }

        [Fact]
        public void AuditException_FromHttpResponse_UnknownCode_UsesGenericAudit()
        {
            // Arrange
            var responseBody = "{\"error\": {\"code\": \"UNKNOWN_AUDIT_ERROR\", \"message\": \"Something happened\"}}";

            // Act
            var exception = CapsaraAuditException.FromHttpResponse(HttpStatusCode.BadRequest, responseBody);

            // Assert
            exception.Code.Should().Be("UNKNOWN_AUDIT_ERROR");
            exception.Message.Should().Be("Something happened");
        }

        [Fact]
        public void AuditException_FromHttpResponse_NullBody_UsesDefault()
        {
            // Act
            var exception = CapsaraAuditException.FromHttpResponse(HttpStatusCode.BadRequest, null);

            // Assert
            exception.Code.Should().Be("AUDIT_ERROR");
            exception.StatusCode.Should().Be(400);
        }

        [Fact]
        public void AuditException_FromHttpResponse_InvalidJson_UsesDefault()
        {
            // Act
            var exception = CapsaraAuditException.FromHttpResponse(HttpStatusCode.BadRequest, "not json");

            // Assert
            exception.Code.Should().Be("AUDIT_ERROR");
        }

        [Fact]
        public void InvalidAction_WithEmptyAction_StillWorks()
        {
            // Act
            var exception = CapsaraAuditException.InvalidAction("");

            // Assert
            exception.Code.Should().Be("INVALID_ACTION");
            exception.Details.Should().ContainKey("action");
            exception.Details!["action"].Should().Be("");
        }

        [Fact]
        public void InvalidAction_WithSpecialCharacters_PreservesAction()
        {
            // Act
            var exception = CapsaraAuditException.InvalidAction("action<>&\"'");

            // Assert
            exception.Details!["action"].Should().Be("action<>&\"'");
        }

        #endregion

        #region Exception Inheritance Tests

        [Fact]
        public void CapsaraAuthException_InheritsFromCapsaraException()
        {
            // Act
            var exception = CapsaraAuthException.InvalidCredentials();

            // Assert
            exception.Should().BeAssignableTo<CapsaraException>();
        }

        [Fact]
        public void CapsaraCapsaException_InheritsFromCapsaraException()
        {
            // Act
            var exception = CapsaraCapsaException.CapsaNotFound();

            // Assert
            exception.Should().BeAssignableTo<CapsaraException>();
        }

        [Fact]
        public void CapsaraAuditException_InheritsFromCapsaraException()
        {
            // Act
            var exception = CapsaraAuditException.MissingDetails();

            // Assert
            exception.Should().BeAssignableTo<CapsaraException>();
        }

        #endregion

        #region Response Body Preservation Tests

        [Fact]
        public void FromHttpResponse_PreservesResponseBody()
        {
            // Arrange
            var responseBody = "{\"error\": {\"code\": \"TEST\", \"message\": \"Test\"}}";

            // Act
            var exception = CapsaraException.FromHttpResponse(HttpStatusCode.BadRequest, responseBody);

            // Assert
            exception.ResponseBody.Should().Be(responseBody);
        }

        [Fact]
        public void FromHttpResponse_TruncatesLargeResponseBody()
        {
            // Arrange - large response body exceeding 1024 char limit
            var responseBody = new string('x', 10000);

            // Act
            var exception = CapsaraException.FromHttpResponse(HttpStatusCode.BadRequest, responseBody);

            // Assert - body is truncated to 1024 chars + "...[truncated]" suffix
            exception.ResponseBody.Should().StartWith(new string('x', 1024));
            exception.ResponseBody.Should().EndWith("...[truncated]");
            exception.ResponseBody!.Length.Should().Be(1024 + "...[truncated]".Length);
        }

        [Fact]
        public void AuthException_PreservesResponseBody()
        {
            // Arrange
            var responseBody = "{\"error\": {\"code\": \"TEST\", \"message\": \"Test\"}}";

            // Act
            var exception = CapsaraAuthException.FromHttpResponse(HttpStatusCode.Unauthorized, responseBody);

            // Assert
            exception.ResponseBody.Should().Be(responseBody);
        }

        [Fact]
        public void CapsaException_PreservesResponseBody()
        {
            // Arrange
            var responseBody = "{\"error\": {\"code\": \"TEST\", \"message\": \"Test\"}}";

            // Act
            var exception = CapsaraCapsaException.FromHttpResponse(HttpStatusCode.NotFound, responseBody);

            // Assert
            exception.ResponseBody.Should().Be(responseBody);
        }

        [Fact]
        public void AuditException_PreservesResponseBody()
        {
            // Arrange
            var responseBody = "{\"error\": {\"code\": \"TEST\", \"message\": \"Test\"}}";

            // Act
            var exception = CapsaraAuditException.FromHttpResponse(HttpStatusCode.BadRequest, responseBody);

            // Assert
            exception.ResponseBody.Should().Be(responseBody);
        }

        #endregion

        #region Cross-Error Type Tests

        [Fact]
        public void AllExceptionTypes_AreSystemException()
        {
            // Arrange
            var baseException = new CapsaraException("Test");
            var authException = CapsaraAuthException.InvalidCredentials();
            var capsaException = CapsaraCapsaException.CapsaNotFound();
            var auditException = CapsaraAuditException.MissingDetails();

            // Assert
            baseException.Should().BeAssignableTo<Exception>();
            authException.Should().BeAssignableTo<Exception>();
            capsaException.Should().BeAssignableTo<Exception>();
            auditException.Should().BeAssignableTo<Exception>();
        }

        [Fact]
        public void AllExceptionTypes_HaveConsistentProperties()
        {
            // Create instances of all types
            var exceptions = new CapsaraException[]
            {
                new CapsaraException("Test", "CODE", 400),
                CapsaraAuthException.InvalidCredentials(),
                CapsaraCapsaException.CapsaNotFound(),
                CapsaraAuditException.MissingDetails()
            };

            // All should have code, status, and message
            foreach (var ex in exceptions)
            {
                ex.Code.Should().NotBeNullOrEmpty();
                ex.Message.Should().NotBeNull();
                ex.StatusCode.Should().BeGreaterThanOrEqualTo(0);
            }
        }

        [Fact]
        public void ExceptionTypes_CanBeCaughtAsBaseType()
        {
            // Arrange
            CapsaraException? caught = null;

            // Act
            try
            {
                throw CapsaraAuthException.InvalidCredentials();
            }
            catch (CapsaraException ex)
            {
                caught = ex;
            }

            // Assert
            caught.Should().NotBeNull();
            caught!.Code.Should().Be("INVALID_CREDENTIALS");
        }

        [Fact]
        public void ExceptionTypes_CanBeCaughtAsSystemException()
        {
            // Arrange
            Exception? caught = null;

            // Act
            try
            {
                throw CapsaraCapsaException.CapsaNotFound();
            }
            catch (Exception ex)
            {
                caught = ex;
            }

            // Assert
            caught.Should().NotBeNull();
            caught.Should().BeOfType<CapsaraCapsaException>();
        }

        #endregion

        #region Edge Cases Tests

        [Fact]
        public void ExceptionWithNullMessage_HandlesGracefully()
        {
            // This tests defensive coding - what happens with edge cases
            var exception = new CapsaraException("", "CODE", 0);

            exception.Message.Should().Be("");
            exception.Code.Should().Be("CODE");
        }

        [Fact]
        public void ExceptionWithVeryLongCode_HandlesGracefully()
        {
            // Act
            var longCode = new string('A', 1000);
            var exception = new CapsaraException("Test", longCode, 400);

            // Assert
            exception.Code.Should().Be(longCode);
            exception.Code.Length.Should().Be(1000);
        }

        [Fact]
        public void ExceptionWithVeryLongMessage_HandlesGracefully()
        {
            // Act
            var longMessage = new string('M', 10000);
            var exception = new CapsaraException(longMessage);

            // Assert
            exception.Message.Should().Be(longMessage);
        }

        [Fact]
        public void FromHttpResponse_WithJsonArray_ThrowsInternalError()
        {
            // Arrange - unexpected JSON structure (array instead of object)
            var responseBody = "[\"error1\", \"error2\"]";

            // Act - The current implementation doesn't handle JSON arrays gracefully
            // This test documents the current behavior (throws exception)
            Action act = () => CapsaraException.FromHttpResponse(HttpStatusCode.BadRequest, responseBody);

            // Assert - Current implementation throws when encountering unexpected JSON types
            act.Should().Throw<InvalidOperationException>();
        }

        [Fact]
        public void FromHttpResponse_WithEmptyJsonObject_HandlesGracefully()
        {
            // Arrange
            var responseBody = "{}";

            // Act
            var exception = CapsaraException.FromHttpResponse(HttpStatusCode.BadRequest, responseBody);

            // Assert
            exception.Code.Should().Be("HTTP_ERROR");
        }

        [Fact]
        public void FromHttpResponse_WithNullErrorCode_HandlesGracefully()
        {
            // Arrange
            var responseBody = "{\"error\": {\"code\": null, \"message\": \"Test\"}}";

            // Act
            var exception = CapsaraException.FromHttpResponse(HttpStatusCode.BadRequest, responseBody);

            // Assert
            exception.Message.Should().Be("Test");
        }

        [Fact]
        public void FromHttpResponse_WithNumericErrorCode_ThrowsInternalError()
        {
            // Arrange - error code as number instead of string
            var responseBody = "{\"error\": {\"code\": 123, \"message\": \"Test\"}}";

            // Act - The current implementation doesn't handle numeric error codes gracefully
            // This test documents the current behavior (throws exception)
            Action act = () => CapsaraException.FromHttpResponse(HttpStatusCode.BadRequest, responseBody);

            // Assert - Current implementation throws when encountering wrong JSON types
            act.Should().Throw<InvalidOperationException>();
        }

        [Fact]
        public void FromHttpResponse_WithNestedDetails_ParsesTopLevel()
        {
            // Arrange
            var responseBody = "{\"error\": {\"code\": \"TEST\", \"message\": \"Test\", \"details\": {\"level1\": {\"level2\": \"value\"}}}}";

            // Act
            var exception = CapsaraException.FromHttpResponse(HttpStatusCode.BadRequest, responseBody);

            // Assert
            exception.Details.Should().ContainKey("level1");
        }

        [Theory]
        [InlineData("")]
        [InlineData(" ")]
        [InlineData("\t")]
        [InlineData("\n")]
        [InlineData("\r\n")]
        public void ExceptionCodes_WithWhitespace_StillWork(string code)
        {
            // Act
            var exception = new CapsaraException("Test", code, 400);

            // Assert
            exception.Code.Should().Be(code);
        }

        [Fact]
        public void DetailsWithNullValue_HandlesGracefully()
        {
            // Arrange
            var details = new Dictionary<string, object> { ["key"] = null! };

            // Act
            var exception = new CapsaraException("Test", "CODE", 400, details);

            // Assert
            exception.Details.Should().ContainKey("key");
        }

        [Fact]
        public void MultipleInnerExceptions_OnlyStoresFirst()
        {
            // Arrange
            var inner1 = new Exception("First");
            var inner2 = new Exception("Second", inner1);

            // Act
            var exception = new CapsaraException("Outer", "CODE", 500, null, null, inner2);

            // Assert
            exception.InnerException.Should().BeSameAs(inner2);
            exception.InnerException!.InnerException.Should().BeSameAs(inner1);
        }

        #endregion

        #region ToString and Serialization Tests

        [Fact]
        public void Exception_ToString_ContainsMessage()
        {
            // Act
            var exception = new CapsaraException("Test error message");

            // Assert
            exception.ToString().Should().Contain("Test error message");
        }

        [Fact]
        public void Exception_ToString_ContainsExceptionType()
        {
            // Act
            var exception = new CapsaraException("Test");

            // Assert
            exception.ToString().Should().Contain("CapsaraException");
        }

        [Fact]
        public void AuthException_ToString_ContainsTypeName()
        {
            // Act
            var exception = CapsaraAuthException.InvalidCredentials();

            // Assert
            exception.ToString().Should().Contain("CapsaraAuthException");
        }

        [Fact]
        public void CapsaException_ToString_ContainsTypeName()
        {
            // Act
            var exception = CapsaraCapsaException.CapsaNotFound();

            // Assert
            exception.ToString().Should().Contain("CapsaraCapsaException");
        }

        [Fact]
        public void AuditException_ToString_ContainsTypeName()
        {
            // Act
            var exception = CapsaraAuditException.MissingDetails();

            // Assert
            exception.ToString().Should().Contain("CapsaraAuditException");
        }

        [Fact]
        public void Exception_WithInnerException_ToString_ContainsBoth()
        {
            // Arrange
            var inner = new InvalidOperationException("Inner error");

            // Act
            var exception = new CapsaraException("Outer error", inner);

            // Assert
            exception.ToString().Should().Contain("Outer error");
            exception.ToString().Should().Contain("Inner error");
        }

        #endregion

        #region Factory Method Completeness Tests

        [Fact]
        public void AllAuthFactoryMethods_ReturnCorrectType()
        {
            // Test all factory methods return CapsaraAuthException
            CapsaraAuthException.InvalidCredentials().Should().BeOfType<CapsaraAuthException>();
            CapsaraAuthException.RefreshTokenRequired().Should().BeOfType<CapsaraAuthException>();
            CapsaraAuthException.InvalidRefreshToken().Should().BeOfType<CapsaraAuthException>();
            CapsaraAuthException.Unauthorized().Should().BeOfType<CapsaraAuthException>();
            CapsaraAuthException.NotImplemented("test").Should().BeOfType<CapsaraAuthException>();
            CapsaraAuthException.ValidationError("test").Should().BeOfType<CapsaraAuthException>();
        }

        [Fact]
        public void AllCapsaFactoryMethods_ReturnCorrectType()
        {
            // Test all factory methods return CapsaraCapsaException
            CapsaraCapsaException.CapsaNotFound().Should().BeOfType<CapsaraCapsaException>();
            CapsaraCapsaException.FileNotFound().Should().BeOfType<CapsaraCapsaException>();
            CapsaraCapsaException.AccessDenied().Should().BeOfType<CapsaraCapsaException>();
            CapsaraCapsaException.CreatorMismatch("a", "b").Should().BeOfType<CapsaraCapsaException>();
            CapsaraCapsaException.CapsaDeleted().Should().BeOfType<CapsaraCapsaException>();
            CapsaraCapsaException.InvalidContentType().Should().BeOfType<CapsaraCapsaException>();
            CapsaraCapsaException.MissingParams().Should().BeOfType<CapsaraCapsaException>();
            CapsaraCapsaException.MissingId().Should().BeOfType<CapsaraCapsaException>();
            CapsaraCapsaException.InvalidExpiration().Should().BeOfType<CapsaraCapsaException>();
            CapsaraCapsaException.MultipartError("test").Should().BeOfType<CapsaraCapsaException>();
            CapsaraCapsaException.DownloadFailed("c", "f").Should().BeOfType<CapsaraCapsaException>();
        }

        [Fact]
        public void AllAuditFactoryMethods_ReturnCorrectType()
        {
            // Test all factory methods return CapsaraAuditException
            CapsaraAuditException.MissingDetails().Should().BeOfType<CapsaraAuditException>();
            CapsaraAuditException.InvalidAction("test").Should().BeOfType<CapsaraAuditException>();
        }

        #endregion

        #region Status Code Consistency Tests

        [Fact]
        public void AuthExceptions_Have401StatusCode()
        {
            // Most auth exceptions should be 401
            CapsaraAuthException.InvalidCredentials().StatusCode.Should().Be(401);
            CapsaraAuthException.RefreshTokenRequired().StatusCode.Should().Be(401);
            CapsaraAuthException.InvalidRefreshToken().StatusCode.Should().Be(401);
            CapsaraAuthException.Unauthorized().StatusCode.Should().Be(401);
        }

        [Fact]
        public void NotFoundExceptions_Have404StatusCode()
        {
            CapsaraCapsaException.CapsaNotFound().StatusCode.Should().Be(404);
            CapsaraCapsaException.FileNotFound().StatusCode.Should().Be(404);
        }

        [Fact]
        public void ForbiddenExceptions_Have403StatusCode()
        {
            CapsaraCapsaException.AccessDenied().StatusCode.Should().Be(403);
            CapsaraCapsaException.CreatorMismatch("a", "b").StatusCode.Should().Be(403);
            CapsaraCapsaException.CapsaDeleted().StatusCode.Should().Be(403);
        }

        [Fact]
        public void BadRequestExceptions_Have400StatusCode()
        {
            CapsaraCapsaException.InvalidContentType().StatusCode.Should().Be(400);
            CapsaraCapsaException.MissingParams().StatusCode.Should().Be(400);
            CapsaraCapsaException.MissingId().StatusCode.Should().Be(400);
            CapsaraCapsaException.InvalidExpiration().StatusCode.Should().Be(400);
            CapsaraAuditException.MissingDetails().StatusCode.Should().Be(400);
            CapsaraAuditException.InvalidAction("test").StatusCode.Should().Be(400);
        }

        [Fact]
        public void NotImplementedException_Has405StatusCode()
        {
            CapsaraAuthException.NotImplemented("test").StatusCode.Should().Be(405);
        }

        [Fact]
        public void ValidationException_Has400StatusCode()
        {
            CapsaraAuthException.ValidationError("test").StatusCode.Should().Be(400);
        }

        #endregion
    }
}
