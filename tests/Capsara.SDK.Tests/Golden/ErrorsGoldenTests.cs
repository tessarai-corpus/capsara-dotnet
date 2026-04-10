using System;
using System.Collections.Generic;
using System.Net;
using Capsara.SDK.Exceptions;
using FluentAssertions;
using Xunit;

namespace Capsara.SDK.Tests.Golden
{
    /// <summary>
    /// Golden tests for exception hierarchy, factory methods, messages, and status codes.
    /// </summary>
    public class ErrorsGoldenTests
    {
        #region Exception Hierarchy Tests

        [Fact]
        public void ExceptionHierarchy_AllInheritFromCapsaraException()
        {
            // Arrange & Act
            var baseException = new CapsaraException("test");
            var authException = CapsaraAuthException.InvalidCredentials();
            var capsaException = CapsaraCapsaException.CapsaNotFound();
            var auditException = CapsaraAuditException.MissingDetails();

            // Assert
            baseException.Should().BeAssignableTo<Exception>();
            authException.Should().BeAssignableTo<CapsaraException>();
            capsaException.Should().BeAssignableTo<CapsaraException>();
            auditException.Should().BeAssignableTo<CapsaraException>();
        }

        [Fact]
        public void ExceptionHierarchy_CanBeCaughtPolymorphically()
        {
            // Arrange
            CapsaraException? caught = null;

            // Act
            try
            {
                throw CapsaraCapsaException.CapsaNotFound("pkg_123");
            }
            catch (CapsaraException ex)
            {
                caught = ex;
            }

            // Assert
            caught.Should().NotBeNull();
            caught.Should().BeOfType<CapsaraCapsaException>();
            caught!.Code.Should().Be("CAPSA_NOT_FOUND");
        }

        #endregion

        #region Factory Method Tests

        [Fact]
        public void AuthException_FactoryMethods_ReturnCorrectCodes()
        {
            // Assert
            CapsaraAuthException.InvalidCredentials().Code.Should().Be("INVALID_CREDENTIALS");
            CapsaraAuthException.RefreshTokenRequired().Code.Should().Be("REFRESH_TOKEN_REQUIRED");
            CapsaraAuthException.InvalidRefreshToken().Code.Should().Be("INVALID_REFRESH_TOKEN");
            CapsaraAuthException.Unauthorized().Code.Should().Be("UNAUTHORIZED");
            CapsaraAuthException.NotImplemented("feature").Code.Should().Be("NOT_IMPLEMENTED");
            CapsaraAuthException.ValidationError("msg").Code.Should().Be("VALIDATION_ERROR");
        }

        [Fact]
        public void CapsaException_FactoryMethods_ReturnCorrectCodes()
        {
            // Assert
            CapsaraCapsaException.CapsaNotFound().Code.Should().Be("CAPSA_NOT_FOUND");
            CapsaraCapsaException.FileNotFound().Code.Should().Be("FILE_NOT_FOUND");
            CapsaraCapsaException.AccessDenied().Code.Should().Be("ACCESS_DENIED");
            CapsaraCapsaException.CreatorMismatch("a", "b").Code.Should().Be("CREATOR_MISMATCH");
            CapsaraCapsaException.CapsaDeleted().Code.Should().Be("CAPSA_DELETED");
            CapsaraCapsaException.InvalidContentType().Code.Should().Be("INVALID_CONTENT_TYPE");
            CapsaraCapsaException.MissingParams().Code.Should().Be("MISSING_PARAMS");
            CapsaraCapsaException.MissingId().Code.Should().Be("MISSING_ID");
            CapsaraCapsaException.InvalidExpiration().Code.Should().Be("INVALID_EXPIRATION");
        }

        #endregion

        #region Message Tests

        [Fact]
        public void CapsaraException_WithMessage_PreservesMessage()
        {
            // Act
            var exception = new CapsaraException("Something went wrong");

            // Assert
            exception.Message.Should().Be("Something went wrong");
        }

        [Fact]
        public void CapsaraException_WithInnerException_PreservesChain()
        {
            // Arrange
            var inner = new InvalidOperationException("Root cause");

            // Act
            var exception = new CapsaraException("Wrapper error", inner);

            // Assert
            exception.Message.Should().Be("Wrapper error");
            exception.InnerException.Should().BeSameAs(inner);
            exception.InnerException!.Message.Should().Be("Root cause");
        }

        [Fact]
        public void NetworkError_ContainsNetworkErrorCode()
        {
            // Arrange
            var inner = new System.Net.Http.HttpRequestException("Connection refused");

            // Act
            var exception = CapsaraException.NetworkError(inner);

            // Assert
            exception.Code.Should().Be("NETWORK_ERROR");
            exception.Message.Should().Contain("Network error");
            exception.InnerException.Should().BeSameAs(inner);
        }

        #endregion

        #region Status Code Tests

        [Fact]
        public void StatusCodes_AreConsistentWithHttpStandards()
        {
            // 401 Unauthorized
            CapsaraAuthException.InvalidCredentials().StatusCode.Should().Be(401);
            CapsaraAuthException.Unauthorized().StatusCode.Should().Be(401);
            CapsaraAuthException.RefreshTokenRequired().StatusCode.Should().Be(401);
            CapsaraAuthException.InvalidRefreshToken().StatusCode.Should().Be(401);

            // 400 Bad Request
            CapsaraAuthException.ValidationError("test").StatusCode.Should().Be(400);
            CapsaraCapsaException.InvalidContentType().StatusCode.Should().Be(400);
            CapsaraCapsaException.MissingParams().StatusCode.Should().Be(400);
            CapsaraCapsaException.MissingId().StatusCode.Should().Be(400);
            CapsaraCapsaException.InvalidExpiration().StatusCode.Should().Be(400);
            CapsaraAuditException.MissingDetails().StatusCode.Should().Be(400);
            CapsaraAuditException.InvalidAction("test").StatusCode.Should().Be(400);

            // 403 Forbidden
            CapsaraCapsaException.AccessDenied().StatusCode.Should().Be(403);
            CapsaraCapsaException.CreatorMismatch("a", "b").StatusCode.Should().Be(403);
            CapsaraCapsaException.CapsaDeleted().StatusCode.Should().Be(403);

            // 404 Not Found
            CapsaraCapsaException.CapsaNotFound().StatusCode.Should().Be(404);
            CapsaraCapsaException.FileNotFound().StatusCode.Should().Be(404);

            // 405 Method Not Allowed
            CapsaraAuthException.NotImplemented("feature").StatusCode.Should().Be(405);
        }

        [Fact]
        public void FromHttpResponse_MapsStatusCodeCorrectly()
        {
            // Arrange
            var responseBody = "{\"error\": {\"code\": \"TEST_ERROR\", \"message\": \"Test\"}}";

            // Act
            var exception = CapsaraException.FromHttpResponse(HttpStatusCode.BadRequest, responseBody);

            // Assert
            exception.StatusCode.Should().Be(400);
            exception.Code.Should().Be("TEST_ERROR");
            exception.ResponseBody.Should().Be(responseBody);
        }

        [Fact]
        public void FromHttpResponse_InvalidJson_FallsBackToHttpError()
        {
            // Act
            var exception = CapsaraException.FromHttpResponse(HttpStatusCode.InternalServerError, "not json");

            // Assert
            exception.Code.Should().Be("HTTP_ERROR");
            exception.StatusCode.Should().Be(500);
            exception.Message.Should().Contain("500");
        }

        [Fact]
        public void CapsaException_DefaultCode_IsUnknownError()
        {
            // Act
            var exception = new CapsaraException("test");

            // Assert
            exception.Code.Should().Be("UNKNOWN_ERROR");
            exception.StatusCode.Should().Be(0);
        }

        #endregion
    }
}
