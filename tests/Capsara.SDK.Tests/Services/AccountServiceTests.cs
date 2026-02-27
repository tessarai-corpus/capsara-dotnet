using System;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Capsara.SDK.Exceptions;
using Capsara.SDK.Internal.Services;
using Capsara.SDK.Tests.Helpers;
using FluentAssertions;
using RichardSzalay.MockHttp;
using Xunit;

namespace Capsara.SDK.Tests.Services
{
    /// <summary>
    /// Tests for AccountService API operations.
    /// </summary>
    public class AccountServiceTests : IDisposable
    {
        private readonly MockHttpMessageHandler _mockHttp;
        private readonly HttpClient _httpClient;

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        public AccountServiceTests()
        {
            _mockHttp = new MockHttpMessageHandler();
            _httpClient = TestHelpers.CreateMockHttpClient(_mockHttp);
        }

        public void Dispose()
        {
            _httpClient.Dispose();
            _mockHttp.Dispose();
        }

        #region GetCurrentPublicKey Tests

        [Fact]
        public async Task GetCurrentPublicKeyAsync_WithValidKey_ReturnsPublicKeyInfo()
        {
            // Arrange
            var keyPair = TestHelpers.GenerateTestKeyPair();
            // Mock must match the API's JSON shape (publicKeyFingerprint, not keyFingerprint)
            var responseJson = JsonSerializer.Serialize(new
            {
                publicKey = keyPair.PublicKey,
                publicKeyFingerprint = keyPair.Fingerprint
            });

            _mockHttp.When(HttpMethod.Get, "*/api/account/key")
                .Respond("application/json", responseJson);

            var service = CreateAccountService();

            // Act
            var result = await service.GetCurrentPublicKeyAsync();

            // Assert
            result.Should().NotBeNull();
            result!.PublicKey.Should().Be(keyPair.PublicKey);
            result.KeyFingerprint.Should().Be(keyPair.Fingerprint);
            result.IsActive.Should().BeTrue();
        }

        [Fact]
        public async Task GetCurrentPublicKeyAsync_NoKeySet_ReturnsNull()
        {
            // Arrange
            _mockHttp.When(HttpMethod.Get, "*/api/account/key")
                .Respond(HttpStatusCode.NotFound);

            var service = CreateAccountService();

            // Act
            var result = await service.GetCurrentPublicKeyAsync();

            // Assert
            result.Should().BeNull();
        }

        [Fact]
        public async Task GetCurrentPublicKeyAsync_ServerError_ReturnsNull()
        {
            // Arrange
            _mockHttp.When(HttpMethod.Get, "*/api/account/key")
                .Respond(HttpStatusCode.InternalServerError);

            var service = CreateAccountService();

            // Act
            var result = await service.GetCurrentPublicKeyAsync();

            // Assert
            result.Should().BeNull();
        }

        [Fact]
        public async Task GetCurrentPublicKeyAsync_NetworkError_ReturnsNull()
        {
            // Arrange
            _mockHttp.When(HttpMethod.Get, "*/api/account/key")
                .Throw(new HttpRequestException("Network error"));

            var service = CreateAccountService();

            // Act
            var result = await service.GetCurrentPublicKeyAsync();

            // Assert
            result.Should().BeNull();
        }

        #endregion

        #region AddPublicKey Tests

        [Fact]
        public async Task AddPublicKeyAsync_WithValidKey_ReturnsPublicKeyInfo()
        {
            // Arrange
            var keyPair = TestHelpers.GenerateTestKeyPair();
            var response = new
            {
                publicKey = keyPair.PublicKey,
                publicKeyFingerprint = keyPair.Fingerprint,
                message = "Key added successfully"
            };

            _mockHttp.When(HttpMethod.Post, "*/api/account/key")
                .Respond("application/json", JsonSerializer.Serialize(response, JsonOptions));

            var service = CreateAccountService();

            // Act
            var result = await service.AddPublicKeyAsync(keyPair.PublicKey, keyPair.Fingerprint);

            // Assert
            result.Should().NotBeNull();
            result.PublicKey.Should().Be(keyPair.PublicKey);
            result.KeyFingerprint.Should().Be(keyPair.Fingerprint);
            result.IsActive.Should().BeTrue();
        }

        [Fact]
        public async Task AddPublicKeyAsync_WithReason_IncludesReasonInRequest()
        {
            // Arrange
            var keyPair = TestHelpers.GenerateTestKeyPair();
            var response = new
            {
                publicKey = keyPair.PublicKey,
                publicKeyFingerprint = keyPair.Fingerprint
            };

            _mockHttp.When(HttpMethod.Post, "*/api/account/key")
                .Respond("application/json", JsonSerializer.Serialize(response, JsonOptions));

            var service = CreateAccountService();

            // Act
            var result = await service.AddPublicKeyAsync(keyPair.PublicKey, keyPair.Fingerprint, "Key rotation");

            // Assert
            result.Should().NotBeNull();
        }

        [Fact]
        public async Task AddPublicKeyAsync_InvalidKey_ThrowsException()
        {
            // Arrange
            var errorResponse = TestHelpers.CreateErrorResponse("INVALID_PUBLIC_KEY", "Invalid public key format");

            _mockHttp.When(HttpMethod.Post, "*/api/account/key")
                .Respond(HttpStatusCode.BadRequest, "application/json", errorResponse);

            var service = CreateAccountService();

            // Act & Assert
            var exception = await Assert.ThrowsAsync<CapsaraException>(
                () => service.AddPublicKeyAsync("invalid-key", "invalid-fingerprint"));

            exception.StatusCode.Should().Be(400);
        }

        [Fact]
        public async Task AddPublicKeyAsync_Unauthorized_ThrowsException()
        {
            // Arrange
            var errorResponse = TestHelpers.CreateErrorResponse("UNAUTHORIZED", "Not authenticated");

            _mockHttp.When(HttpMethod.Post, "*/api/account/key")
                .Respond(HttpStatusCode.Unauthorized, "application/json", errorResponse);

            var service = CreateAccountService();

            // Act & Assert
            var exception = await Assert.ThrowsAsync<CapsaraException>(
                () => service.AddPublicKeyAsync("key", "fingerprint"));

            exception.StatusCode.Should().Be(401);
        }

        [Fact]
        public async Task AddPublicKeyAsync_NetworkError_ThrowsException()
        {
            // Arrange
            _mockHttp.When(HttpMethod.Post, "*/api/account/key")
                .Throw(new HttpRequestException("Network error"));

            var service = CreateAccountService();

            // Act & Assert
            var exception = await Assert.ThrowsAsync<CapsaraException>(
                () => service.AddPublicKeyAsync("key", "fingerprint"));

            exception.Code.Should().Be("NETWORK_ERROR");
        }

        #endregion

        #region GetKeyHistory Tests

        [Fact]
        public async Task GetKeyHistoryAsync_ReturnsKeyHistory()
        {
            // Arrange
            var keyPair1 = TestHelpers.GenerateTestKeyPair();
            var keyPair2 = TestHelpers.GenerateTestKeyPair();
            var response = new
            {
                keys = new[]
                {
                    new
                    {
                        publicKey = keyPair1.PublicKey,
                        keyFingerprint = keyPair1.Fingerprint,
                        createdAt = DateTimeOffset.UtcNow.AddDays(-30).ToString("o"),
                        revokedAt = (string?)DateTimeOffset.UtcNow.AddDays(-1).ToString("o"),
                        isActive = false
                    },
                    new
                    {
                        publicKey = keyPair2.PublicKey,
                        keyFingerprint = keyPair2.Fingerprint,
                        createdAt = DateTimeOffset.UtcNow.AddDays(-1).ToString("o"),
                        revokedAt = (string?)null,
                        isActive = true
                    }
                }
            };

            _mockHttp.When(HttpMethod.Get, "*/api/account/key/history")
                .Respond("application/json", JsonSerializer.Serialize(response, JsonOptions));

            var service = CreateAccountService();

            // Act
            var result = await service.GetKeyHistoryAsync();

            // Assert
            result.Should().HaveCount(2);
            result[0].IsActive.Should().BeFalse();
            result[1].IsActive.Should().BeTrue();
        }

        [Fact]
        public async Task GetKeyHistoryAsync_EmptyHistory_ReturnsEmptyArray()
        {
            // Arrange
            var response = new { keys = Array.Empty<object>() };

            _mockHttp.When(HttpMethod.Get, "*/api/account/key/history")
                .Respond("application/json", JsonSerializer.Serialize(response, JsonOptions));

            var service = CreateAccountService();

            // Act
            var result = await service.GetKeyHistoryAsync();

            // Assert
            result.Should().BeEmpty();
        }

        [Fact]
        public async Task GetKeyHistoryAsync_ServerError_ReturnsEmptyArray()
        {
            // Arrange
            _mockHttp.When(HttpMethod.Get, "*/api/account/key/history")
                .Respond(HttpStatusCode.InternalServerError);

            var service = CreateAccountService();

            // Act
            var result = await service.GetKeyHistoryAsync();

            // Assert
            result.Should().BeEmpty();
        }

        [Fact]
        public async Task GetKeyHistoryAsync_NetworkError_ReturnsEmptyArray()
        {
            // Arrange
            _mockHttp.When(HttpMethod.Get, "*/api/account/key/history")
                .Throw(new HttpRequestException("Network error"));

            var service = CreateAccountService();

            // Act
            var result = await service.GetKeyHistoryAsync();

            // Assert
            result.Should().BeEmpty();
        }

        #endregion

        #region RotateKey Tests

        [Fact]
        public async Task RotateKeyAsync_GeneratesNewKeyAndUploads()
        {
            // Arrange
            var response = new
            {
                publicKey = "new-public-key",
                publicKeyFingerprint = "new-fingerprint"
            };

            _mockHttp.When(HttpMethod.Post, "*/api/account/key")
                .Respond("application/json", JsonSerializer.Serialize(response, JsonOptions));

            var service = CreateAccountService();

            // Act
            var result = await service.RotateKeyAsync();

            // Assert
            result.Should().NotBeNull();
            result.KeyPair.Should().NotBeNull();
            result.KeyPair.PublicKey.Should().NotBeNullOrEmpty();
            result.KeyPair.PrivateKey.Should().NotBeNullOrEmpty();
            result.KeyPair.Fingerprint.Should().NotBeNullOrEmpty();
            result.ServerInfo.Should().NotBeNull();
        }

        [Fact]
        public async Task RotateKeyAsync_ServerError_ThrowsException()
        {
            // Arrange
            var errorResponse = TestHelpers.CreateErrorResponse("SERVER_ERROR", "Internal server error");

            _mockHttp.When(HttpMethod.Post, "*/api/account/key")
                .Respond(HttpStatusCode.InternalServerError, "application/json", errorResponse);

            var service = CreateAccountService();

            // Act & Assert
            var exception = await Assert.ThrowsAsync<CapsaraException>(
                () => service.RotateKeyAsync());

            exception.StatusCode.Should().Be(500);
        }

        #endregion

        private AccountService CreateAccountService()
        {
            return new AccountService(_httpClient);
        }
    }
}
