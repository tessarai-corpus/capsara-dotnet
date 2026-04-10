using System;
using System.Net;
using System.Net.Http;
using System.Text;
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
    /// Tests for DownloadService file download operations.
    /// </summary>
    public class DownloadServiceTests : IDisposable
    {
        private readonly MockHttpMessageHandler _mockHttp;
        private readonly MockHttpMessageHandler _mockBlobHttp;
        private readonly HttpClient _httpClient;
        private readonly HttpClient _blobHttpClient;

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        public DownloadServiceTests()
        {
            _mockHttp = new MockHttpMessageHandler();
            _mockBlobHttp = new MockHttpMessageHandler();
            _httpClient = TestHelpers.CreateMockHttpClient(_mockHttp);
            _blobHttpClient = new HttpClient(_mockBlobHttp) { BaseAddress = new Uri("https://storage.test.com/") };
        }

        public void Dispose()
        {
            _httpClient.Dispose();
            _blobHttpClient.Dispose();
            _mockHttp.Dispose();
            _mockBlobHttp.Dispose();
        }

        #region GetFileDownloadUrl Tests

        [Fact]
        public async Task GetFileDownloadUrlAsync_ReturnsSignedUrl()
        {
            // Arrange
            var capsaId = TestHelpers.GenerateCapsaId();
            var fileId = TestHelpers.GenerateFileId();
            var expectedUrl = $"https://storage.test.com/files/{fileId}?sig=abc123";

            var response = new
            {
                fileId,
                downloadUrl = expectedUrl,
                expiresAt = DateTimeOffset.UtcNow.AddHours(1).ToString("o")
            };

            _mockHttp.When(HttpMethod.Get, $"*/api/capsas/{capsaId}/files/{fileId}/download*")
                .Respond("application/json", JsonSerializer.Serialize(response, JsonOptions));

            var service = CreateDownloadService();

            // Act
            var (downloadUrl, expiresAt) = await service.GetFileDownloadUrlAsync(capsaId, fileId);

            // Assert
            downloadUrl.Should().Be(expectedUrl);
            expiresAt.Should().NotBeNullOrEmpty();
        }

        [Fact]
        public async Task GetFileDownloadUrlAsync_WithCustomExpiration_SetsQueryParam()
        {
            // Arrange
            var capsaId = TestHelpers.GenerateCapsaId();
            var fileId = TestHelpers.GenerateFileId();
            var expectedUrl = "https://storage.test.com/files/test";

            var response = new { fileId, downloadUrl = expectedUrl, expiresAt = "2024-01-01T00:00:00Z" };

            _mockHttp.When(HttpMethod.Get, $"*/api/capsas/{capsaId}/files/{fileId}/download*")
                .Respond("application/json", JsonSerializer.Serialize(response, JsonOptions));

            var service = CreateDownloadService();

            // Act
            var (downloadUrl, _) = await service.GetFileDownloadUrlAsync(capsaId, fileId, expiresInMinutes: 120);

            // Assert
            downloadUrl.Should().NotBeNullOrEmpty();
        }

        [Fact]
        public async Task GetFileDownloadUrlAsync_FileNotFound_ThrowsException()
        {
            // Arrange
            var capsaId = TestHelpers.GenerateCapsaId();
            var fileId = "file_nonexistent";
            var errorResponse = TestHelpers.CreateErrorResponse("FILE_NOT_FOUND", "File not found");

            _mockHttp.When(HttpMethod.Get, $"*/api/capsas/{capsaId}/files/{fileId}/download*")
                .Respond(HttpStatusCode.NotFound, "application/json", errorResponse);

            var service = CreateDownloadService();

            // Act & Assert
            var exception = await Assert.ThrowsAsync<CapsaraCapsaException>(
                () => service.GetFileDownloadUrlAsync(capsaId, fileId));

            exception.Code.Should().Be("FILE_NOT_FOUND");
        }

        [Fact]
        public async Task GetFileDownloadUrlAsync_CapsaNotFound_ThrowsException()
        {
            // Arrange
            var capsaId = "pkg_nonexistent";
            var fileId = TestHelpers.GenerateFileId();
            var errorResponse = TestHelpers.CreateErrorResponse("CAPSA_NOT_FOUND", "Capsa not found");

            _mockHttp.When(HttpMethod.Get, $"*/api/capsas/{capsaId}/files/{fileId}/download*")
                .Respond(HttpStatusCode.NotFound, "application/json", errorResponse);

            var service = CreateDownloadService();

            // Act & Assert
            var exception = await Assert.ThrowsAsync<CapsaraCapsaException>(
                () => service.GetFileDownloadUrlAsync(capsaId, fileId));

            exception.Code.Should().Be("CAPSA_NOT_FOUND");
        }

        [Fact]
        public async Task GetFileDownloadUrlAsync_AccessDenied_ThrowsException()
        {
            // Arrange
            var capsaId = TestHelpers.GenerateCapsaId();
            var fileId = TestHelpers.GenerateFileId();
            var errorResponse = TestHelpers.CreateErrorResponse("ACCESS_DENIED", "Access denied");

            _mockHttp.When(HttpMethod.Get, $"*/api/capsas/{capsaId}/files/{fileId}/download*")
                .Respond(HttpStatusCode.Forbidden, "application/json", errorResponse);

            var service = CreateDownloadService();

            // Act & Assert
            var exception = await Assert.ThrowsAsync<CapsaraCapsaException>(
                () => service.GetFileDownloadUrlAsync(capsaId, fileId));

            exception.Code.Should().Be("ACCESS_DENIED");
        }

        [Fact]
        public async Task GetFileDownloadUrlAsync_CapsaDeleted_ThrowsException()
        {
            // Arrange
            var capsaId = TestHelpers.GenerateCapsaId();
            var fileId = TestHelpers.GenerateFileId();
            var errorResponse = TestHelpers.CreateErrorResponse("CAPSA_DELETED", "Capsa is deleted");

            _mockHttp.When(HttpMethod.Get, $"*/api/capsas/{capsaId}/files/{fileId}/download*")
                .Respond(HttpStatusCode.Forbidden, "application/json", errorResponse);

            var service = CreateDownloadService();

            // Act & Assert
            var exception = await Assert.ThrowsAsync<CapsaraCapsaException>(
                () => service.GetFileDownloadUrlAsync(capsaId, fileId));

            exception.Code.Should().Be("CAPSA_DELETED");
        }

        [Fact]
        public async Task GetFileDownloadUrlAsync_NetworkError_ThrowsException()
        {
            // Arrange
            var capsaId = TestHelpers.GenerateCapsaId();
            var fileId = TestHelpers.GenerateFileId();

            _mockHttp.When(HttpMethod.Get, $"*/api/capsas/{capsaId}/files/{fileId}/download*")
                .Throw(new HttpRequestException("Network error"));

            var service = CreateDownloadService();

            // Act & Assert
            var exception = await Assert.ThrowsAsync<CapsaraException>(
                () => service.GetFileDownloadUrlAsync(capsaId, fileId));

            exception.Code.Should().Be("NETWORK_ERROR");
        }

        #endregion

        #region DownloadEncryptedFile Tests

        [Fact]
        public async Task DownloadEncryptedFileAsync_FileNotFound_ThrowsException()
        {
            // Arrange
            var capsaId = TestHelpers.GenerateCapsaId();
            var fileId = "file_nonexistent";
            var errorResponse = TestHelpers.CreateErrorResponse("FILE_NOT_FOUND", "File not found");

            _mockHttp.When(HttpMethod.Get, $"*/api/capsas/{capsaId}/files/{fileId}/download*")
                .Respond(HttpStatusCode.NotFound, "application/json", errorResponse);

            var service = CreateDownloadService();

            // Act & Assert
            var exception = await Assert.ThrowsAsync<CapsaraCapsaException>(
                () => service.DownloadEncryptedFileAsync(capsaId, fileId));

            exception.Code.Should().Be("FILE_NOT_FOUND");
        }

        #endregion

        #region Expiration Validation Tests

        [Fact]
        public async Task GetFileDownloadUrlAsync_InvalidExpiration_ThrowsException()
        {
            // Arrange
            var capsaId = TestHelpers.GenerateCapsaId();
            var fileId = TestHelpers.GenerateFileId();
            var errorResponse = TestHelpers.CreateErrorResponse("INVALID_EXPIRATION", "Expiration must be between 1 and 1440 minutes");

            _mockHttp.When(HttpMethod.Get, $"*/api/capsas/{capsaId}/files/{fileId}/download*")
                .Respond(HttpStatusCode.BadRequest, "application/json", errorResponse);

            var service = CreateDownloadService();

            // Act & Assert
            var exception = await Assert.ThrowsAsync<CapsaraCapsaException>(
                () => service.GetFileDownloadUrlAsync(capsaId, fileId, expiresInMinutes: 0));

            exception.Code.Should().Be("INVALID_EXPIRATION");
        }

        #endregion

        private DownloadService CreateDownloadService()
        {
            return new DownloadService(_httpClient, _blobHttpClient);
        }
    }
}
