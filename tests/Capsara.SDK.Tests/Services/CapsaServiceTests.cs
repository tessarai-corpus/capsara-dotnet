using System;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Capsara.SDK.Exceptions;
using Capsara.SDK.Internal.Http;
using Capsara.SDK.Internal.Services;
using Capsara.SDK.Models;
using Capsara.SDK.Tests.Helpers;
using FluentAssertions;
using RichardSzalay.MockHttp;
using Xunit;

namespace Capsara.SDK.Tests.Services
{
    /// <summary>
    /// Tests for CapsaService envelope CRUD operations.
    /// </summary>
    public class CapsaServiceTests : IDisposable
    {
        private readonly MockHttpMessageHandler _mockHttp;
        private readonly HttpClient _httpClient;
        private readonly KeyService _keyService;

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        public CapsaServiceTests()
        {
            _mockHttp = new MockHttpMessageHandler();
            _httpClient = TestHelpers.CreateMockHttpClient(_mockHttp);
            // Create a real KeyService instance - it won't be used for these tests
            _keyService = new KeyService(
                "https://api.test.com",
                () => "test-token",
                new KeyServiceOptions { Retry = new RetryConfig { MaxRetries = 0 } });
        }

        public void Dispose()
        {
            _httpClient.Dispose();
            _mockHttp.Dispose();
        }

        #region GetCapsa Tests

        [Fact]
        public async Task GetCapsaAsync_WithValidId_ReturnsCapsa()
        {
            // Arrange
            var capsaId = TestHelpers.GenerateCapsaId();
            var expectedCapsa = TestHelpers.CreateMockCapsa(capsaId);

            _mockHttp.When(HttpMethod.Get, $"*/api/capsas/{capsaId}")
                .Respond("application/json", JsonSerializer.Serialize(expectedCapsa, JsonOptions));

            var service = CreateCapsaService();

            // Act
            var result = await service.GetCapsaAsync(capsaId);

            // Assert
            result.Should().NotBeNull();
            result.Id.Should().Be(capsaId);
        }

        [Fact]
        public async Task GetCapsaAsync_WithNonExistentId_ThrowsCapsaNotFound()
        {
            // Arrange
            var capsaId = "pkg_nonexistent";
            var errorResponse = TestHelpers.CreateErrorResponse("CAPSA_NOT_FOUND", "Capsa not found");

            _mockHttp.When(HttpMethod.Get, $"*/api/capsas/{capsaId}")
                .Respond(HttpStatusCode.NotFound, "application/json", errorResponse);

            var service = CreateCapsaService();

            // Act & Assert
            var exception = await Assert.ThrowsAsync<CapsaraCapsaException>(
                () => service.GetCapsaAsync(capsaId));

            exception.Code.Should().Be("CAPSA_NOT_FOUND");
            exception.StatusCode.Should().Be(404);
        }

        [Fact]
        public async Task GetCapsaAsync_WithAccessDenied_ThrowsAccessDenied()
        {
            // Arrange
            var capsaId = TestHelpers.GenerateCapsaId();
            var errorResponse = TestHelpers.CreateErrorResponse("ACCESS_DENIED", "You do not have access to this capsa");

            _mockHttp.When(HttpMethod.Get, $"*/api/capsas/{capsaId}")
                .Respond(HttpStatusCode.Forbidden, "application/json", errorResponse);

            var service = CreateCapsaService();

            // Act & Assert
            var exception = await Assert.ThrowsAsync<CapsaraCapsaException>(
                () => service.GetCapsaAsync(capsaId));

            exception.Code.Should().Be("ACCESS_DENIED");
            exception.StatusCode.Should().Be(403);
        }

        [Fact]
        public async Task GetCapsaAsync_NetworkError_ThrowsCapsaraException()
        {
            // Arrange
            var capsaId = TestHelpers.GenerateCapsaId();

            _mockHttp.When(HttpMethod.Get, $"*/api/capsas/{capsaId}")
                .Throw(new HttpRequestException("Network error"));

            var service = CreateCapsaService();

            // Act & Assert
            var exception = await Assert.ThrowsAsync<CapsaraException>(
                () => service.GetCapsaAsync(capsaId));

            exception.Code.Should().Be("NETWORK_ERROR");
        }

        [Fact]
        public async Task GetCapsaAsync_ReturnsAllCapsaFields()
        {
            // Arrange
            var capsaId = TestHelpers.GenerateCapsaId();
            var creatorId = TestHelpers.GeneratePartyId();
            var file = TestHelpers.CreateMockEncryptedFile();

            var expectedCapsa = TestHelpers.CreateMockCapsa(capsaId, creatorId, new[] { file });
            expectedCapsa.EncryptedSubject = "encrypted-subject";
            expectedCapsa.SubjectIV = "subject-iv";
            expectedCapsa.SubjectAuthTag = "subject-auth-tag";
            expectedCapsa.TotalSize = 1024;

            _mockHttp.When(HttpMethod.Get, $"*/api/capsas/{capsaId}")
                .Respond("application/json", JsonSerializer.Serialize(expectedCapsa, JsonOptions));

            var service = CreateCapsaService();

            // Act
            var result = await service.GetCapsaAsync(capsaId);

            // Assert
            result.Id.Should().Be(capsaId);
            result.Creator.Should().Be(creatorId);
            result.Files.Should().HaveCount(1);
            result.EncryptedSubject.Should().Be("encrypted-subject");
            result.TotalSize.Should().Be(1024);
        }

        #endregion

        #region ListCapsas Tests

        [Fact]
        public async Task ListCapsasAsync_WithNoFilters_ReturnsAllCapsas()
        {
            // Arrange
            var response = new CapsaListResponse
            {
                Capsas = new[]
                {
                    new CapsaSummary { Id = "pkg_1", Status = "active" },
                    new CapsaSummary { Id = "pkg_2", Status = "active" }
                },
                Pagination = new CursorPagination { Limit = 20, HasMore = false }
            };

            _mockHttp.When(HttpMethod.Get, "*/api/capsas")
                .Respond("application/json", JsonSerializer.Serialize(response, JsonOptions));

            var service = CreateCapsaService();

            // Act
            var result = await service.ListCapsasAsync();

            // Assert
            result.Should().NotBeNull();
            result.Capsas.Should().HaveCount(2);
            result.Pagination.HasMore.Should().BeFalse();
        }

        [Fact]
        public async Task ListCapsasAsync_WithStatusFilter_BuildsCorrectQueryString()
        {
            // Arrange
            var response = new CapsaListResponse
            {
                Capsas = Array.Empty<CapsaSummary>(),
                Pagination = new CursorPagination { Limit = 20, HasMore = false }
            };

            _mockHttp.When(HttpMethod.Get, "*/api/capsas*")
                .WithQueryString("status", "active")
                .Respond("application/json", JsonSerializer.Serialize(response, JsonOptions));

            var service = CreateCapsaService();
            var filters = new CapsaListFilters { Status = CapsaStatus.Active };

            // Act
            var result = await service.ListCapsasAsync(filters);

            // Assert
            result.Should().NotBeNull();
        }

        [Fact]
        public async Task ListCapsasAsync_WithPagination_BuildsCorrectQueryString()
        {
            // Arrange
            var response = new CapsaListResponse
            {
                Capsas = Array.Empty<CapsaSummary>(),
                Pagination = new CursorPagination
                {
                    Limit = 50,
                    HasMore = true,
                    NextCursor = "next-cursor-123"
                }
            };

            _mockHttp.When(HttpMethod.Get, "*/api/capsas*")
                .Respond("application/json", JsonSerializer.Serialize(response, JsonOptions));

            var service = CreateCapsaService();
            var filters = new CapsaListFilters { Limit = 50, After = "cursor-abc" };

            // Act
            var result = await service.ListCapsasAsync(filters);

            // Assert
            result.Pagination.Limit.Should().Be(50);
            result.Pagination.HasMore.Should().BeTrue();
            result.Pagination.NextCursor.Should().Be("next-cursor-123");
        }

        [Fact]
        public async Task ListCapsasAsync_WithCreatedByFilter_BuildsCorrectQueryString()
        {
            // Arrange
            var creatorId = TestHelpers.GeneratePartyId();
            var response = new CapsaListResponse
            {
                Capsas = new[] { new CapsaSummary { Id = "pkg_1", Creator = creatorId } },
                Pagination = new CursorPagination { Limit = 20, HasMore = false }
            };

            _mockHttp.When(HttpMethod.Get, "*/api/capsas*")
                .Respond("application/json", JsonSerializer.Serialize(response, JsonOptions));

            var service = CreateCapsaService();
            var filters = new CapsaListFilters { CreatedBy = creatorId };

            // Act
            var result = await service.ListCapsasAsync(filters);

            // Assert
            result.Capsas.Should().HaveCount(1);
            result.Capsas[0].Creator.Should().Be(creatorId);
        }

        [Fact]
        public async Task ListCapsasAsync_WithDateRangeFilters_BuildsCorrectQueryString()
        {
            // Arrange
            var response = new CapsaListResponse
            {
                Capsas = Array.Empty<CapsaSummary>(),
                Pagination = new CursorPagination { Limit = 20, HasMore = false }
            };

            _mockHttp.When(HttpMethod.Get, "*/api/capsas*")
                .Respond("application/json", JsonSerializer.Serialize(response, JsonOptions));

            var service = CreateCapsaService();
            var filters = new CapsaListFilters
            {
                StartDate = "2024-01-01T00:00:00Z",
                EndDate = "2024-12-31T23:59:59Z"
            };

            // Act
            var result = await service.ListCapsasAsync(filters);

            // Assert
            result.Should().NotBeNull();
        }

        [Fact]
        public async Task ListCapsasAsync_ServerError_ThrowsCapsaException()
        {
            // Arrange
            var errorResponse = TestHelpers.CreateErrorResponse("INTERNAL_ERROR", "Server error");

            _mockHttp.When(HttpMethod.Get, "*/api/capsas*")
                .Respond(HttpStatusCode.InternalServerError, "application/json", errorResponse);

            var service = CreateCapsaService();

            // Act & Assert
            var exception = await Assert.ThrowsAsync<CapsaraCapsaException>(
                () => service.ListCapsasAsync());

            exception.StatusCode.Should().Be(500);
        }

        [Fact]
        public async Task ListCapsasAsync_EmptyResponse_ReturnsEmptyArray()
        {
            // Arrange
            var response = new CapsaListResponse
            {
                Capsas = Array.Empty<CapsaSummary>(),
                Pagination = new CursorPagination { Limit = 20, HasMore = false }
            };

            _mockHttp.When(HttpMethod.Get, "*/api/capsas*")
                .Respond("application/json", JsonSerializer.Serialize(response, JsonOptions));

            var service = CreateCapsaService();

            // Act
            var result = await service.ListCapsasAsync();

            // Assert
            result.Capsas.Should().BeEmpty();
        }

        #endregion

        #region DeleteCapsa Tests

        [Fact]
        public async Task DeleteCapsaAsync_WithValidId_Succeeds()
        {
            // Arrange
            var capsaId = TestHelpers.GenerateCapsaId();

            _mockHttp.When(HttpMethod.Delete, $"*/api/capsas/{capsaId}")
                .Respond(HttpStatusCode.NoContent);

            var service = CreateCapsaService();

            // Act & Assert
            await service.Invoking(s => s.DeleteCapsaAsync(capsaId))
                .Should().NotThrowAsync();
        }

        [Fact]
        public async Task DeleteCapsaAsync_WithNonExistentId_ThrowsCapsaNotFound()
        {
            // Arrange
            var capsaId = "pkg_nonexistent";
            var errorResponse = TestHelpers.CreateErrorResponse("CAPSA_NOT_FOUND", "Capsa not found");

            _mockHttp.When(HttpMethod.Delete, $"*/api/capsas/{capsaId}")
                .Respond(HttpStatusCode.NotFound, "application/json", errorResponse);

            var service = CreateCapsaService();

            // Act & Assert
            var exception = await Assert.ThrowsAsync<CapsaraCapsaException>(
                () => service.DeleteCapsaAsync(capsaId));

            exception.Code.Should().Be("CAPSA_NOT_FOUND");
        }

        [Fact]
        public async Task DeleteCapsaAsync_AccessDenied_ThrowsAccessDenied()
        {
            // Arrange
            var capsaId = TestHelpers.GenerateCapsaId();
            var errorResponse = TestHelpers.CreateErrorResponse("ACCESS_DENIED", "Cannot delete this capsa");

            _mockHttp.When(HttpMethod.Delete, $"*/api/capsas/{capsaId}")
                .Respond(HttpStatusCode.Forbidden, "application/json", errorResponse);

            var service = CreateCapsaService();

            // Act & Assert
            var exception = await Assert.ThrowsAsync<CapsaraCapsaException>(
                () => service.DeleteCapsaAsync(capsaId));

            exception.Code.Should().Be("ACCESS_DENIED");
            exception.StatusCode.Should().Be(403);
        }

        [Fact]
        public async Task DeleteCapsaAsync_AlreadyDeleted_ThrowsCapsaDeleted()
        {
            // Arrange
            var capsaId = TestHelpers.GenerateCapsaId();
            var errorResponse = TestHelpers.CreateErrorResponse("CAPSA_DELETED", "Capsa is already deleted");

            _mockHttp.When(HttpMethod.Delete, $"*/api/capsas/{capsaId}")
                .Respond(HttpStatusCode.Forbidden, "application/json", errorResponse);

            var service = CreateCapsaService();

            // Act & Assert
            var exception = await Assert.ThrowsAsync<CapsaraCapsaException>(
                () => service.DeleteCapsaAsync(capsaId));

            exception.Code.Should().Be("CAPSA_DELETED");
        }

        [Fact]
        public async Task DeleteCapsaAsync_NetworkError_ThrowsCapsaraException()
        {
            // Arrange
            var capsaId = TestHelpers.GenerateCapsaId();

            _mockHttp.When(HttpMethod.Delete, $"*/api/capsas/{capsaId}")
                .Throw(new HttpRequestException("Network error"));

            var service = CreateCapsaService();

            // Act & Assert
            var exception = await Assert.ThrowsAsync<CapsaraException>(
                () => service.DeleteCapsaAsync(capsaId));

            exception.Code.Should().Be("NETWORK_ERROR");
        }

        #endregion

        private CapsaService CreateCapsaService()
        {
            return new CapsaService(_httpClient, _keyService);
        }
    }
}
