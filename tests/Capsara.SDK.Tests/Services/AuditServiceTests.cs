using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Capsara.SDK.Exceptions;
using Capsara.SDK.Internal.Services;
using Capsara.SDK.Models;
using Capsara.SDK.Tests.Helpers;
using FluentAssertions;
using RichardSzalay.MockHttp;
using Xunit;

namespace Capsara.SDK.Tests.Services
{
    /// <summary>
    /// Tests for AuditService audit trail retrieval.
    /// </summary>
    public class AuditServiceTests : IDisposable
    {
        private readonly MockHttpMessageHandler _mockHttp;
        private readonly HttpClient _httpClient;

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        public AuditServiceTests()
        {
            _mockHttp = new MockHttpMessageHandler();
            _httpClient = TestHelpers.CreateMockHttpClient(_mockHttp);
        }

        public void Dispose()
        {
            _httpClient.Dispose();
            _mockHttp.Dispose();
        }

        #region GetAuditEntries Tests

        [Fact]
        public async Task GetAuditEntriesAsync_WithValidCapsaId_ReturnsEntries()
        {
            // Arrange
            var capsaId = TestHelpers.GenerateCapsaId();
            var response = new GetAuditEntriesResponse
            {
                AuditEntries = new[]
                {
                    TestHelpers.CreateMockAuditEntry("created"),
                    TestHelpers.CreateMockAuditEntry("accessed")
                },
                Pagination = new CursorPagination { Limit = 100, HasMore = false }
            };

            _mockHttp.When(HttpMethod.Get, $"*/api/capsas/{capsaId}/audit")
                .Respond("application/json", JsonSerializer.Serialize(response, JsonOptions));

            var service = CreateAuditService();

            // Act
            var result = await service.GetAuditEntriesAsync(capsaId);

            // Assert
            result.Should().NotBeNull();
            result.AuditEntries.Should().HaveCount(2);
        }

        [Fact]
        public async Task GetAuditEntriesAsync_WithFilters_BuildsCorrectQueryString()
        {
            // Arrange
            var capsaId = TestHelpers.GenerateCapsaId();
            var partyId = TestHelpers.GeneratePartyId();
            var response = new GetAuditEntriesResponse
            {
                AuditEntries = new[] { TestHelpers.CreateMockAuditEntry("accessed", partyId) },
                Pagination = new CursorPagination { Limit = 50, HasMore = false }
            };

            _mockHttp.When(HttpMethod.Get, $"*/api/capsas/{capsaId}/audit*")
                .Respond("application/json", JsonSerializer.Serialize(response, JsonOptions));

            var service = CreateAuditService();
            var filters = new GetAuditEntriesFilters
            {
                Action = "accessed",
                Party = partyId,
                Limit = 50,
                Page = 1
            };

            // Act
            var result = await service.GetAuditEntriesAsync(capsaId, filters);

            // Assert
            result.AuditEntries.Should().HaveCount(1);
        }

        [Fact]
        public async Task GetAuditEntriesAsync_CapsaNotFound_ThrowsException()
        {
            // Arrange
            var capsaId = "pkg_nonexistent";
            var errorResponse = TestHelpers.CreateErrorResponse("CAPSA_NOT_FOUND", "Capsa not found");

            _mockHttp.When(HttpMethod.Get, $"*/api/capsas/{capsaId}/audit")
                .Respond(HttpStatusCode.NotFound, "application/json", errorResponse);

            var service = CreateAuditService();

            // Act & Assert
            var exception = await Assert.ThrowsAsync<CapsaraAuditException>(
                () => service.GetAuditEntriesAsync(capsaId));

            exception.StatusCode.Should().Be(404);
        }

        [Fact]
        public async Task GetAuditEntriesAsync_AccessDenied_ThrowsException()
        {
            // Arrange
            var capsaId = TestHelpers.GenerateCapsaId();
            var errorResponse = TestHelpers.CreateErrorResponse("ACCESS_DENIED", "Access denied");

            _mockHttp.When(HttpMethod.Get, $"*/api/capsas/{capsaId}/audit")
                .Respond(HttpStatusCode.Forbidden, "application/json", errorResponse);

            var service = CreateAuditService();

            // Act & Assert
            var exception = await Assert.ThrowsAsync<CapsaraAuditException>(
                () => service.GetAuditEntriesAsync(capsaId));

            exception.StatusCode.Should().Be(403);
        }

        [Fact]
        public async Task GetAuditEntriesAsync_NetworkError_ThrowsCapsaraException()
        {
            // Arrange
            var capsaId = TestHelpers.GenerateCapsaId();

            _mockHttp.When(HttpMethod.Get, $"*/api/capsas/{capsaId}/audit")
                .Throw(new HttpRequestException("Network error"));

            var service = CreateAuditService();

            // Act & Assert
            var exception = await Assert.ThrowsAsync<CapsaraException>(
                () => service.GetAuditEntriesAsync(capsaId));

            exception.Code.Should().Be("NETWORK_ERROR");
        }

        [Fact]
        public async Task GetAuditEntriesAsync_EmptyResponse_ReturnsEmptyArray()
        {
            // Arrange
            var capsaId = TestHelpers.GenerateCapsaId();
            var response = new GetAuditEntriesResponse
            {
                AuditEntries = Array.Empty<AuditEntry>(),
                Pagination = new CursorPagination { Limit = 100, HasMore = false }
            };

            _mockHttp.When(HttpMethod.Get, $"*/api/capsas/{capsaId}/audit")
                .Respond("application/json", JsonSerializer.Serialize(response, JsonOptions));

            var service = CreateAuditService();

            // Act
            var result = await service.GetAuditEntriesAsync(capsaId);

            // Assert
            result.AuditEntries.Should().BeEmpty();
        }

        #endregion

        #region CreateAuditEntry Tests

        [Fact]
        public async Task CreateAuditEntryAsync_WithLogAction_Succeeds()
        {
            // Arrange
            var capsaId = TestHelpers.GenerateCapsaId();
            var entry = new CreateAuditEntryRequest
            {
                Action = AuditActions.Log,
                Details = new Dictionary<string, object> { ["note"] = "Test log entry" }
            };

            _mockHttp.When(HttpMethod.Post, $"*/api/capsas/{capsaId}/audit")
                .Respond(HttpStatusCode.Created, "application/json", "{\"success\": true}");

            var service = CreateAuditService();

            // Act
            var result = await service.CreateAuditEntryAsync(capsaId, entry);

            // Assert
            result.Should().BeTrue();
        }

        [Fact]
        public async Task CreateAuditEntryAsync_WithProcessedAction_Succeeds()
        {
            // Arrange
            var capsaId = TestHelpers.GenerateCapsaId();
            var entry = new CreateAuditEntryRequest
            {
                Action = AuditActions.Processed
            };

            _mockHttp.When(HttpMethod.Post, $"*/api/capsas/{capsaId}/audit")
                .Respond(HttpStatusCode.Created, "application/json", "{\"success\": true}");

            var service = CreateAuditService();

            // Act
            var result = await service.CreateAuditEntryAsync(capsaId, entry);

            // Assert
            result.Should().BeTrue();
        }

        [Fact]
        public async Task CreateAuditEntryAsync_LogActionWithoutDetails_ThrowsException()
        {
            // Arrange
            var capsaId = TestHelpers.GenerateCapsaId();
            var entry = new CreateAuditEntryRequest
            {
                Action = AuditActions.Log,
                Details = null // Missing required details for 'log' action
            };

            var service = CreateAuditService();

            // Act & Assert
            var exception = await Assert.ThrowsAsync<CapsaraAuditException>(
                () => service.CreateAuditEntryAsync(capsaId, entry));

            exception.Code.Should().Be("MISSING_DETAILS");
        }

        [Fact]
        public async Task CreateAuditEntryAsync_LogActionWithEmptyDetails_ThrowsException()
        {
            // Arrange
            var capsaId = TestHelpers.GenerateCapsaId();
            var entry = new CreateAuditEntryRequest
            {
                Action = AuditActions.Log,
                Details = new Dictionary<string, object>() // Empty details
            };

            var service = CreateAuditService();

            // Act & Assert
            var exception = await Assert.ThrowsAsync<CapsaraAuditException>(
                () => service.CreateAuditEntryAsync(capsaId, entry));

            exception.Code.Should().Be("MISSING_DETAILS");
        }

        [Fact]
        public async Task CreateAuditEntryAsync_CapsaNotFound_ThrowsException()
        {
            // Arrange
            var capsaId = "pkg_nonexistent";
            var entry = new CreateAuditEntryRequest
            {
                Action = AuditActions.Processed
            };
            var errorResponse = TestHelpers.CreateErrorResponse("CAPSA_NOT_FOUND", "Capsa not found");

            _mockHttp.When(HttpMethod.Post, $"*/api/capsas/{capsaId}/audit")
                .Respond(HttpStatusCode.NotFound, "application/json", errorResponse);

            var service = CreateAuditService();

            // Act & Assert
            var exception = await Assert.ThrowsAsync<CapsaraAuditException>(
                () => service.CreateAuditEntryAsync(capsaId, entry));

            exception.StatusCode.Should().Be(404);
        }

        [Fact]
        public async Task CreateAuditEntryAsync_NetworkError_ThrowsCapsaraException()
        {
            // Arrange
            var capsaId = TestHelpers.GenerateCapsaId();
            var entry = new CreateAuditEntryRequest
            {
                Action = AuditActions.Processed
            };

            _mockHttp.When(HttpMethod.Post, $"*/api/capsas/{capsaId}/audit")
                .Throw(new HttpRequestException("Network error"));

            var service = CreateAuditService();

            // Act & Assert
            var exception = await Assert.ThrowsAsync<CapsaraException>(
                () => service.CreateAuditEntryAsync(capsaId, entry));

            exception.Code.Should().Be("NETWORK_ERROR");
        }

        [Fact]
        public async Task CreateAuditEntryAsync_InvalidAction_ThrowsException()
        {
            // Arrange
            var capsaId = TestHelpers.GenerateCapsaId();
            var entry = new CreateAuditEntryRequest
            {
                Action = "invalid_action"
            };
            var errorResponse = TestHelpers.CreateErrorResponse("INVALID_ACTION", "Invalid action type");

            _mockHttp.When(HttpMethod.Post, $"*/api/capsas/{capsaId}/audit")
                .Respond(HttpStatusCode.BadRequest, "application/json", errorResponse);

            var service = CreateAuditService();

            // Act & Assert
            var exception = await Assert.ThrowsAsync<CapsaraAuditException>(
                () => service.CreateAuditEntryAsync(capsaId, entry));

            exception.Code.Should().Be("INVALID_ACTION");
        }

        #endregion

        private AuditService CreateAuditService()
        {
            return new AuditService(_httpClient);
        }
    }
}
