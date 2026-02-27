using System;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Capsara.SDK.Internal.Services;
using Capsara.SDK.Models;
using Capsara.SDK.Tests.Helpers;
using FluentAssertions;
using RichardSzalay.MockHttp;
using Xunit;

namespace Capsara.SDK.Tests.Services
{
    /// <summary>
    /// Tests for LimitsService usage limits retrieval.
    /// </summary>
    public class LimitsServiceTests : IDisposable
    {
        private readonly MockHttpMessageHandler _mockHttp;
        private readonly HttpClient _httpClient;

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        public LimitsServiceTests()
        {
            _mockHttp = new MockHttpMessageHandler();
            _httpClient = TestHelpers.CreateMockHttpClient(_mockHttp);
        }

        public void Dispose()
        {
            _httpClient.Dispose();
            _mockHttp.Dispose();
        }

        #region GetLimits Tests

        [Fact]
        public async Task GetLimitsAsync_ReturnsLimitsFromServer()
        {
            // Arrange
            var expectedLimits = new SystemLimits
            {
                MaxFileSize = 500 * 1024 * 1024, // 500 MB
                MaxFilesPerCapsa = 50,
                MaxTotalSize = 5L * 1024 * 1024 * 1024 // 5 GB
            };

            _mockHttp.When(HttpMethod.Get, "*/api/limits")
                .Respond("application/json", JsonSerializer.Serialize(expectedLimits, JsonOptions));

            var service = CreateLimitsService();

            // Act
            var result = await service.GetLimitsAsync();

            // Assert
            result.Should().NotBeNull();
            result.MaxFileSize.Should().Be(500 * 1024 * 1024);
            result.MaxFilesPerCapsa.Should().Be(50);
            result.MaxTotalSize.Should().Be(5L * 1024 * 1024 * 1024);
        }

        [Fact]
        public async Task GetLimitsAsync_ServerError_ReturnsDefaultLimits()
        {
            // Arrange
            _mockHttp.When(HttpMethod.Get, "*/api/limits")
                .Respond(HttpStatusCode.InternalServerError);

            var service = CreateLimitsService();

            // Act
            var result = await service.GetLimitsAsync();

            // Assert
            result.Should().NotBeNull();
            result.MaxFileSize.Should().Be(SystemLimits.Default.MaxFileSize);
            result.MaxFilesPerCapsa.Should().Be(SystemLimits.Default.MaxFilesPerCapsa);
            result.MaxTotalSize.Should().Be(SystemLimits.Default.MaxTotalSize);
        }

        [Fact]
        public async Task GetLimitsAsync_NetworkError_ReturnsDefaultLimits()
        {
            // Arrange
            _mockHttp.When(HttpMethod.Get, "*/api/limits")
                .Throw(new HttpRequestException("Network error"));

            var service = CreateLimitsService();

            // Act
            var result = await service.GetLimitsAsync();

            // Assert
            result.Should().NotBeNull();
            result.MaxFileSize.Should().Be(SystemLimits.Default.MaxFileSize);
        }

        [Fact]
        public async Task GetLimitsAsync_NotFoundEndpoint_ReturnsDefaultLimits()
        {
            // Arrange
            _mockHttp.When(HttpMethod.Get, "*/api/limits")
                .Respond(HttpStatusCode.NotFound);

            var service = CreateLimitsService();

            // Act
            var result = await service.GetLimitsAsync();

            // Assert
            result.Should().NotBeNull();
            result.MaxFileSize.Should().Be(SystemLimits.Default.MaxFileSize);
        }

        #endregion

        #region Caching Tests

        [Fact]
        public async Task GetLimitsAsync_CachesResult()
        {
            // Arrange
            var expectedLimits = new SystemLimits
            {
                MaxFileSize = 100 * 1024 * 1024,
                MaxFilesPerCapsa = 25,
                MaxTotalSize = 1L * 1024 * 1024 * 1024
            };

            int requestCount = 0;
            _mockHttp.When(HttpMethod.Get, "*/api/limits")
                .Respond(_ =>
                {
                    requestCount++;
                    return new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(
                            JsonSerializer.Serialize(expectedLimits, JsonOptions),
                            System.Text.Encoding.UTF8,
                            "application/json")
                    };
                });

            var service = CreateLimitsService();

            // Act
            var result1 = await service.GetLimitsAsync();
            var result2 = await service.GetLimitsAsync();
            var result3 = await service.GetLimitsAsync();

            // Assert
            requestCount.Should().Be(1); // Only one request should be made
            result1.MaxFileSize.Should().Be(result2.MaxFileSize);
            result2.MaxFileSize.Should().Be(result3.MaxFileSize);
        }

        [Fact]
        public async Task ClearCache_ForcesNewRequest()
        {
            // Arrange
            var limits1 = new SystemLimits { MaxFileSize = 100 * 1024 * 1024 };
            var limits2 = new SystemLimits { MaxFileSize = 200 * 1024 * 1024 };

            int requestCount = 0;
            _mockHttp.When(HttpMethod.Get, "*/api/limits")
                .Respond(_ =>
                {
                    requestCount++;
                    var limits = requestCount == 1 ? limits1 : limits2;
                    return new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(
                            JsonSerializer.Serialize(limits, JsonOptions),
                            System.Text.Encoding.UTF8,
                            "application/json")
                    };
                });

            var service = CreateLimitsService();

            // Act
            var result1 = await service.GetLimitsAsync();
            service.ClearCache();
            var result2 = await service.GetLimitsAsync();

            // Assert
            requestCount.Should().Be(2);
            result1.MaxFileSize.Should().Be(100 * 1024 * 1024);
            result2.MaxFileSize.Should().Be(200 * 1024 * 1024);
        }

        [Fact]
        public void ClearCache_DoesNotThrow()
        {
            // Arrange
            var service = CreateLimitsService();

            // Act & Assert
            service.Invoking(s => s.ClearCache())
                .Should().NotThrow();
        }

        #endregion

        #region Default Limits Tests

        [Fact]
        public void SystemLimits_Default_HasExpectedValues()
        {
            // Act
            var defaults = SystemLimits.Default;

            // Assert
            defaults.MaxFileSize.Should().Be(1024 * 1024 * 1024); // 1 GB
            defaults.MaxFilesPerCapsa.Should().Be(100);
            defaults.MaxTotalSize.Should().Be(10L * 1024 * 1024 * 1024); // 10 GB
        }

        #endregion

        private LimitsService CreateLimitsService()
        {
            return new LimitsService(_httpClient);
        }
    }
}
