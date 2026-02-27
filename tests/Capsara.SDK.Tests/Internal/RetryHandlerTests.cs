using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Capsara.SDK.Internal.Http;
using Capsara.SDK.Tests.Helpers;
using FluentAssertions;
using Xunit;

namespace Capsara.SDK.Tests.Internal
{
    /// <summary>
    /// Tests for RetryHandler HTTP retry logic with exponential backoff.
    /// </summary>
    public class RetryHandlerTests
    {
        #region Successful Request Tests

        [Fact]
        public async Task SendAsync_SuccessfulRequest_ReturnsResponse()
        {
            // Arrange
            var mockHandler = new MockRetryHandler();
            mockHandler.AddResponse(HttpStatusCode.OK, "{\"data\": \"test\"}");

            var retryHandler = new RetryHandler(mockHandler, new RetryConfig { MaxRetries = 3 });
            var client = new HttpClient(retryHandler);

            // Act
            var response = await client.GetAsync("https://api.test.com/test");

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            mockHandler.RequestCount.Should().Be(1);
        }

        [Fact]
        public async Task SendAsync_NonRetryableError_DoesNotRetry()
        {
            // Arrange
            var mockHandler = new MockRetryHandler();
            mockHandler.AddResponse(HttpStatusCode.BadRequest, "{\"error\": \"bad request\"}");

            var retryHandler = new RetryHandler(mockHandler, new RetryConfig { MaxRetries = 3 });
            var client = new HttpClient(retryHandler);

            // Act
            var response = await client.GetAsync("https://api.test.com/test");

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
            mockHandler.RequestCount.Should().Be(1); // No retries
        }

        #endregion

        #region Retry on 503 Tests

        [Fact]
        public async Task SendAsync_503ThenSuccess_Retries()
        {
            // Arrange
            var mockHandler = new MockRetryHandler();
            mockHandler.AddResponse(HttpStatusCode.ServiceUnavailable);
            mockHandler.AddResponse(HttpStatusCode.OK, "{\"data\": \"test\"}");

            var retryHandler = new RetryHandler(mockHandler, new RetryConfig
            {
                MaxRetries = 3,
                BaseDelay = TimeSpan.FromMilliseconds(10),
                MaxDelay = TimeSpan.FromMilliseconds(100)
            });
            var client = new HttpClient(retryHandler);

            // Act
            var response = await client.GetAsync("https://api.test.com/test");

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            mockHandler.RequestCount.Should().Be(2);
        }

        [Fact]
        public async Task SendAsync_503Multiple_RetriesUntilSuccess()
        {
            // Arrange
            var mockHandler = new MockRetryHandler();
            mockHandler.AddResponse(HttpStatusCode.ServiceUnavailable);
            mockHandler.AddResponse(HttpStatusCode.ServiceUnavailable);
            mockHandler.AddResponse(HttpStatusCode.OK, "{\"data\": \"test\"}");

            var retryHandler = new RetryHandler(mockHandler, new RetryConfig
            {
                MaxRetries = 3,
                BaseDelay = TimeSpan.FromMilliseconds(10),
                MaxDelay = TimeSpan.FromMilliseconds(100)
            });
            var client = new HttpClient(retryHandler);

            // Act
            var response = await client.GetAsync("https://api.test.com/test");

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            mockHandler.RequestCount.Should().Be(3);
        }

        [Fact]
        public async Task SendAsync_503ExceedsMaxRetries_Returns503()
        {
            // Arrange
            var mockHandler = new MockRetryHandler();
            mockHandler.AddResponse(HttpStatusCode.ServiceUnavailable);
            mockHandler.AddResponse(HttpStatusCode.ServiceUnavailable);
            mockHandler.AddResponse(HttpStatusCode.ServiceUnavailable);
            mockHandler.AddResponse(HttpStatusCode.ServiceUnavailable);

            var retryHandler = new RetryHandler(mockHandler, new RetryConfig
            {
                MaxRetries = 3,
                BaseDelay = TimeSpan.FromMilliseconds(10),
                MaxDelay = TimeSpan.FromMilliseconds(100)
            });
            var client = new HttpClient(retryHandler);

            // Act
            var response = await client.GetAsync("https://api.test.com/test");

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable);
            mockHandler.RequestCount.Should().Be(4); // 1 initial + 3 retries
        }

        #endregion

        #region Retry on 429 Tests

        [Fact]
        public async Task SendAsync_429ThenSuccess_Retries()
        {
            // Arrange
            var mockHandler = new MockRetryHandler();
            mockHandler.AddResponse((HttpStatusCode)429);
            mockHandler.AddResponse(HttpStatusCode.OK, "{\"data\": \"test\"}");

            var retryHandler = new RetryHandler(mockHandler, new RetryConfig
            {
                MaxRetries = 3,
                BaseDelay = TimeSpan.FromMilliseconds(10),
                MaxDelay = TimeSpan.FromMilliseconds(100)
            });
            var client = new HttpClient(retryHandler);

            // Act
            var response = await client.GetAsync("https://api.test.com/test");

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            mockHandler.RequestCount.Should().Be(2);
        }

        [Fact]
        public async Task SendAsync_429WithRetryAfterHeader_UsesServerDelay()
        {
            // Arrange
            var mockHandler = new MockRetryHandler();
            mockHandler.AddResponse(req =>
            {
                var response = new HttpResponseMessage((HttpStatusCode)429);
                response.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromSeconds(1));
                // Must set Content to avoid null reference in RetryHandler.GetServerSuggestedDelayAsync
                response.Content = new StringContent("", System.Text.Encoding.UTF8, "application/json");
                return response;
            });
            mockHandler.AddResponse(HttpStatusCode.OK);

            var retryHandler = new RetryHandler(mockHandler, new RetryConfig
            {
                MaxRetries = 3,
                BaseDelay = TimeSpan.FromMilliseconds(10),
                MaxDelay = TimeSpan.FromSeconds(5)
            });
            var client = new HttpClient(retryHandler);

            // Act
            var startTime = DateTime.UtcNow;
            var response = await client.GetAsync("https://api.test.com/test");
            var elapsed = DateTime.UtcNow - startTime;

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            mockHandler.RequestCount.Should().Be(2);
            // Should have waited at least close to 1 second (with some tolerance)
            elapsed.TotalMilliseconds.Should().BeGreaterThan(800);
        }

        #endregion

        #region Network Error Tests

        [Fact]
        public async Task SendAsync_NetworkErrorThenSuccess_Retries()
        {
            // Arrange
            var mockHandler = new MockRetryHandler();
            mockHandler.AddException(new HttpRequestException("Network error"));
            mockHandler.AddResponse(HttpStatusCode.OK, "{\"data\": \"test\"}");

            var retryHandler = new RetryHandler(mockHandler, new RetryConfig
            {
                MaxRetries = 3,
                BaseDelay = TimeSpan.FromMilliseconds(10),
                MaxDelay = TimeSpan.FromMilliseconds(100)
            });
            var client = new HttpClient(retryHandler);

            // Act
            var response = await client.GetAsync("https://api.test.com/test");

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            mockHandler.RequestCount.Should().Be(2);
        }

        [Fact]
        public async Task SendAsync_NetworkErrorExceedsRetries_Throws()
        {
            // Arrange
            var mockHandler = new MockRetryHandler();
            mockHandler.AddException(new HttpRequestException("Network error"));
            mockHandler.AddException(new HttpRequestException("Network error"));
            mockHandler.AddException(new HttpRequestException("Network error"));
            mockHandler.AddException(new HttpRequestException("Network error"));

            var retryHandler = new RetryHandler(mockHandler, new RetryConfig
            {
                MaxRetries = 3,
                BaseDelay = TimeSpan.FromMilliseconds(10),
                MaxDelay = TimeSpan.FromMilliseconds(100)
            });
            var client = new HttpClient(retryHandler);

            // Act & Assert
            await Assert.ThrowsAsync<HttpRequestException>(
                () => client.GetAsync("https://api.test.com/test"));

            mockHandler.RequestCount.Should().Be(4); // 1 initial + 3 retries
        }

        #endregion

        #region Exponential Backoff Tests

        [Fact]
        public async Task SendAsync_UsesExponentialBackoff()
        {
            // Arrange
            var mockHandler = new MockRetryHandler();
            mockHandler.AddResponse(HttpStatusCode.ServiceUnavailable);
            mockHandler.AddResponse(HttpStatusCode.ServiceUnavailable);
            mockHandler.AddResponse(HttpStatusCode.OK);

            var retryHandler = new RetryHandler(mockHandler, new RetryConfig
            {
                MaxRetries = 3,
                BaseDelay = TimeSpan.FromMilliseconds(100),
                MaxDelay = TimeSpan.FromSeconds(10)
            });
            var client = new HttpClient(retryHandler);

            // Act
            var startTime = DateTime.UtcNow;
            var response = await client.GetAsync("https://api.test.com/test");
            var elapsed = DateTime.UtcNow - startTime;

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            // First retry: ~100ms, Second retry: ~200ms
            // Total should be at least 200ms+ (with jitter)
            elapsed.TotalMilliseconds.Should().BeGreaterThan(200);
        }

        #endregion

        #region Max Delay Tests

        [Fact]
        public async Task SendAsync_RespectsMaxDelay()
        {
            // Arrange
            var mockHandler = new MockRetryHandler();
            mockHandler.AddResponse(HttpStatusCode.ServiceUnavailable);
            mockHandler.AddResponse(HttpStatusCode.ServiceUnavailable);
            mockHandler.AddResponse(HttpStatusCode.ServiceUnavailable);
            mockHandler.AddResponse(HttpStatusCode.OK);

            var retryHandler = new RetryHandler(mockHandler, new RetryConfig
            {
                MaxRetries = 5,
                BaseDelay = TimeSpan.FromSeconds(10), // Very long base delay
                MaxDelay = TimeSpan.FromMilliseconds(50) // But capped at 50ms
            });
            var client = new HttpClient(retryHandler);

            // Act
            var startTime = DateTime.UtcNow;
            var response = await client.GetAsync("https://api.test.com/test");
            var elapsed = DateTime.UtcNow - startTime;

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            // Even with a 10s base delay, max delay of 50ms means total should be reasonable
            // Using 1000ms threshold to account for system scheduling variance on slow machines
            elapsed.TotalMilliseconds.Should().BeLessThan(1000);
        }

        #endregion

        #region Cancellation Tests

        [Fact]
        public async Task SendAsync_CancellationRequested_ThrowsOperationCanceled()
        {
            // Arrange
            var mockHandler = new MockRetryHandler();
            mockHandler.AddResponse(HttpStatusCode.ServiceUnavailable);

            var retryHandler = new RetryHandler(mockHandler, new RetryConfig
            {
                MaxRetries = 3,
                BaseDelay = TimeSpan.FromSeconds(10) // Long delay to allow cancellation
            });
            var client = new HttpClient(retryHandler);

            var cts = new CancellationTokenSource();
            cts.CancelAfter(50); // Cancel quickly

            // Act & Assert
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => client.GetAsync("https://api.test.com/test", cts.Token));
        }

        #endregion

        #region Non-Retryable Status Codes Tests

        [Theory]
        [InlineData(HttpStatusCode.BadRequest)]
        [InlineData(HttpStatusCode.Unauthorized)]
        [InlineData(HttpStatusCode.Forbidden)]
        [InlineData(HttpStatusCode.NotFound)]
        [InlineData(HttpStatusCode.InternalServerError)]
        public async Task SendAsync_NonRetryableStatusCode_DoesNotRetry(HttpStatusCode statusCode)
        {
            // Arrange
            var mockHandler = new MockRetryHandler();
            mockHandler.AddResponse(statusCode);

            var retryHandler = new RetryHandler(mockHandler, new RetryConfig { MaxRetries = 3 });
            var client = new HttpClient(retryHandler);

            // Act
            var response = await client.GetAsync("https://api.test.com/test");

            // Assert
            response.StatusCode.Should().Be(statusCode);
            mockHandler.RequestCount.Should().Be(1);
        }

        #endregion

        #region Server Suggested Delay Tests

        [Fact]
        public async Task SendAsync_ServerSuggestedRetryAfter_UsesServerDelay()
        {
            // Arrange
            var mockHandler = new MockRetryHandler();
            mockHandler.AddResponse(HttpStatusCode.ServiceUnavailable,
                "{\"error\": {\"retryAfter\": 1}}"); // 1 second delay
            mockHandler.AddResponse(HttpStatusCode.OK);

            var retryHandler = new RetryHandler(mockHandler, new RetryConfig
            {
                MaxRetries = 3,
                BaseDelay = TimeSpan.FromMilliseconds(10),
                MaxDelay = TimeSpan.FromSeconds(5)
            });
            var client = new HttpClient(retryHandler);

            // Act
            var startTime = DateTime.UtcNow;
            var response = await client.GetAsync("https://api.test.com/test");
            var elapsed = DateTime.UtcNow - startTime;

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            // Should have waited at least close to 1 second
            elapsed.TotalMilliseconds.Should().BeGreaterThan(800);
        }

        [Fact]
        public async Task SendAsync_ServerSuggestedDelayExceedsMax_UsesMaxDelay()
        {
            // Arrange
            var mockHandler = new MockRetryHandler();
            mockHandler.AddResponse(HttpStatusCode.ServiceUnavailable,
                "{\"error\": {\"retryAfter\": 60}}"); // 60 second delay
            mockHandler.AddResponse(HttpStatusCode.OK);

            var retryHandler = new RetryHandler(mockHandler, new RetryConfig
            {
                MaxRetries = 3,
                BaseDelay = TimeSpan.FromMilliseconds(10),
                MaxDelay = TimeSpan.FromMilliseconds(100) // Cap at 100ms
            });
            var client = new HttpClient(retryHandler);

            // Act
            var startTime = DateTime.UtcNow;
            var response = await client.GetAsync("https://api.test.com/test");
            var elapsed = DateTime.UtcNow - startTime;

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            // Should have capped at ~100ms, not 60 seconds
            elapsed.TotalMilliseconds.Should().BeLessThan(500);
        }

        #endregion

        #region Default Config Tests

        [Fact]
        public void RetryConfig_Default_HasExpectedValues()
        {
            // Act
            var config = RetryConfig.Default;

            // Assert
            config.MaxRetries.Should().BeGreaterThan(0);
            config.BaseDelay.TotalMilliseconds.Should().BeGreaterThan(0);
            config.MaxDelay.TotalMilliseconds.Should().BeGreaterThan(config.BaseDelay.TotalMilliseconds);
        }

        #endregion
    }
}
