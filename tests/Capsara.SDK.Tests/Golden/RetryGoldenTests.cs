using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Capsara.SDK.Internal.Http;
using Capsara.SDK.Tests.Helpers;
using FluentAssertions;
using Xunit;

namespace Capsara.SDK.Tests.Golden
{
    /// <summary>
    /// Golden tests for retry handler: configuration, backoff calculation, and retry behavior.
    /// </summary>
    public class RetryGoldenTests
    {
        #region Configuration Tests

        [Fact]
        public void RetryConfig_Default_HasCorrectValues()
        {
            // Act
            var config = RetryConfig.Default;

            // Assert
            config.MaxRetries.Should().Be(3);
            config.BaseDelay.Should().Be(TimeSpan.FromSeconds(1));
            config.MaxDelay.Should().Be(TimeSpan.FromSeconds(30));
            config.EnableLogging.Should().BeFalse();
            config.Logger.Should().BeNull();
        }

        [Fact]
        public void RetryConfig_NoRetry_HasZeroRetries()
        {
            // Act
            var config = RetryConfig.NoRetry;

            // Assert
            config.MaxRetries.Should().Be(0);
        }

        [Fact]
        public void RetryConfig_CustomValues_AreRespected()
        {
            // Arrange & Act
            var config = new RetryConfig
            {
                MaxRetries = 5,
                BaseDelay = TimeSpan.FromMilliseconds(500),
                MaxDelay = TimeSpan.FromSeconds(60),
                EnableLogging = true,
                Logger = msg => { }
            };

            // Assert
            config.MaxRetries.Should().Be(5);
            config.BaseDelay.Should().Be(TimeSpan.FromMilliseconds(500));
            config.MaxDelay.Should().Be(TimeSpan.FromSeconds(60));
            config.EnableLogging.Should().BeTrue();
            config.Logger.Should().NotBeNull();
        }

        #endregion

        #region Retry Behavior Tests

        [Fact]
        public async Task RetryHandler_NonRetryableStatus_DoesNotRetry()
        {
            // Arrange
            var mockHandler = new MockRetryHandler();
            mockHandler.AddResponse(HttpStatusCode.BadRequest);

            var retryHandler = new RetryHandler(mockHandler, new RetryConfig { MaxRetries = 3 });
            using var client = new HttpClient(retryHandler);

            // Act
            var response = await client.GetAsync("https://api.test.com/test");

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
            mockHandler.RequestCount.Should().Be(1, "Should not retry 400 errors");
        }

        [Fact]
        public async Task RetryHandler_503_RetriesUpToMax()
        {
            // Arrange
            var mockHandler = new MockRetryHandler();
            mockHandler.AddResponse(HttpStatusCode.ServiceUnavailable);
            mockHandler.AddResponse(HttpStatusCode.ServiceUnavailable);
            mockHandler.AddResponse(HttpStatusCode.OK);

            var config = new RetryConfig
            {
                MaxRetries = 3,
                BaseDelay = TimeSpan.FromMilliseconds(10), // Fast for testing
                MaxDelay = TimeSpan.FromMilliseconds(100)
            };

            var retryHandler = new RetryHandler(mockHandler, config);
            using var client = new HttpClient(retryHandler);

            // Act
            var response = await client.GetAsync("https://api.test.com/test");

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            mockHandler.RequestCount.Should().Be(3);
        }

        [Fact]
        public async Task RetryHandler_429_Retries()
        {
            // Arrange
            var mockHandler = new MockRetryHandler();
            mockHandler.AddResponse((HttpStatusCode)429); // Too Many Requests
            mockHandler.AddResponse(HttpStatusCode.OK);

            var config = new RetryConfig
            {
                MaxRetries = 3,
                BaseDelay = TimeSpan.FromMilliseconds(10),
                MaxDelay = TimeSpan.FromMilliseconds(100)
            };

            var retryHandler = new RetryHandler(mockHandler, config);
            using var client = new HttpClient(retryHandler);

            // Act
            var response = await client.GetAsync("https://api.test.com/test");

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            mockHandler.RequestCount.Should().Be(2);
        }

        [Fact]
        public async Task RetryHandler_MaxRetriesExhausted_ReturnsLastResponse()
        {
            // Arrange
            var mockHandler = new MockRetryHandler();
            mockHandler.AddResponse(HttpStatusCode.ServiceUnavailable);
            mockHandler.AddResponse(HttpStatusCode.ServiceUnavailable);
            mockHandler.AddResponse(HttpStatusCode.ServiceUnavailable);
            mockHandler.AddResponse(HttpStatusCode.ServiceUnavailable); // Beyond max retries

            var config = new RetryConfig
            {
                MaxRetries = 2,
                BaseDelay = TimeSpan.FromMilliseconds(10),
                MaxDelay = TimeSpan.FromMilliseconds(50)
            };

            var retryHandler = new RetryHandler(mockHandler, config);
            using var client = new HttpClient(retryHandler);

            // Act
            var response = await client.GetAsync("https://api.test.com/test");

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable);
            mockHandler.RequestCount.Should().Be(3); // 1 initial + 2 retries
        }

        [Fact]
        public async Task RetryHandler_NoRetryConfig_DoesNotRetry()
        {
            // Arrange
            var mockHandler = new MockRetryHandler();
            mockHandler.AddResponse(HttpStatusCode.ServiceUnavailable);

            var retryHandler = new RetryHandler(mockHandler, RetryConfig.NoRetry);
            using var client = new HttpClient(retryHandler);

            // Act
            var response = await client.GetAsync("https://api.test.com/test");

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable);
            mockHandler.RequestCount.Should().Be(1);
        }

        #endregion
    }
}
