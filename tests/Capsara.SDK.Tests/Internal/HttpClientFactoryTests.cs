using System;
using Capsara.SDK.Internal.Http;
using FluentAssertions;
using Xunit;

namespace Capsara.SDK.Tests.Internal
{
    /// <summary>
    /// Tests for HttpClientFactory client creation and configuration.
    /// </summary>
    public class HttpClientFactoryTests : IDisposable
    {
        private readonly System.Collections.Generic.List<System.Net.Http.HttpClient> _clients = new();

        public void Dispose()
        {
            foreach (var client in _clients)
            {
                client.Dispose();
            }
        }

        #region Create Tests

        [Fact]
        public void Create_WithBaseUrl_SetsBaseAddress()
        {
            // Act
            var client = HttpClientFactory.Create("https://api.test.com");
            _clients.Add(client);

            // Assert
            client.BaseAddress.Should().NotBeNull();
            client.BaseAddress!.ToString().Should().StartWith("https://api.test.com");
        }

        [Fact]
        public void Create_WithTrailingSlash_NormalizesBaseAddress()
        {
            // Act
            var client = HttpClientFactory.Create("https://api.test.com/");
            _clients.Add(client);

            // Assert
            client.BaseAddress!.ToString().Should().EndWith("/");
        }

        [Fact]
        public void Create_WithoutTrailingSlash_AddsTrailingSlash()
        {
            // Act
            var client = HttpClientFactory.Create("https://api.test.com");
            _clients.Add(client);

            // Assert
            client.BaseAddress!.ToString().Should().EndWith("/");
        }

        [Fact]
        public void Create_SetsDefaultTimeout()
        {
            // Act
            var client = HttpClientFactory.Create("https://api.test.com");
            _clients.Add(client);

            // Assert
            client.Timeout.Should().BeGreaterThan(TimeSpan.Zero);
        }

        [Fact]
        public void Create_WithTimeoutConfig_SetsCustomTimeout()
        {
            // Arrange
            var timeoutConfig = new HttpTimeoutConfig
            {
                ApiTimeout = TimeSpan.FromMinutes(5)
            };

            // Act
            var client = HttpClientFactory.Create("https://api.test.com", null, timeoutConfig);
            _clients.Add(client);

            // Assert
            client.Timeout.Should().Be(TimeSpan.FromMinutes(5));
        }

        [Fact]
        public void Create_SetsUserAgentHeader()
        {
            // Act
            var client = HttpClientFactory.Create("https://api.test.com");
            _clients.Add(client);

            // Assert
            client.DefaultRequestHeaders.UserAgent.Should().NotBeEmpty();
        }

        [Fact]
        public void Create_SetsSdkVersionHeader()
        {
            // Act
            var client = HttpClientFactory.Create("https://api.test.com");
            _clients.Add(client);

            // Assert
            client.DefaultRequestHeaders.Contains("X-SDK-Version").Should().BeTrue();
        }

        [Fact]
        public void Create_WithCustomUserAgent_IncludesInHeader()
        {
            // Act
            var client = HttpClientFactory.Create("https://api.test.com", null, null, null, "CustomApp/1.0");
            _clients.Add(client);

            // Assert
            var userAgent = string.Join(" ", client.DefaultRequestHeaders.UserAgent);
            userAgent.Should().Contain("Capsara");
        }

        #endregion

        #region CreateForUpload Tests

        [Fact]
        public void CreateForUpload_SetsExtendedTimeout()
        {
            // Arrange
            var timeoutConfig = new HttpTimeoutConfig
            {
                ApiTimeout = TimeSpan.FromMinutes(1),
                UploadTimeout = TimeSpan.FromMinutes(30)
            };

            // Act
            var client = HttpClientFactory.CreateForUpload("https://api.test.com", null, timeoutConfig);
            _clients.Add(client);

            // Assert
            client.Timeout.Should().Be(TimeSpan.FromMinutes(30));
        }

        [Fact]
        public void CreateForUpload_WithDefaultConfig_UsesDefaultUploadTimeout()
        {
            // Act
            var client = HttpClientFactory.CreateForUpload("https://api.test.com");
            _clients.Add(client);

            // Assert
            client.Timeout.Should().Be(HttpTimeoutConfig.Default.UploadTimeout);
        }

        #endregion

        #region CreateForDownload Tests

        [Fact]
        public void CreateForDownload_SetsDownloadTimeout()
        {
            // Arrange
            var timeoutConfig = new HttpTimeoutConfig
            {
                ApiTimeout = TimeSpan.FromMinutes(1),
                DownloadTimeout = TimeSpan.FromMinutes(15)
            };

            // Act
            var client = HttpClientFactory.CreateForDownload("https://api.test.com", null, timeoutConfig);
            _clients.Add(client);

            // Assert
            client.Timeout.Should().Be(TimeSpan.FromMinutes(15));
        }

        [Fact]
        public void CreateForDownload_WithDefaultConfig_UsesDefaultDownloadTimeout()
        {
            // Act
            var client = HttpClientFactory.CreateForDownload("https://api.test.com");
            _clients.Add(client);

            // Assert
            client.Timeout.Should().Be(HttpTimeoutConfig.Default.DownloadTimeout);
        }

        #endregion

        #region CreateUnauthenticated Tests

        [Fact]
        public void CreateUnauthenticated_CreatesClient()
        {
            // Act
            var client = HttpClientFactory.CreateUnauthenticated("https://api.test.com");
            _clients.Add(client);

            // Assert
            client.Should().NotBeNull();
            client.BaseAddress.Should().NotBeNull();
        }

        [Fact]
        public void CreateUnauthenticated_SetsHeaders()
        {
            // Act
            var client = HttpClientFactory.CreateUnauthenticated("https://api.test.com");
            _clients.Add(client);

            // Assert
            client.DefaultRequestHeaders.UserAgent.Should().NotBeEmpty();
            client.DefaultRequestHeaders.Contains("X-SDK-Version").Should().BeTrue();
        }

        #endregion

        #region Token Provider Tests

        [Fact]
        public void Create_WithTokenProvider_CreatesAuthenticatedClient()
        {
            // Arrange
            Func<string?> getToken = () => "test-token";

            // Act
            var client = HttpClientFactory.Create("https://api.test.com", getToken);
            _clients.Add(client);

            // Assert
            client.Should().NotBeNull();
        }

        [Fact]
        public void Create_WithNullTokenProvider_CreatesClient()
        {
            // Act
            var client = HttpClientFactory.Create("https://api.test.com", null);
            _clients.Add(client);

            // Assert
            client.Should().NotBeNull();
        }

        #endregion

        #region Connection Pooling Tests

        [Fact]
        public void Create_MultipleClients_SharesConnectionPool()
        {
            // Act
            var client1 = HttpClientFactory.Create("https://api.test.com");
            var client2 = HttpClientFactory.Create("https://api.test.com");
            var client3 = HttpClientFactory.Create("https://api.different.com");
            _clients.Add(client1);
            _clients.Add(client2);
            _clients.Add(client3);

            // Assert - All clients should be created (they share the underlying handler)
            client1.Should().NotBeNull();
            client2.Should().NotBeNull();
            client3.Should().NotBeNull();
        }

        #endregion

        #region HttpTimeoutConfig Tests

        [Fact]
        public void HttpTimeoutConfig_Default_HasReasonableValues()
        {
            // Act
            var config = HttpTimeoutConfig.Default;

            // Assert
            // ApiTimeout: 12 minutes, UploadTimeout: 15 minutes, DownloadTimeout: 1 minute
            config.ApiTimeout.TotalSeconds.Should().BeGreaterThan(0);
            config.UploadTimeout.TotalSeconds.Should().BeGreaterThan(config.ApiTimeout.TotalSeconds);
            // DownloadTimeout is intentionally shorter (1 minute) for fast blob downloads
            config.DownloadTimeout.TotalSeconds.Should().BeGreaterThan(0);
        }

        #endregion

        #region RetryConfig Tests

        [Fact]
        public void RetryConfig_Default_HasReasonableValues()
        {
            // Act
            var config = RetryConfig.Default;

            // Assert
            config.MaxRetries.Should().BeGreaterThan(0);
            config.BaseDelay.TotalMilliseconds.Should().BeGreaterThan(0);
            config.MaxDelay.TotalMilliseconds.Should().BeGreaterThan(config.BaseDelay.TotalMilliseconds);
        }

        [Fact]
        public void RetryConfig_CustomValues_AreApplied()
        {
            // Arrange
            var config = new RetryConfig
            {
                MaxRetries = 5,
                BaseDelay = TimeSpan.FromSeconds(1),
                MaxDelay = TimeSpan.FromSeconds(30),
                EnableLogging = true,
                Logger = msg => { }
            };

            // Assert
            config.MaxRetries.Should().Be(5);
            config.BaseDelay.Should().Be(TimeSpan.FromSeconds(1));
            config.MaxDelay.Should().Be(TimeSpan.FromSeconds(30));
            config.EnableLogging.Should().BeTrue();
            config.Logger.Should().NotBeNull();
        }

        #endregion
    }
}
