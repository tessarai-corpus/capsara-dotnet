using System;
using System.Net;
using System.Net.Http;

namespace Capsara.SDK.Internal.Http
{
    /// <summary>Creates configured HttpClient instances with shared connection pooling.</summary>
    internal static class HttpClientFactory
    {
        private static readonly Lazy<HttpMessageHandler> SharedHandler = new(() => CreateSharedHandler());

        private static HttpMessageHandler CreateSharedHandler()
        {
#if NET6_0_OR_GREATER
            return new SocketsHttpHandler
            {
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
                PooledConnectionLifetime = TimeSpan.FromMinutes(15),
                PooledConnectionIdleTimeout = TimeSpan.FromMinutes(2),
                MaxConnectionsPerServer = 50,
                EnableMultipleHttp2Connections = true,
                KeepAlivePingPolicy = HttpKeepAlivePingPolicy.WithActiveRequests,
                KeepAlivePingDelay = TimeSpan.FromSeconds(30),
                KeepAlivePingTimeout = TimeSpan.FromSeconds(10),
                ConnectTimeout = TimeSpan.FromSeconds(30),
            };
#else
            return new HttpClientHandler
            {
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
                MaxConnectionsPerServer = 50,
            };
#endif
        }

        public static HttpClient Create(
            string baseUrl,
            Func<string?>? getToken = null,
            HttpTimeoutConfig? timeoutConfig = null,
            RetryConfig? retryConfig = null,
            string? userAgent = null)
        {
            var timeout = timeoutConfig ?? HttpTimeoutConfig.Default;
            var retry = retryConfig ?? RetryConfig.Default;

            // Handler pipeline: RetryHandler -> AuthHandler -> SharedHandler
            HttpMessageHandler handler = SharedHandler.Value;

            if (getToken != null)
            {
                handler = new AuthHandler(handler, getToken);
            }

            handler = new RetryHandler(handler, retry);

            // disposeHandler: false preserves shared handler across client lifetimes
            var client = new HttpClient(handler, disposeHandler: false)
            {
                BaseAddress = new Uri(baseUrl.TrimEnd('/') + "/"),
                Timeout = timeout.ApiTimeout
            };

            client.DefaultRequestHeaders.Add("User-Agent", SdkVersion.BuildUserAgent(userAgent));
            client.DefaultRequestHeaders.Add("X-SDK-Version", SdkVersion.Version);

            return client;
        }

        public static HttpClient CreateForUpload(
            string baseUrl,
            Func<string?>? getToken = null,
            HttpTimeoutConfig? timeoutConfig = null,
            RetryConfig? retryConfig = null,
            string? userAgent = null)
        {
            var timeout = timeoutConfig ?? HttpTimeoutConfig.Default;
            var client = Create(baseUrl, getToken, timeoutConfig, retryConfig, userAgent);
            client.Timeout = timeout.UploadTimeout;
            return client;
        }

        public static HttpClient CreateForDownload(
            string baseUrl,
            Func<string?>? getToken = null,
            HttpTimeoutConfig? timeoutConfig = null,
            RetryConfig? retryConfig = null,
            string? userAgent = null)
        {
            var timeout = timeoutConfig ?? HttpTimeoutConfig.Default;
            var client = Create(baseUrl, getToken, timeoutConfig, retryConfig, userAgent);
            client.Timeout = timeout.DownloadTimeout;
            return client;
        }

        public static HttpClient CreateUnauthenticated(
            string baseUrl,
            HttpTimeoutConfig? timeoutConfig = null,
            RetryConfig? retryConfig = null,
            string? userAgent = null)
        {
            return Create(baseUrl, null, timeoutConfig, retryConfig, userAgent);
        }

        /// <summary>For blob storage downloads. No auth (SAS URLs) or retry (storage-level retry).</summary>
        public static HttpClient CreateForBlob(HttpTimeoutConfig? timeoutConfig = null)
        {
            var timeout = timeoutConfig ?? HttpTimeoutConfig.Default;

            var client = new HttpClient(SharedHandler.Value, disposeHandler: false)
            {
                Timeout = timeout.DownloadTimeout
            };

            return client;
        }
    }
}
