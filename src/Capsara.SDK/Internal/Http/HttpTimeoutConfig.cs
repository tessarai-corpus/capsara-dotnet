using System;

namespace Capsara.SDK.Internal.Http
{
    /// <summary>
    /// HTTP timeout configuration.
    /// SDK timeouts must exceed server timeouts to avoid connection reset errors.
    /// vault.api: 10 min request, 11 min keepAlive, 30s MongoDB/circuit breaker.
    /// </summary>
    public sealed class HttpTimeoutConfig
    {
        /// <summary>Timeout for general API requests (default: 12 minutes).</summary>
        public TimeSpan ApiTimeout { get; set; } = TimeSpan.FromMinutes(12);
        /// <summary>Timeout for file upload requests (default: 15 minutes).</summary>
        public TimeSpan UploadTimeout { get; set; } = TimeSpan.FromMinutes(15);
        /// <summary>Timeout for file download requests (default: 1 minute).</summary>
        public TimeSpan DownloadTimeout { get; set; } = TimeSpan.FromMinutes(1);
        /// <summary>Timeout for establishing a connection (default: 30 seconds).</summary>
        public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>Default timeout configuration.</summary>
        public static HttpTimeoutConfig Default => new HttpTimeoutConfig();

        /// <summary>Creates a configuration with a custom API timeout.</summary>
        /// <param name="timeout">Custom API timeout duration.</param>
        /// <returns>New timeout configuration with the specified API timeout.</returns>
        public static HttpTimeoutConfig WithApiTimeout(TimeSpan timeout) =>
            new HttpTimeoutConfig { ApiTimeout = timeout };
    }
}
