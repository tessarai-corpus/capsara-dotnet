using System;
using Capsara.SDK.Internal.Http;
using Capsara.SDK.Models;

namespace Capsara.SDK
{
    /// <summary>Configuration options for CapsaraClient.</summary>
    public sealed class CapsaraClientOptions
    {
        /// <summary>Login credentials for automatic authentication.</summary>
        public AuthCredentials? Credentials { get; set; }
        /// <summary>Pre-existing access token (skips login).</summary>
        public string? AccessToken { get; set; }
        /// <summary>Expected JWT issuer for token validation.</summary>
        public string? ExpectedIssuer { get; set; }
        /// <summary>Expected JWT audience for token validation.</summary>
        public string? ExpectedAudience { get; set; }
        /// <summary>HTTP timeout configuration.</summary>
        public HttpTimeoutConfig? Timeout { get; set; }
        /// <summary>Retry policy configuration.</summary>
        public RetryConfig? Retry { get; set; }
        /// <summary>Maximum capsas per upload batch (default: 150).</summary>
        public int MaxBatchSize { get; set; } = 150;

        /// <summary>Appended to the default SDK user agent string.</summary>
        public string? UserAgent { get; set; }

        /// <summary>Time-to-live for cached master keys.</summary>
        public TimeSpan? CacheTTL { get; set; }
        /// <summary>Enable SDK diagnostic logging.</summary>
        public bool EnableLogging { get; set; }
        /// <summary>Custom log handler for SDK diagnostic messages.</summary>
        public Action<string>? Logger { get; set; }
    }
}
