using System;

namespace Capsara.SDK.Internal.Http
{
    /// <summary>Retry configuration with exponential backoff.</summary>
    public sealed class RetryConfig
    {
        /// <summary>Maximum number of retry attempts (default: 3).</summary>
        public int MaxRetries { get; set; } = 3;
        /// <summary>Base delay between retries before exponential increase (default: 1 second).</summary>
        public TimeSpan BaseDelay { get; set; } = TimeSpan.FromSeconds(1);
        /// <summary>Maximum delay between retries (default: 30 seconds).</summary>
        public TimeSpan MaxDelay { get; set; } = TimeSpan.FromSeconds(30);
        /// <summary>Whether to log retry attempts via the logger callback.</summary>
        public bool EnableLogging { get; set; } = false;
        /// <summary>Optional logger callback for retry diagnostic messages.</summary>
        public Action<string>? Logger { get; set; }

        /// <summary>Default retry configuration (3 retries, 1s base delay, 30s max delay).</summary>
        public static RetryConfig Default => new RetryConfig();
        /// <summary>Configuration that disables retries.</summary>
        public static RetryConfig NoRetry => new RetryConfig { MaxRetries = 0 };
    }
}
