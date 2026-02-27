using System;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
#if NETFRAMEWORK
using Thread = System.Threading.Thread;
#endif

namespace Capsara.SDK.Internal.Http
{
    /// <summary>Retries 503 and 429 responses with exponential backoff and jitter.</summary>
    internal sealed class RetryHandler : DelegatingHandler
    {
        private readonly RetryConfig _config;
#if NET6_0_OR_GREATER
        // Random.Shared is thread-safe in .NET 6+
        private static Random RandomInstance => Random.Shared;
#else
        // Thread-local Random for .NET Framework 4.8
        [ThreadStatic]
        private static Random? _threadLocalRandom;
        private static Random RandomInstance => _threadLocalRandom ??= new Random(Environment.TickCount ^ Thread.CurrentThread.ManagedThreadId);
#endif

        public RetryHandler(RetryConfig? config = null)
            : base()
        {
            _config = config ?? RetryConfig.Default;
        }

        public RetryHandler(HttpMessageHandler innerHandler, RetryConfig? config = null)
            : base(innerHandler)
        {
            _config = config ?? RetryConfig.Default;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            int retryCount = 0;
            HttpResponseMessage? response = null;

            while (true)
            {
                try
                {
                    response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

                    if (!IsRetryableStatus(response.StatusCode) || retryCount >= _config.MaxRetries)
                    {
                        return response;
                    }

                    retryCount++;
                    var delay = await CalculateDelayAsync(response, retryCount).ConfigureAwait(false);

                    if (_config.EnableLogging && _config.Logger != null)
                    {
                        _config.Logger($"[Capsara SDK] Retry {retryCount}/{_config.MaxRetries} for {(int)response.StatusCode} - waiting {delay.TotalMilliseconds:F0}ms");
                    }

                    response.Dispose();
                    await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                }
                catch (HttpRequestException) when (retryCount < _config.MaxRetries)
                {
                    retryCount++;
                    var delay = CalculateExponentialBackoff(retryCount);

                    if (_config.EnableLogging && _config.Logger != null)
                    {
                        _config.Logger($"[Capsara SDK] Retry {retryCount}/{_config.MaxRetries} for connection error - waiting {delay.TotalMilliseconds:F0}ms");
                    }

                    await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                }
            }
        }

        private static bool IsRetryableStatus(HttpStatusCode status)
        {
            return status == HttpStatusCode.ServiceUnavailable ||
                   status == (HttpStatusCode)429;
        }

        private async Task<TimeSpan> CalculateDelayAsync(HttpResponseMessage response, int retryCount)
        {
            var serverDelay = await GetServerSuggestedDelayAsync(response).ConfigureAwait(false);
            if (serverDelay.HasValue)
            {
                return TimeSpan.FromMilliseconds(
                    Math.Min(serverDelay.Value.TotalMilliseconds, _config.MaxDelay.TotalMilliseconds));
            }

            if (response.Headers.RetryAfter != null)
            {
                if (response.Headers.RetryAfter.Delta.HasValue)
                {
                    return TimeSpan.FromMilliseconds(
                        Math.Min(response.Headers.RetryAfter.Delta.Value.TotalMilliseconds, _config.MaxDelay.TotalMilliseconds));
                }

                if (response.Headers.RetryAfter.Date.HasValue)
                {
                    var delay = response.Headers.RetryAfter.Date.Value - DateTimeOffset.UtcNow;
                    if (delay > TimeSpan.Zero)
                    {
                        return TimeSpan.FromMilliseconds(
                            Math.Min(delay.TotalMilliseconds, _config.MaxDelay.TotalMilliseconds));
                    }
                }
            }

            return CalculateExponentialBackoff(retryCount);
        }

        private TimeSpan CalculateExponentialBackoff(int retryCount)
        {
            var exponentialDelayMs = _config.BaseDelay.TotalMilliseconds * Math.Pow(2, retryCount - 1);
            var jitter = RandomInstance.NextDouble() * 0.3 * exponentialDelayMs;
            var totalDelayMs = Math.Min(exponentialDelayMs + jitter, _config.MaxDelay.TotalMilliseconds);
            return TimeSpan.FromMilliseconds(totalDelayMs);
        }

        private static async Task<TimeSpan?> GetServerSuggestedDelayAsync(HttpResponseMessage response)
        {
            try
            {
                var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                if (string.IsNullOrEmpty(content))
                    return null;

                using var doc = JsonDocument.Parse(content);
                if (doc.RootElement.TryGetProperty("error", out var errorElement) &&
                    errorElement.TryGetProperty("retryAfter", out var retryAfterElement) &&
                    retryAfterElement.ValueKind == JsonValueKind.Number)
                {
                    var seconds = retryAfterElement.GetDouble();
                    return TimeSpan.FromSeconds(seconds);
                }
            }
            catch (JsonException)
            {
            }

            return null;
        }
    }
}
