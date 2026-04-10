using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Capsara.SDK.Models;

namespace Capsara.SDK.Internal.Services
{
    /// <summary>System limits management with caching.</summary>
    internal sealed class LimitsService
    {
        private readonly HttpClient _httpClient;
        private readonly TimeSpan _cacheTTL = TimeSpan.FromDays(7);
        private SystemLimits? _cachedLimits;
        private DateTimeOffset? _cachedAt;

        private static readonly JsonSerializerOptions _jsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        public LimitsService(HttpClient httpClient)
        {
            _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        }

        /// <summary>Get system limits (from cache or fetch from API).</summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>System limits.</returns>
        public async Task<SystemLimits> GetLimitsAsync(CancellationToken cancellationToken = default)
        {
            if (_cachedLimits != null && _cachedAt.HasValue)
            {
                var age = DateTimeOffset.UtcNow - _cachedAt.Value;

                if (age < _cacheTTL)
                {
                    return _cachedLimits;
                }

                _cachedLimits = null;
                _cachedAt = null;
            }

            var limits = await FetchLimitsAsync(cancellationToken).ConfigureAwait(false);

            _cachedLimits = limits;
            _cachedAt = DateTimeOffset.UtcNow;

            return limits;
        }

        /// <summary>Fetch system limits from API.</summary>
        private async Task<SystemLimits> FetchLimitsAsync(CancellationToken cancellationToken)
        {
            try
            {
                var response = await _httpClient.GetAsync("/api/limits", cancellationToken).ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                {
                    return SystemLimits.Default;
                }

                var responseBody = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                return JsonSerializer.Deserialize<SystemLimits>(responseBody, _jsonOptions) ?? SystemLimits.Default;
            }
            catch
            {
                // API is down or /limits endpoint doesn't exist - use fallback
                return SystemLimits.Default;
            }
        }

        /// <summary>Clear the limits cache.</summary>
        public void ClearCache()
        {
            _cachedLimits = null;
            _cachedAt = null;
        }
    }
}
