using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Capsara.SDK.Exceptions;
using Capsara.SDK.Internal.Http;
using Capsara.SDK.Models;

namespace Capsara.SDK.Internal.Services
{
    /// <summary>Key service options.</summary>
    public sealed class KeyServiceOptions
    {
        /// <summary>HTTP timeout configuration for key service requests.</summary>
        public HttpTimeoutConfig? Timeout { get; set; }

        /// <summary>Retry configuration for failed key service requests.</summary>
        public RetryConfig? Retry { get; set; }

        /// <summary>Custom User-Agent header value for HTTP requests.</summary>
        public string? UserAgent { get; set; }
    }

    /// <summary>Party key management for fetching public keys.</summary>
    internal sealed class KeyService
    {
        private readonly HttpClient _http;
        private static readonly JsonSerializerOptions _jsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        /// <summary>Initializes a new instance of the <see cref="KeyService"/> class.</summary>
        /// <param name="baseUrl">Base URL of the API.</param>
        /// <param name="getToken">Function that returns the current access token.</param>
        /// <param name="options">Optional key service configuration.</param>
        public KeyService(string baseUrl, Func<string?> getToken, KeyServiceOptions? options = null)
        {
            _http = HttpClientFactory.Create(
                baseUrl,
                getToken,
                options?.Timeout,
                options?.Retry,
                options?.UserAgent);
        }

        /// <summary>Fetch a single party key by exact ID (excludes delegates).</summary>
        /// <param name="partyId">Party ID to fetch.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Party key or null if not found.</returns>
        public async Task<PartyKey?> FetchExplicitPartyKeyAsync(string partyId, CancellationToken cancellationToken = default)
        {
            var parties = await FetchPartyKeysAsync(new[] { partyId }, cancellationToken).ConfigureAwait(false);

            // Return only the explicitly requested party (API may include delegates)
            foreach (var party in parties)
            {
                if (party.Id == partyId)
                    return party;
            }
            return null;
        }

        /// <summary>
        /// Fetch party keys from API (includes delegates).
        /// Uses POST to avoid URL length limits with large batches.
        /// </summary>
        /// <param name="partyIds">Array of party IDs.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Array of party keys (includes delegates).</returns>
        public async Task<PartyKey[]> FetchPartyKeysAsync(string[] partyIds, CancellationToken cancellationToken = default)
        {
            try
            {
                var content = new StringContent(
                    JsonSerializer.Serialize(new { ids = partyIds }, _jsonOptions),
                    Encoding.UTF8,
                    "application/json");

                var response = await _http.PostAsync("/api/party/keys", content, cancellationToken).ConfigureAwait(false);
                var responseBody = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                {
                    throw CapsaraException.FromHttpResponse(response.StatusCode, responseBody);
                }

                var result = JsonSerializer.Deserialize<PartyKeysResponse>(responseBody, _jsonOptions);
                return result?.Parties ?? Array.Empty<PartyKey>();
            }
            catch (HttpRequestException ex)
            {
                throw CapsaraException.NetworkError(ex);
            }
        }

        private sealed class PartyKeysResponse
        {
            public PartyKey[] Parties { get; set; } = Array.Empty<PartyKey>();
        }
    }
}
