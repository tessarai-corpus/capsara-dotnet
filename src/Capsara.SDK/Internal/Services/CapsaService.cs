using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Capsara.SDK.Exceptions;
using Capsara.SDK.Models;

namespace Capsara.SDK.Internal.Services
{
    /// <summary>Capsa CRUD operations service.</summary>
    internal sealed class CapsaService
    {
        private readonly HttpClient _http;
        private readonly KeyService _keyService;
        private static readonly JsonSerializerOptions _jsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        public CapsaService(HttpClient httpClient, KeyService keyService)
        {
            _http = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
            _keyService = keyService ?? throw new ArgumentNullException(nameof(keyService));
        }

        /// <summary>Get capsa by ID (encrypted).</summary>
        /// <param name="capsaId">Capsa ID.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Encrypted capsa.</returns>
        public async Task<Capsa> GetCapsaAsync(string capsaId, CancellationToken cancellationToken = default)
        {
            try
            {
                var response = await _http.GetAsync($"/api/capsas/{capsaId}", cancellationToken).ConfigureAwait(false);
                var responseBody = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                {
                    throw CapsaraCapsaException.FromHttpResponse(response.StatusCode, responseBody);
                }

                return JsonSerializer.Deserialize<Capsa>(responseBody, _jsonOptions)
                    ?? throw new CapsaraCapsaException("Invalid capsa response", "INVALID_RESPONSE", (int)response.StatusCode);
            }
            catch (HttpRequestException ex)
            {
                throw CapsaraException.NetworkError(ex);
            }
        }

        /// <summary>List capsas with cursor-based pagination.</summary>
        /// <param name="filters">Query filters.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Paginated capsa list.</returns>
        public async Task<CapsaListResponse> ListCapsasAsync(CapsaListFilters? filters = null, CancellationToken cancellationToken = default)
        {
            try
            {
                var queryString = BuildQueryString(filters);
                var url = string.IsNullOrEmpty(queryString) ? "/api/capsas" : $"/api/capsas?{queryString}";

                var response = await _http.GetAsync(url, cancellationToken).ConfigureAwait(false);
                var responseBody = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                {
                    throw CapsaraCapsaException.FromHttpResponse(response.StatusCode, responseBody);
                }

                var data = JsonSerializer.Deserialize<CapsaListResponse>(responseBody, _jsonOptions);

                // Defensive handling for null/undefined response data
                return new CapsaListResponse
                {
                    Capsas = data?.Capsas ?? Array.Empty<CapsaSummary>(),
                    Pagination = new CursorPagination
                    {
                        Limit = data?.Pagination?.Limit ?? filters?.Limit ?? 20,
                        HasMore = data?.Pagination?.HasMore ?? false,
                        NextCursor = data?.Pagination?.NextCursor,
                        PrevCursor = data?.Pagination?.PrevCursor
                    }
                };
            }
            catch (HttpRequestException ex)
            {
                throw CapsaraException.NetworkError(ex);
            }
        }

        /// <summary>Soft delete a capsa.</summary>
        /// <param name="capsaId">Capsa ID.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        public async Task DeleteCapsaAsync(string capsaId, CancellationToken cancellationToken = default)
        {
            try
            {
                var response = await _http.DeleteAsync($"/api/capsas/{capsaId}", cancellationToken).ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                {
                    var responseBody = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    throw CapsaraCapsaException.FromHttpResponse(response.StatusCode, responseBody);
                }
            }
            catch (HttpRequestException ex)
            {
                throw CapsaraException.NetworkError(ex);
            }
        }

        /// <summary>Get creator's public key for signature verification.</summary>
        internal async Task<string?> GetCreatorPublicKeyAsync(string creatorId, CancellationToken cancellationToken = default)
        {
            var creatorKey = await _keyService.FetchExplicitPartyKeyAsync(creatorId, cancellationToken).ConfigureAwait(false);
            return creatorKey?.PublicKey;
        }

        private static string BuildQueryString(CapsaListFilters? filters)
        {
            if (filters == null) return string.Empty;

            var sb = new StringBuilder();
            void Append(string key, string? value)
            {
                if (string.IsNullOrEmpty(value)) return;
                if (sb.Length > 0) sb.Append('&');
                sb.Append(Uri.EscapeDataString(key));
                sb.Append('=');
                sb.Append(Uri.EscapeDataString(value));
            }

            if (filters.Status.HasValue)
                Append("status", filters.Status.Value.ToApiString());
            Append("createdBy", filters.CreatedBy);
            Append("startDate", filters.StartDate);
            Append("endDate", filters.EndDate);
            Append("expiringBefore", filters.ExpiringBefore);
            if (filters.HasLegalHold.HasValue)
                Append("hasLegalHold", filters.HasLegalHold.Value.ToString().ToLowerInvariant());
            if (filters.Limit.HasValue)
                Append("limit", filters.Limit.Value.ToString());
            Append("after", filters.After);
            Append("before", filters.Before);

            return sb.ToString();
        }
    }
}
