using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Capsara.SDK.Exceptions;
using Capsara.SDK.Models;

namespace Capsara.SDK.Internal.Services
{
    /// <summary>Audit trail service for capsa audit entry operations.</summary>
    internal sealed class AuditService
    {
        private readonly HttpClient _http;
        private static readonly JsonSerializerOptions _jsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        public AuditService(HttpClient httpClient)
        {
            _http = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        }

        /// <summary>Get audit trail for a capsa.</summary>
        /// <param name="capsaId">Capsa ID.</param>
        /// <param name="filters">Optional filters.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Paginated audit entries.</returns>
        public async Task<GetAuditEntriesResponse> GetAuditEntriesAsync(
            string capsaId,
            GetAuditEntriesFilters? filters = null,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var queryString = BuildQueryString(filters);
                var url = string.IsNullOrEmpty(queryString)
                    ? $"/api/capsas/{capsaId}/audit"
                    : $"/api/capsas/{capsaId}/audit?{queryString}";

                var response = await _http.GetAsync(url, cancellationToken).ConfigureAwait(false);
                var responseBody = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                {
                    throw CapsaraAuditException.FromHttpResponse(response.StatusCode, responseBody);
                }

                return JsonSerializer.Deserialize<GetAuditEntriesResponse>(responseBody, _jsonOptions)
                    ?? new GetAuditEntriesResponse();
            }
            catch (HttpRequestException ex)
            {
                throw CapsaraException.NetworkError(ex);
            }
        }

        /// <summary>Create audit entry for a capsa.</summary>
        /// <param name="capsaId">Capsa ID.</param>
        /// <param name="entry">Audit entry request.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>True on success.</returns>
        public async Task<bool> CreateAuditEntryAsync(
            string capsaId,
            CreateAuditEntryRequest entry,
            CancellationToken cancellationToken = default)
        {
            // Client-side validation: 'log' action requires details
            if (entry.Action == AuditActions.Log && (entry.Details == null || entry.Details.Count == 0))
            {
                throw CapsaraAuditException.MissingDetails();
            }

            try
            {
                var content = new StringContent(
                    JsonSerializer.Serialize(entry, _jsonOptions),
                    Encoding.UTF8,
                    "application/json");

                var response = await _http.PostAsync($"/api/capsas/{capsaId}/audit", content, cancellationToken).ConfigureAwait(false);
                var responseBody = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                {
                    throw CapsaraAuditException.FromHttpResponse(response.StatusCode, responseBody);
                }

                return true;
            }
            catch (HttpRequestException ex)
            {
                throw CapsaraException.NetworkError(ex);
            }
        }

        private static string BuildQueryString(GetAuditEntriesFilters? filters)
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

            Append("action", filters.Action);
            Append("party", filters.Party);
            if (filters.Page.HasValue)
                Append("page", filters.Page.Value.ToString());
            if (filters.Limit.HasValue)
                Append("limit", filters.Limit.Value.ToString());

            return sb.ToString();
        }
    }
}
