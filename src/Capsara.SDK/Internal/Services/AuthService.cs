using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Capsara.SDK.Exceptions;
using Capsara.SDK.Internal.Http;
using Capsara.SDK.Models;

namespace Capsara.SDK.Internal.Services
{
    /// <summary>Authentication state change event data.</summary>
    public sealed class AuthStateChangedEventArgs : EventArgs
    {
        /// <summary>Whether the client is currently authenticated.</summary>
        public bool IsAuthenticated { get; }

        /// <summary>Type of authentication event (login, refresh, logout).</summary>
        public string Event { get; }

        /// <summary>Initializes a new instance of the <see cref="AuthStateChangedEventArgs"/> class.</summary>
        /// <param name="isAuthenticated">Whether the client is authenticated.</param>
        /// <param name="eventType">Type of authentication event.</param>
        public AuthStateChangedEventArgs(bool isAuthenticated, string eventType)
        {
            IsAuthenticated = isAuthenticated;
            Event = eventType;
        }
    }

    /// <summary>Authentication service options.</summary>
    public sealed class AuthServiceOptions
    {
        /// <summary>Expected JWT issuer claim for token validation.</summary>
        public string? ExpectedIssuer { get; set; }

        /// <summary>Expected JWT audience claim for token validation.</summary>
        public string? ExpectedAudience { get; set; }

        /// <summary>HTTP timeout configuration for authentication requests.</summary>
        public HttpTimeoutConfig? Timeout { get; set; }

        /// <summary>Retry configuration for failed authentication requests.</summary>
        public RetryConfig? Retry { get; set; }

        /// <summary>Custom User-Agent header value for HTTP requests.</summary>
        public string? UserAgent { get; set; }
    }

    /// <summary>Authentication service for managing access tokens and refresh tokens.</summary>
    internal sealed class AuthService
    {
        private string? _accessToken;
        private string? _refreshToken;
        private long? _tokenExpiresAt;
        private readonly HttpClient _http;
        private readonly string _expectedIssuer;
        private readonly string _expectedAudience;
        private Exception? _lastRefreshError;
        private static readonly JsonSerializerOptions _jsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        /// <summary>Raised when the authentication state changes (login, refresh, logout).</summary>
        public event EventHandler<AuthStateChangedEventArgs>? AuthStateChanged;

        /// <summary>Initializes a new instance of the <see cref="AuthService"/> class.</summary>
        /// <param name="baseUrl">Base URL of the authentication API.</param>
        /// <param name="options">Optional authentication service configuration.</param>
        public AuthService(string baseUrl, AuthServiceOptions? options = null)
        {
            _http = HttpClientFactory.Create(
                baseUrl,
                null, // No auth for auth service - we handle it manually
                options?.Timeout,
                options?.Retry,
                options?.UserAgent);

            _expectedIssuer = options?.ExpectedIssuer ?? "vault.api";
            _expectedAudience = options?.ExpectedAudience ?? "vault.api";
        }

        private void EmitAuthChange(string eventType)
        {
            AuthStateChanged?.Invoke(this, new AuthStateChangedEventArgs(IsAuthenticated, eventType));
        }

        private static Dictionary<string, object>? DecodeJwtPayload(string token)
        {
            try
            {
                var parts = token.Split('.');
                if (parts.Length != 3) return null;

                var payload = parts[1];
                // Add padding if needed
                switch (payload.Length % 4)
                {
                    case 2: payload += "=="; break;
                    case 3: payload += "="; break;
                }
                // Convert from base64url to base64
                payload = payload.Replace('-', '+').Replace('_', '/');

                var bytes = Convert.FromBase64String(payload);
                var json = Encoding.UTF8.GetString(bytes);
                return JsonSerializer.Deserialize<Dictionary<string, object>>(json);
            }
            catch
            {
                return null;
            }
        }

        private long? ValidateAndExtractExpiry(string token)
        {
            var payload = DecodeJwtPayload(token);
            if (payload == null) return null;

            if (payload.TryGetValue("exp", out var expValue) && expValue is JsonElement expElement)
            {
                if (expElement.TryGetInt64(out var exp))
                {
                    return exp * 1000; // Convert to milliseconds
                }
            }

            return null;
        }

        /// <summary>Checks whether the access token is expired or will expire within the buffer period.</summary>
        /// <param name="bufferSeconds">Seconds before actual expiry to consider the token expired (default: 30).</param>
        /// <returns>True if the token is expired or missing.</returns>
        public bool IsTokenExpired(int bufferSeconds = 30)
        {
            if (_tokenExpiresAt == null) return true;
            return DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() >= _tokenExpiresAt.Value - bufferSeconds * 1000;
        }

        /// <summary>Authenticates with the server using the provided credentials.</summary>
        /// <param name="credentials">Login credentials (API key and secret).</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Authentication response containing access and refresh tokens.</returns>
        public async Task<AuthResponse> LoginAsync(AuthCredentials credentials, CancellationToken cancellationToken = default)
        {
            try
            {
                var content = new StringContent(
                    JsonSerializer.Serialize(credentials, _jsonOptions),
                    Encoding.UTF8,
                    "application/json");

                var response = await _http.PostAsync("/api/auth/login", content, cancellationToken).ConfigureAwait(false);
                var responseBody = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                {
                    throw CapsaraAuthException.FromHttpResponse(response.StatusCode, responseBody);
                }

                var authResponse = JsonSerializer.Deserialize<AuthResponse>(responseBody, _jsonOptions)
                    ?? throw new CapsaraAuthException("Invalid login response", "INVALID_RESPONSE", (int)response.StatusCode);

                _accessToken = authResponse.AccessToken;
                _refreshToken = authResponse.RefreshToken;

                if (authResponse.ExpiresIn > 0)
                {
                    _tokenExpiresAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + authResponse.ExpiresIn * 1000;
                }
                else if (!string.IsNullOrEmpty(authResponse.AccessToken))
                {
                    _tokenExpiresAt = ValidateAndExtractExpiry(authResponse.AccessToken);
                }

                EmitAuthChange("login");
                return authResponse;
            }
            catch (HttpRequestException ex)
            {
                throw CapsaraException.NetworkError(ex);
            }
        }

        /// <summary>Refreshes the access token using the stored refresh token.</summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>True if the token was refreshed successfully.</returns>
        public async Task<bool> RefreshAsync(CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(_refreshToken)) return false;

            try
            {
                var content = new StringContent(
                    JsonSerializer.Serialize(new { refreshToken = _refreshToken }, _jsonOptions),
                    Encoding.UTF8,
                    "application/json");

                var response = await _http.PostAsync("/api/auth/refresh", content, cancellationToken).ConfigureAwait(false);
                var responseBody = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                {
                    _lastRefreshError = CapsaraAuthException.FromHttpResponse(response.StatusCode, responseBody);
                    return false;
                }

                var authResponse = JsonSerializer.Deserialize<AuthResponse>(responseBody, _jsonOptions);
                if (authResponse == null) return false;

                _accessToken = authResponse.AccessToken;
                if (!string.IsNullOrEmpty(authResponse.RefreshToken))
                {
                    _refreshToken = authResponse.RefreshToken;
                }

                if (authResponse.ExpiresIn > 0)
                {
                    _tokenExpiresAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + authResponse.ExpiresIn * 1000;
                }
                else if (!string.IsNullOrEmpty(authResponse.AccessToken))
                {
                    _tokenExpiresAt = ValidateAndExtractExpiry(authResponse.AccessToken);
                }

                _lastRefreshError = null;
                EmitAuthChange("refresh");
                return true;
            }
            catch (Exception ex)
            {
                _lastRefreshError = ex;
                return false;
            }
        }

        /// <summary>Gets the last error that occurred during token refresh.</summary>
        /// <returns>The exception from the last failed refresh, or null.</returns>
        public Exception? GetLastRefreshError() => _lastRefreshError;

        /// <summary>Gets the current access token.</summary>
        /// <returns>The access token, or null if not authenticated.</returns>
        public string? GetToken() => _accessToken;

        /// <summary>Gets the current refresh token.</summary>
        /// <returns>The refresh token, or null if not available.</returns>
        public string? GetRefreshToken() => _refreshToken;

        /// <summary>Whether the client has a valid access token.</summary>
        public bool IsAuthenticated => _accessToken != null;

        /// <summary>Whether a refresh token is available for token renewal.</summary>
        public bool CanRefresh => _refreshToken != null;

        /// <summary>Logs out by clearing local tokens and notifying the server.</summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>True if server-side logout succeeded.</returns>
        public async Task<bool> LogoutAsync(CancellationToken cancellationToken = default)
        {
            var currentAccessToken = _accessToken;
            var currentRefreshToken = _refreshToken;

            _accessToken = null;
            _refreshToken = null;
            _tokenExpiresAt = null;

            if (!string.IsNullOrEmpty(currentAccessToken) && !string.IsNullOrEmpty(currentRefreshToken))
            {
                try
                {
                    var content = new StringContent(
                        JsonSerializer.Serialize(new { refreshToken = currentRefreshToken }, _jsonOptions),
                        Encoding.UTF8,
                        "application/json");

                    using var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/logout")
                    {
                        Content = content
                    };
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", currentAccessToken);

                    await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
                    EmitAuthChange("logout");
                    return true;
                }
                catch
                {
                    // Server-side logout failed, but tokens cleared locally
                    EmitAuthChange("logout");
                    return false;
                }
            }

            EmitAuthChange("logout");
            return true;
        }

        /// <summary>Sets the access token and extracts its expiry.</summary>
        /// <param name="token">JWT access token.</param>
        public void SetToken(string token)
        {
            _accessToken = token;
            _tokenExpiresAt = ValidateAndExtractExpiry(token);
        }

        /// <summary>Sets the refresh token for token renewal.</summary>
        /// <param name="token">Refresh token.</param>
        public void SetRefreshToken(string token)
        {
            _refreshToken = token;
        }

        /// <summary>Sets both access and refresh tokens.</summary>
        /// <param name="accessToken">JWT access token.</param>
        /// <param name="refreshToken">Refresh token for token renewal.</param>
        public void SetTokens(string accessToken, string refreshToken)
        {
            _accessToken = accessToken;
            _refreshToken = refreshToken;
            _tokenExpiresAt = ValidateAndExtractExpiry(accessToken);
        }
    }
}
