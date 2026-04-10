using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Capsara.SDK.Exceptions;
using Capsara.SDK.Internal.Crypto;

namespace Capsara.SDK.Internal.Services
{
    /// <summary>Public key information from the server.</summary>
    public sealed class PublicKeyInfo
    {
        /// <summary>PEM-encoded RSA public key.</summary>
        [JsonPropertyName("publicKey")]
        public string PublicKey { get; set; } = string.Empty;

        /// <summary>SHA-256 fingerprint of the public key.</summary>
        [JsonPropertyName("keyFingerprint")]
        public string KeyFingerprint { get; set; } = string.Empty;

        /// <summary>ISO 8601 timestamp when the key was created.</summary>
        [JsonPropertyName("createdAt")]
        public string CreatedAt { get; set; } = string.Empty;

        /// <summary>Whether this key is the currently active key.</summary>
        [JsonPropertyName("isActive")]
        public bool IsActive { get; set; }
    }

    /// <summary>Key history entry for tracking key rotations.</summary>
    public sealed class KeyHistoryEntry
    {
        /// <summary>PEM-encoded RSA public key.</summary>
        [JsonPropertyName("publicKey")]
        public string PublicKey { get; set; } = string.Empty;

        /// <summary>SHA-256 fingerprint of the public key.</summary>
        [JsonPropertyName("keyFingerprint")]
        public string KeyFingerprint { get; set; } = string.Empty;

        /// <summary>ISO 8601 timestamp when the key was created.</summary>
        [JsonPropertyName("createdAt")]
        public string CreatedAt { get; set; } = string.Empty;

        /// <summary>ISO 8601 timestamp when the key was revoked, or null if still active.</summary>
        [JsonPropertyName("revokedAt")]
        public string? RevokedAt { get; set; }

        /// <summary>Whether this key is the currently active key.</summary>
        [JsonPropertyName("isActive")]
        public bool IsActive { get; set; }
    }

    /// <summary>Result of key rotation operation.</summary>
    public sealed class KeyRotationResult
    {
        /// <summary>Generated RSA key pair including public key, private key, and fingerprint.</summary>
        public GeneratedKeyPairResult KeyPair { get; set; } = null!;

        /// <summary>Updated public key information from the server.</summary>
        public PublicKeyInfo ServerInfo { get; set; } = null!;
    }

    /// <summary>Account management service for key rotation and account operations.</summary>
    internal sealed class AccountService
    {
        private readonly HttpClient _httpClient;

        private static readonly JsonSerializerOptions _jsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        /// <summary>Initializes a new instance of the <see cref="AccountService"/> class.</summary>
        /// <param name="httpClient">HTTP client for API requests.</param>
        public AccountService(HttpClient httpClient)
        {
            _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        }

        /// <summary>Get current active public key.</summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Current public key info or null if not set.</returns>
        public async Task<PublicKeyInfo?> GetCurrentPublicKeyAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var response = await _httpClient.GetAsync("/api/account/key", cancellationToken).ConfigureAwait(false);
                var responseBody = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                {
                    return null;
                }

                // API returns publicKeyFingerprint, not keyFingerprint
                var result = JsonSerializer.Deserialize<GetKeyResponse>(responseBody, _jsonOptions);
                if (result?.PublicKey == null) return null;

                return new PublicKeyInfo
                {
                    PublicKey = result.PublicKey,
                    KeyFingerprint = result.PublicKeyFingerprint ?? string.Empty,
                    IsActive = true
                };
            }
            catch
            {
                return null;
            }
        }

        /// <summary>Add new public key (auto-rotates: moves current to history).</summary>
        /// <param name="publicKey">New public key in PEM format.</param>
        /// <param name="fingerprint">SHA-256 fingerprint of the public key.</param>
        /// <param name="reason">Optional reason for key rotation.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Updated public key info.</returns>
        public async Task<PublicKeyInfo> AddPublicKeyAsync(
            string publicKey,
            string fingerprint,
            string? reason = null,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var requestBody = new
                {
                    publicKey,
                    publicKeyFingerprint = fingerprint,
                    reason
                };

                var content = new StringContent(
                    JsonSerializer.Serialize(requestBody, _jsonOptions),
                    Encoding.UTF8,
                    "application/json");

                var response = await _httpClient.PostAsync("/api/account/key", content, cancellationToken).ConfigureAwait(false);
                var responseBody = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                {
                    throw CapsaraException.FromHttpResponse(response.StatusCode, responseBody);
                }

                var result = JsonSerializer.Deserialize<AddKeyResponse>(responseBody, _jsonOptions);

                return new PublicKeyInfo
                {
                    PublicKey = result?.PublicKey ?? publicKey,
                    KeyFingerprint = result?.PublicKeyFingerprint ?? fingerprint,
                    CreatedAt = DateTimeOffset.UtcNow.ToString("o"),
                    IsActive = true
                };
            }
            catch (HttpRequestException ex)
            {
                throw CapsaraException.NetworkError(ex);
            }
        }

        /// <summary>Get key history (all previous keys).</summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Array of historical keys (including current active key).</returns>
        public async Task<KeyHistoryEntry[]> GetKeyHistoryAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var response = await _httpClient.GetAsync("/api/account/key/history", cancellationToken).ConfigureAwait(false);
                var responseBody = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                {
                    return Array.Empty<KeyHistoryEntry>();
                }

                var result = JsonSerializer.Deserialize<KeyHistoryResponse>(responseBody, _jsonOptions);
                return result?.Keys ?? Array.Empty<KeyHistoryEntry>();
            }
            catch
            {
                return Array.Empty<KeyHistoryEntry>();
            }
        }

        /// <summary>
        /// Rotate key: generate new key pair and update on server.
        /// Application must store the returned private key securely.
        /// The private key is never sent to the server.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>New key pair and updated server info.</returns>
        public async Task<KeyRotationResult> RotateKeyAsync(CancellationToken cancellationToken = default)
        {
            var keyPair = await KeyGenerator.GenerateKeyPairAsync(cancellationToken).ConfigureAwait(false);
            var serverInfo = await AddPublicKeyAsync(keyPair.PublicKey, keyPair.Fingerprint, null, cancellationToken).ConfigureAwait(false);

            return new KeyRotationResult
            {
                KeyPair = keyPair,
                ServerInfo = serverInfo
            };
        }

        private sealed class AddKeyResponse
        {
            [JsonPropertyName("publicKey")]
            public string? PublicKey { get; set; }

            [JsonPropertyName("publicKeyFingerprint")]
            public string? PublicKeyFingerprint { get; set; }

            [JsonPropertyName("message")]
            public string? Message { get; set; }
        }

        private sealed class GetKeyResponse
        {
            [JsonPropertyName("publicKey")]
            public string? PublicKey { get; set; }

            [JsonPropertyName("publicKeyFingerprint")]
            public string? PublicKeyFingerprint { get; set; }
        }

        private sealed class KeyHistoryResponse
        {
            [JsonPropertyName("keys")]
            public KeyHistoryEntry[]? Keys { get; set; }
        }
    }
}
