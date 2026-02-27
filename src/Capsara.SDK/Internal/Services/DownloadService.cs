using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Capsara.SDK.Exceptions;
using Capsara.SDK.Internal.Http;

namespace Capsara.SDK.Internal.Services
{
    /// <summary>File metadata for decryption.</summary>
    public sealed class FileMetadata
    {
        /// <summary>Base64url-encoded initialization vector for file decryption.</summary>
        public string IV { get; set; } = string.Empty;

        /// <summary>Base64url-encoded GCM authentication tag for file integrity.</summary>
        public string AuthTag { get; set; } = string.Empty;

        /// <summary>Whether the file was compressed before encryption.</summary>
        public bool Compressed { get; set; }

        /// <summary>Base64url-encoded encrypted original filename.</summary>
        public string EncryptedFilename { get; set; } = string.Empty;

        /// <summary>Base64url-encoded initialization vector for filename decryption.</summary>
        public string FilenameIV { get; set; } = string.Empty;

        /// <summary>Base64url-encoded GCM authentication tag for filename integrity.</summary>
        public string FilenameAuthTag { get; set; } = string.Empty;
    }

    /// <summary>Decrypted file result.</summary>
    public sealed class DecryptedFileResult
    {
        /// <summary>Decrypted and decompressed file contents.</summary>
        public byte[] Data { get; set; } = Array.Empty<byte>();

        /// <summary>Decrypted original filename.</summary>
        public string Filename { get; set; } = string.Empty;
    }

    /// <summary>Download URL response.</summary>
    internal sealed class DownloadUrlResponse
    {
        /// <summary>File identifier.</summary>
        public string FileId { get; set; } = string.Empty;
        /// <summary>Pre-signed URL for downloading the encrypted file.</summary>
        public string DownloadUrl { get; set; } = string.Empty;
        /// <summary>ISO 8601 timestamp when the download URL expires.</summary>
        public string ExpiresAt { get; set; } = string.Empty;
    }

    /// <summary>Download service options.</summary>
    public sealed class DownloadServiceOptions
    {
        /// <summary>HTTP timeout configuration for download operations.</summary>
        public HttpTimeoutConfig? TimeoutConfig { get; set; }

        /// <summary>Retry configuration for failed download requests.</summary>
        public RetryConfig? RetryConfig { get; set; }

        /// <summary>Optional logger callback for diagnostic messages.</summary>
        public Action<string>? Logger { get; set; }
    }

    /// <summary>File download and decryption service.</summary>
    internal sealed class DownloadService
    {
        private readonly HttpClient _http;
        private readonly HttpClient _blobDownloadClient;
        private readonly HttpTimeoutConfig _timeoutConfig;
        private readonly RetryConfig _retryConfig;
        private readonly Action<string>? _logger;
        private static readonly JsonSerializerOptions _jsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        /// <summary>Initializes a new instance of the <see cref="DownloadService"/> class.</summary>
        /// <param name="httpClient">HTTP client for API requests.</param>
        /// <param name="blobHttpClient">HTTP client for blob storage downloads.</param>
        /// <param name="options">Optional download service configuration.</param>
        public DownloadService(HttpClient httpClient, HttpClient blobHttpClient, DownloadServiceOptions? options = null)
        {
            _http = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
            _blobDownloadClient = blobHttpClient ?? throw new ArgumentNullException(nameof(blobHttpClient));
            _timeoutConfig = options?.TimeoutConfig ?? HttpTimeoutConfig.Default;
            _retryConfig = options?.RetryConfig ?? RetryConfig.Default;
            _logger = options?.Logger;
        }

        /// <summary>Get download URL for encrypted file.</summary>
        /// <param name="capsaId">Capsa ID.</param>
        /// <param name="fileId">File ID.</param>
        /// <param name="expiresInMinutes">URL expiration in minutes (default: 60).</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Download URL and expiration.</returns>
        public async Task<(string DownloadUrl, string ExpiresAt)> GetFileDownloadUrlAsync(
            string capsaId,
            string fileId,
            int expiresInMinutes = 60,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var url = $"/api/capsas/{capsaId}/files/{fileId}/download?expires={expiresInMinutes}";
                var response = await _http.GetAsync(url, cancellationToken).ConfigureAwait(false);
                var responseBody = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                {
                    throw CapsaraCapsaException.FromHttpResponse(response.StatusCode, responseBody);
                }

                var result = JsonSerializer.Deserialize<DownloadUrlResponse>(responseBody, _jsonOptions)
                    ?? throw new CapsaraCapsaException("Invalid download URL response", "INVALID_RESPONSE", (int)response.StatusCode);

                return (result.DownloadUrl, result.ExpiresAt);
            }
            catch (HttpRequestException ex)
            {
                throw CapsaraException.NetworkError(ex);
            }
        }

        /// <summary>Download encrypted file from blob storage.</summary>
        /// <param name="capsaId">Capsa ID.</param>
        /// <param name="fileId">File ID.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Encrypted file data.</returns>
        public async Task<byte[]> DownloadEncryptedFileAsync(
            string capsaId,
            string fileId,
            CancellationToken cancellationToken = default)
        {
            var (downloadUrl, _) = await GetFileDownloadUrlAsync(capsaId, fileId, 60, cancellationToken).ConfigureAwait(false);
            return await DownloadFileWithRetryAsync(downloadUrl, 0, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>Download file with retry logic.</summary>
        private async Task<byte[]> DownloadFileWithRetryAsync(
            string downloadUrl,
            int retryCount,
            CancellationToken cancellationToken)
        {
            try
            {
                var response = await _blobDownloadClient.GetAsync(downloadUrl, cancellationToken).ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                {
                    var status = (int)response.StatusCode;
                    var isRetryable = status == 503 || status == 429;

                    if (isRetryable && retryCount < _retryConfig.MaxRetries)
                    {
                        var retryDelay = CalculateRetryDelay(retryCount);

                        if (_retryConfig.EnableLogging && _logger != null)
                        {
                            _logger($"[Capsara SDK] Retry attempt {retryCount + 1}/{_retryConfig.MaxRetries} for {status} error (file download) - waiting {retryDelay.TotalMilliseconds:F0}ms");
                        }

                        await Task.Delay(retryDelay, cancellationToken).ConfigureAwait(false);
                        return await DownloadFileWithRetryAsync(downloadUrl, retryCount + 1, cancellationToken).ConfigureAwait(false);
                    }

                    throw CapsaraCapsaException.DownloadFailed("", "", new Exception($"Download failed with status {status}"));
                }

                return await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
            }
            catch (HttpRequestException) when (retryCount < _retryConfig.MaxRetries)
            {
                var retryDelay = CalculateRetryDelay(retryCount);

                if (_retryConfig.EnableLogging && _logger != null)
                {
                    _logger($"[Capsara SDK] Retry attempt {retryCount + 1}/{_retryConfig.MaxRetries} for network error (file download) - waiting {retryDelay.TotalMilliseconds:F0}ms");
                }

                await Task.Delay(retryDelay, cancellationToken).ConfigureAwait(false);
                return await DownloadFileWithRetryAsync(downloadUrl, retryCount + 1, cancellationToken).ConfigureAwait(false);
            }
        }

        /// <summary>Calculate retry delay with exponential backoff.</summary>
        private TimeSpan CalculateRetryDelay(int retryCount)
        {
            var exponentialDelayMs = _retryConfig.BaseDelay.TotalMilliseconds * Math.Pow(2, retryCount);
            var jitter = new Random().NextDouble() * 0.3 * exponentialDelayMs;
            var totalDelayMs = Math.Min(exponentialDelayMs + jitter, _retryConfig.MaxDelay.TotalMilliseconds);
            return TimeSpan.FromMilliseconds(totalDelayMs);
        }
    }
}
