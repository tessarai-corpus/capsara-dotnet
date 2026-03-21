using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Capsara.SDK.Builder;
using Capsara.SDK.Exceptions;
using Capsara.SDK.Internal.Http;
using Capsara.SDK.Internal.Upload;
using Capsara.SDK.Models;

namespace Capsara.SDK.Internal.Services
{
    /// <summary>Result of sending capsas.</summary>
    public sealed class SendResult
    {
        /// <summary>Batch identifier for tracking the send operation.</summary>
        [JsonPropertyName("batchId")]
        public string BatchId { get; set; } = string.Empty;

        /// <summary>Number of capsas successfully sent.</summary>
        [JsonPropertyName("successful")]
        public int Successful { get; set; }

        /// <summary>Number of capsas that failed to send.</summary>
        [JsonPropertyName("failed")]
        public int Failed { get; set; }

        /// <summary>Whether the batch completed with partial success.</summary>
        [JsonPropertyName("partialSuccess")]
        public bool? PartialSuccess { get; set; }

        /// <summary>Array of successfully created capsas.</summary>
        [JsonPropertyName("created")]
        public CreatedCapsa[] Created { get; set; } = Array.Empty<CreatedCapsa>();

        /// <summary>Array of errors for capsas that failed to send.</summary>
        [JsonPropertyName("errors")]
        public SendError[]? Errors { get; set; }
    }

    /// <summary>Created capsa result.</summary>
    public sealed class CreatedCapsa
    {
        /// <summary>Server-assigned package identifier.</summary>
        [JsonPropertyName("packageId")]
        public string PackageId { get; set; } = string.Empty;

        /// <summary>Index of this capsa in the original send request.</summary>
        [JsonPropertyName("index")]
        public int Index { get; set; }
    }

    /// <summary>Error for a failed capsa.</summary>
    public sealed class SendError
    {
        /// <summary>Index of the failed capsa in the original send request.</summary>
        [JsonPropertyName("index")]
        public int Index { get; set; }

        /// <summary>Server-assigned package identifier, if available.</summary>
        [JsonPropertyName("packageId")]
        public string PackageId { get; set; } = string.Empty;

        /// <summary>Error message describing the failure.</summary>
        [JsonPropertyName("error")]
        public string Error { get; set; } = string.Empty;
    }

    /// <summary>Service for uploading capsas to the API.</summary>
    internal sealed class UploadService
    {
        private readonly HttpClient _httpClient;
        private readonly KeyService _keyService;
        private readonly int _maxBatchSize;
        private readonly RetryConfig _retryConfig;

        private static readonly JsonSerializerOptions _jsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        /// <summary>Initializes a new instance of the <see cref="UploadService"/> class.</summary>
        /// <param name="httpClient">HTTP client for API requests.</param>
        /// <param name="keyService">Key service for fetching party public keys.</param>
        /// <param name="maxBatchSize">Maximum capsas per batch (default: 100).</param>
        /// <param name="retryConfig">Retry configuration for failed requests.</param>
        public UploadService(
            HttpClient httpClient,
            KeyService keyService,
            int maxBatchSize = 100,
            RetryConfig? retryConfig = null)
        {
            _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
            _keyService = keyService ?? throw new ArgumentNullException(nameof(keyService));
            _maxBatchSize = maxBatchSize;
            _retryConfig = retryConfig ?? RetryConfig.Default;
        }

        /// <summary>Send capsas with automatic batch splitting.</summary>
        /// <param name="builders">Array of CapsaBuilder instances.</param>
        /// <param name="creatorId">Creator party ID.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Send result.</returns>
        public async Task<SendResult> SendCapsasAsync(
            CapsaBuilder[] builders,
            string creatorId,
            CancellationToken cancellationToken = default)
        {
            if (builders == null || builders.Length == 0)
            {
                throw new ArgumentException("No capsas provided to send", nameof(builders));
            }

            if (builders.Length > 500)
            {
                throw new ArgumentException("Send limited to 500 capsas per request", nameof(builders));
            }

            const int MAX_FILES_PER_BATCH = 500;
            for (int i = 0; i < builders.Length; i++)
            {
                var fileCount = builders[i].GetFileCount();
                if (fileCount > MAX_FILES_PER_BATCH)
                {
                    throw new ArgumentException(
                        $"Capsa at index {i} has {fileCount} files, exceeding the batch limit of {MAX_FILES_PER_BATCH} files.");
                }
            }

            return await SendInBalancedBatchesAsync(builders, creatorId, cancellationToken).ConfigureAwait(false);
        }

        private async Task<SendResult> SendInBalancedBatchesAsync(
            CapsaBuilder[] builders,
            string creatorId,
            CancellationToken cancellationToken)
        {
            const int MAX_FILES_PER_BATCH = 500;

            var chunks = new List<CapsaBuilder[]>();
            var currentChunk = new List<CapsaBuilder>();
            int currentChunkFileCount = 0;

            foreach (var builder in builders)
            {
                var builderFileCount = builder.GetFileCount();
                var wouldExceedCapsaLimit = currentChunk.Count >= _maxBatchSize;
                var wouldExceedFileLimit = currentChunkFileCount + builderFileCount > MAX_FILES_PER_BATCH;

                if (currentChunk.Count > 0 && (wouldExceedCapsaLimit || wouldExceedFileLimit))
                {
                    chunks.Add(currentChunk.ToArray());
                    currentChunk = new List<CapsaBuilder> { builder };
                    currentChunkFileCount = builderFileCount;
                }
                else
                {
                    currentChunk.Add(builder);
                    currentChunkFileCount += builderFileCount;
                }
            }

            if (currentChunk.Count > 0)
            {
                chunks.Add(currentChunk.ToArray());
            }

            var results = new List<SendResult>();
            int currentOffset = 0;

            for (int chunkIndex = 0; chunkIndex < chunks.Count; chunkIndex++)
            {
                var chunk = chunks[chunkIndex];

                try
                {
                    var allPartyIds = new HashSet<string> { creatorId };
                    foreach (var builder in chunk)
                    {
                        foreach (var id in builder.GetRecipientIds())
                        {
                            allPartyIds.Add(id);
                        }
                    }

                    var partyKeys = await _keyService.FetchPartyKeysAsync(
                        allPartyIds.ToArray(),
                        cancellationToken).ConfigureAwait(false);

                    var builtCapsas = new List<BuiltCapsa>();
                    foreach (var builder in chunk)
                    {
                        var built = await builder.BuildAsync(partyKeys).ConfigureAwait(false);
                        builtCapsas.Add(built);
                    }

                    var multipartBuilder = new MultipartBuilder();
                    multipartBuilder.AddMetadata(chunk.Length, creatorId);

                    for (int capsaIndex = 0; capsaIndex < builtCapsas.Count; capsaIndex++)
                    {
                        var builtCapsa = builtCapsas[capsaIndex];
                        multipartBuilder.AddCapsaMetadata(builtCapsa.Capsa, capsaIndex);

                        foreach (var file in builtCapsa.Files)
                        {
                            multipartBuilder.AddFileBinary(file.Data, file.Metadata.FileId);
                        }
                    }

                    var body = multipartBuilder.Build();
                    var result = await SendWithRetryAsync(body, multipartBuilder.GetContentType(), cancellationToken).ConfigureAwait(false);

                    var adjustedCreated = result.Created
                        .Select(c => new CreatedCapsa { PackageId = c.PackageId, Index = c.Index + currentOffset })
                        .ToArray();

                    var adjustedErrors = result.Errors?
                        .Select(e => new SendError { Index = e.Index + currentOffset, PackageId = e.PackageId, Error = e.Error })
                        .ToArray();

                    results.Add(new SendResult
                    {
                        BatchId = result.BatchId,
                        Successful = result.Successful,
                        Failed = result.Failed,
                        PartialSuccess = result.PartialSuccess,
                        Created = adjustedCreated,
                        Errors = adjustedErrors
                    });

                    currentOffset += chunk.Length;
                }
                catch (Exception ex)
                {
                    var failedErrors = chunk.Select((_, index) => new SendError
                    {
                        Index = currentOffset + index,
                        PackageId = string.Empty,
                        Error = ex.Message
                    }).ToArray();

                    results.Add(new SendResult
                    {
                        BatchId = string.Empty,
                        Successful = 0,
                        Failed = chunk.Length,
                        PartialSuccess = false,
                        Created = Array.Empty<CreatedCapsa>(),
                        Errors = failedErrors
                    });

                    currentOffset += chunk.Length;
                }
            }

            var allErrors = results.SelectMany(r => r.Errors ?? Array.Empty<SendError>()).ToArray();
            var aggregated = new SendResult
            {
                BatchId = results.FirstOrDefault()?.BatchId ?? $"batch_{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}",
                Successful = results.Sum(r => r.Successful),
                Failed = results.Sum(r => r.Failed),
                PartialSuccess = results.Any(r => r.PartialSuccess == true) ||
                                 (results.Any(r => r.Successful > 0) && results.Any(r => r.Failed > 0)),
                Created = results.SelectMany(r => r.Created).ToArray(),
                Errors = allErrors.Length > 0 ? allErrors : null
            };

            return aggregated;
        }

        private async Task<SendResult> SendWithRetryAsync(
            byte[] body,
            string contentType,
            CancellationToken cancellationToken,
            int retryCount = 0)
        {
            using var content = new ByteArrayContent(body);
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("multipart/form-data");
            var boundaryValue = contentType.Substring(contentType.IndexOf("boundary=") + "boundary=".Length);
            content.Headers.ContentType.Parameters.Add(
                new System.Net.Http.Headers.NameValueHeaderValue("boundary", boundaryValue));

            try
            {
                var response = await _httpClient.PostAsync("/api/capsas", content, cancellationToken).ConfigureAwait(false);
                var responseBody = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                if (response.IsSuccessStatusCode || (int)response.StatusCode == 207)
                {
                    return JsonSerializer.Deserialize<SendResult>(responseBody, _jsonOptions)
                        ?? throw new CapsaraException("Invalid response", "INVALID_RESPONSE", (int)response.StatusCode);
                }

                var isRetryable = (int)response.StatusCode == 503 || (int)response.StatusCode == 429;
                if (isRetryable && retryCount < _retryConfig.MaxRetries)
                {
                    var retryDelay = CalculateRetryDelay(responseBody, retryCount);
                    await Task.Delay(retryDelay, cancellationToken).ConfigureAwait(false);
                    return await SendWithRetryAsync(body, contentType, cancellationToken, retryCount + 1).ConfigureAwait(false);
                }

                throw CapsaraCapsaException.FromHttpResponse(response.StatusCode, responseBody);
            }
            catch (HttpRequestException ex)
            {
                throw CapsaraException.NetworkError(ex);
            }
        }

        private TimeSpan CalculateRetryDelay(string responseBody, int retryCount)
        {
            try
            {
                using var doc = JsonDocument.Parse(responseBody);
                if (doc.RootElement.TryGetProperty("error", out var errorElement) &&
                    errorElement.TryGetProperty("retryAfter", out var retryAfterElement) &&
                    retryAfterElement.TryGetInt32(out var retryAfter))
                {
                    var serverDelay = TimeSpan.FromSeconds(retryAfter);
                    return serverDelay > _retryConfig.MaxDelay ? _retryConfig.MaxDelay : serverDelay;
                }
            }
            catch
            {
                // Parse failed, use exponential backoff
            }

            var exponentialDelay = _retryConfig.BaseDelay.TotalMilliseconds * Math.Pow(2, retryCount);
            var jitter = new Random().NextDouble() * 0.3 * exponentialDelay;
            var totalDelay = TimeSpan.FromMilliseconds(exponentialDelay + jitter);

            return totalDelay > _retryConfig.MaxDelay ? _retryConfig.MaxDelay : totalDelay;
        }
    }
}
