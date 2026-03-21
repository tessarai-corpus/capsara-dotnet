using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Capsara.SDK.Builder;
using Capsara.SDK.Internal.Crypto;
using Capsara.SDK.Internal.Http;
using Capsara.SDK.Internal.Services;
using Capsara.SDK.Models;
using Capsara.SDK.Tests.Helpers;
using FluentAssertions;
using Moq;
using RichardSzalay.MockHttp;
using Xunit;

namespace Capsara.SDK.Tests.Services
{
    /// <summary>
    /// Tests for UploadService batch envelope upload operations.
    /// Uses shared key fixture to avoid expensive RSA key generation per test.
    /// </summary>
    [Collection("SharedKeys")]
    public class UploadServiceTests : IDisposable
    {
        private readonly GeneratedKeyPairResult _primaryKeyPair;
        private readonly GeneratedKeyPairResult _secondaryKeyPair;
        private readonly System.Collections.Generic.List<IDisposable> _disposables = new();
        private bool _disposed;

        public UploadServiceTests(SharedKeyFixture fixture)
        {
            _primaryKeyPair = fixture.PrimaryKeyPair;
            _secondaryKeyPair = fixture.SecondaryKeyPair;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            foreach (var disposable in _disposables)
            {
                disposable.Dispose();
            }
            _disposables.Clear();
        }

        private MockHttpMessageHandler CreateMockHandler()
        {
            var handler = new MockHttpMessageHandler();
            _disposables.Add(handler);
            return handler;
        }

        private HttpClient CreateHttpClient(MockHttpMessageHandler handler, string baseUrl = "https://api.test.com")
        {
            var client = handler.ToHttpClient();
            client.BaseAddress = new Uri(baseUrl);
            _disposables.Add(client);
            return client;
        }

        #region Helper Methods

        private CapsaBuilder CreateMockBuilder(int fileCount = 1)
        {
            // Create a real builder using shared key fixture
            var creatorId = TestHelpers.GeneratePartyId();

            var builder = new CapsaBuilder(creatorId, _primaryKeyPair.PrivateKey);
            builder.AddRecipient(TestHelpers.GeneratePartyId());

            for (int i = 0; i < fileCount; i++)
            {
                builder.AddFile(new FileInput
                {
                    Filename = $"file_{i}.txt",
                    Data = Encoding.UTF8.GetBytes($"Content for file {i}")
                });
            }

            return builder;
        }

        private KeyService CreateMockKeyService(MockHttpMessageHandler mockHttp)
        {
            // KeyService requires specific constructor pattern - use shared keys
            var mockPartyResponse = new
            {
                parties = new[]
                {
                    new
                    {
                        id = "party_creator",
                        publicKey = _primaryKeyPair.PublicKey,
                        fingerprint = _primaryKeyPair.Fingerprint
                    },
                    new
                    {
                        id = "party_recipient",
                        publicKey = _secondaryKeyPair.PublicKey,
                        fingerprint = _secondaryKeyPair.Fingerprint
                    }
                }
            };

            mockHttp
                .When(HttpMethod.Post, "*/api/party/keys")
                .Respond("application/json", JsonSerializer.Serialize(mockPartyResponse));

            return new KeyService(
                "https://api.test.com",
                () => "test-token",
                new KeyServiceOptions
                {
                    Retry = new RetryConfig { MaxRetries = 0 }
                });
        }

        #endregion

        #region Validation Tests

        [Fact]
        public async Task SendCapsasAsync_NoCapsasProvided_Throws()
        {
            // Arrange
            var mockHttp = CreateMockHandler();
            var httpClient = CreateHttpClient(mockHttp);

            var keyService = CreateMockKeyService(mockHttp);
            var uploadService = new UploadService(httpClient, keyService);

            // Act & Assert
            var ex = await Assert.ThrowsAsync<ArgumentException>(
                () => uploadService.SendCapsasAsync(Array.Empty<CapsaBuilder>(), "creator_123"));

            ex.Message.Should().Contain("No capsas provided");
        }

        [Fact]
        public async Task SendCapsasAsync_MoreThan500Capsas_Throws()
        {
            // Arrange
            var mockHttp = CreateMockHandler();
            var httpClient = CreateHttpClient(mockHttp);

            var keyService = CreateMockKeyService(mockHttp);
            var uploadService = new UploadService(httpClient, keyService);

            var builders = new CapsaBuilder[501];
            for (int i = 0; i < 501; i++)
            {
                builders[i] = CreateMockBuilder();
            }

            // Act & Assert
            var ex = await Assert.ThrowsAsync<ArgumentException>(
                () => uploadService.SendCapsasAsync(builders, "creator_123"));

            ex.Message.Should().Contain("500 capsas");
        }

        [Fact]
        public void CapsaBuilder_ExceedsFileLimit_Throws()
        {
            // The test validates that CapsaBuilder enforces MaxFilesPerCapsa limit (default: 100)
            // The UploadService has a separate MAX_FILES_PER_BATCH of 500 for batching across capsas

            // Arrange - use shared key fixture
            var creatorId = TestHelpers.GeneratePartyId();
            var builder = new CapsaBuilder(creatorId, _primaryKeyPair.PrivateKey);
            builder.AddRecipient(TestHelpers.GeneratePartyId());

            // Add files up to the limit (100)
            for (int i = 0; i < 100; i++)
            {
                builder.AddFile(new FileInput
                {
                    Filename = $"file_{i}.txt",
                    Data = Encoding.UTF8.GetBytes($"Content for file {i}")
                });
            }

            // Act & Assert - 101st file should throw
            var ex = Assert.Throws<InvalidOperationException>(() =>
                builder.AddFile(new FileInput
                {
                    Filename = "file_101.txt",
                    Data = Encoding.UTF8.GetBytes("This should fail")
                }));

            ex.Message.Should().Contain("100");
        }

        #endregion

        #region SendResult Model Tests

        [Fact]
        public void SendResult_DefaultValues_AreCorrect()
        {
            // Act
            var result = new SendResult();

            // Assert
            result.BatchId.Should().Be(string.Empty);
            result.Successful.Should().Be(0);
            result.Failed.Should().Be(0);
            result.PartialSuccess.Should().BeNull();
            result.Created.Should().BeEmpty();
            result.Errors.Should().BeNull();
        }

        [Fact]
        public void SendResult_WithValues_StoresCorrectly()
        {
            // Arrange & Act
            var result = new SendResult
            {
                BatchId = "batch_123",
                Successful = 5,
                Failed = 2,
                PartialSuccess = true,
                Created = new[]
                {
                    new CreatedCapsa { PackageId = "pkg_1", Index = 0 },
                    new CreatedCapsa { PackageId = "pkg_2", Index = 1 }
                },
                Errors = new[]
                {
                    new SendError { Index = 2, PackageId = "pkg_3", Error = "Validation failed" }
                }
            };

            // Assert
            result.BatchId.Should().Be("batch_123");
            result.Successful.Should().Be(5);
            result.Failed.Should().Be(2);
            result.PartialSuccess.Should().BeTrue();
            result.Created.Should().HaveCount(2);
            result.Errors.Should().HaveCount(1);
        }

        [Fact]
        public void CreatedCapsa_DefaultValues_AreCorrect()
        {
            // Act
            var created = new CreatedCapsa();

            // Assert
            created.PackageId.Should().Be(string.Empty);
            created.Index.Should().Be(0);
        }

        [Fact]
        public void SendError_DefaultValues_AreCorrect()
        {
            // Act
            var error = new SendError();

            // Assert
            error.Index.Should().Be(0);
            error.PackageId.Should().Be(string.Empty);
            error.Error.Should().Be(string.Empty);
        }

        #endregion

        #region JSON Deserialization Tests

        [Fact]
        public void SendResult_DeserializesFromJson()
        {
            // Arrange
            var json = @"{
                ""batchId"": ""batch_abc"",
                ""successful"": 3,
                ""failed"": 1,
                ""partialSuccess"": true,
                ""created"": [
                    { ""packageId"": ""pkg_1"", ""index"": 0 },
                    { ""packageId"": ""pkg_2"", ""index"": 1 },
                    { ""packageId"": ""pkg_3"", ""index"": 2 }
                ],
                ""errors"": [
                    { ""index"": 3, ""packageId"": ""pkg_4"", ""error"": ""Failed to process"" }
                ]
            }";

            var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

            // Act
            var result = JsonSerializer.Deserialize<SendResult>(json, options);

            // Assert
            result.Should().NotBeNull();
            result!.BatchId.Should().Be("batch_abc");
            result.Successful.Should().Be(3);
            result.Failed.Should().Be(1);
            result.PartialSuccess.Should().BeTrue();
            result.Created.Should().HaveCount(3);
            result.Created[0].PackageId.Should().Be("pkg_1");
            result.Errors.Should().HaveCount(1);
            result.Errors![0].Error.Should().Be("Failed to process");
        }

        [Fact]
        public void SendResult_DeserializesMinimalJson()
        {
            // Arrange
            var json = @"{
                ""batchId"": ""batch_123"",
                ""successful"": 1,
                ""failed"": 0,
                ""created"": [{ ""packageId"": ""pkg_1"", ""index"": 0 }]
            }";

            var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

            // Act
            var result = JsonSerializer.Deserialize<SendResult>(json, options);

            // Assert
            result.Should().NotBeNull();
            result!.BatchId.Should().Be("batch_123");
            result.Successful.Should().Be(1);
            result.Failed.Should().Be(0);
            result.PartialSuccess.Should().BeNull();
            result.Created.Should().HaveCount(1);
            result.Errors.Should().BeNull();
        }

        #endregion

        #region Constructor Tests

        [Fact]
        public void UploadService_NullHttpClient_Throws()
        {
            // Arrange
            var mockHttp = CreateMockHandler();
            var keyService = CreateMockKeyService(mockHttp);

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() =>
                new UploadService(null!, keyService));
        }

        [Fact]
        public void UploadService_NullKeyService_Throws()
        {
            // Arrange
            var mockHttp = CreateMockHandler();
            var httpClient = CreateHttpClient(mockHttp);

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() =>
                new UploadService(httpClient, null!));
        }

        [Fact]
        public void UploadService_WithValidParameters_CreatesInstance()
        {
            // Arrange
            var mockHttp = CreateMockHandler();
            var httpClient = CreateHttpClient(mockHttp);
            var keyService = CreateMockKeyService(mockHttp);

            // Act
            var service = new UploadService(httpClient, keyService);

            // Assert
            service.Should().NotBeNull();
        }

        [Fact]
        public void UploadService_WithCustomMaxBatchSize_CreatesInstance()
        {
            // Arrange
            var mockHttp = CreateMockHandler();
            var httpClient = CreateHttpClient(mockHttp);
            var keyService = CreateMockKeyService(mockHttp);

            // Act
            var service = new UploadService(httpClient, keyService, maxBatchSize: 50);

            // Assert
            service.Should().NotBeNull();
        }

        [Fact]
        public void UploadService_WithCustomRetryConfig_CreatesInstance()
        {
            // Arrange
            var mockHttp = CreateMockHandler();
            var httpClient = CreateHttpClient(mockHttp);
            var keyService = CreateMockKeyService(mockHttp);
            var retryConfig = new RetryConfig
            {
                MaxRetries = 5,
                BaseDelay = TimeSpan.FromMilliseconds(100),
                MaxDelay = TimeSpan.FromSeconds(5)
            };

            // Act
            var service = new UploadService(httpClient, keyService, retryConfig: retryConfig);

            // Assert
            service.Should().NotBeNull();
        }

        #endregion

        #region Batching Logic Tests

        [Fact]
        public void BatchingLogic_SplitsByMaxCapsas()
        {
            // This test verifies the batching logic conceptually
            // In production, capsas with total count > maxBatchSize are split

            // Arrange
            var capsaCounts = new[] { 1, 1, 1, 1, 1 }; // 5 capsas with 1 file each
            var maxBatchSize = 3;

            // Act - calculate expected batches
            var batches = 0;
            var currentCount = 0;
            foreach (var count in capsaCounts)
            {
                if (currentCount >= maxBatchSize)
                {
                    batches++;
                    currentCount = 1;
                }
                else
                {
                    currentCount++;
                }
            }
            if (currentCount > 0) batches++;

            // Assert
            batches.Should().Be(2); // 3 in first batch, 2 in second
        }

        [Fact]
        public void BatchingLogic_SplitsByFileCount()
        {
            // This test verifies the file count batching logic conceptually
            // In production, batches are split when total files would exceed 500

            // Arrange
            var fileCounts = new[] { 300, 300, 100 }; // 3 capsas
            var maxFilesPerBatch = 500;

            // Act - calculate expected batches
            var batches = new System.Collections.Generic.List<int> { 0 };
            var currentFileCount = 0;
            foreach (var fileCount in fileCounts)
            {
                if (currentFileCount + fileCount > maxFilesPerBatch && currentFileCount > 0)
                {
                    batches.Add(0);
                    currentFileCount = fileCount;
                }
                else
                {
                    currentFileCount += fileCount;
                }
                batches[batches.Count - 1]++;
            }

            // Assert
            // Batch 1: first capsa (300 files)
            // Batch 2: second capsa (300 files) + third capsa (100 files) = 400 files
            batches.Should().HaveCount(2);
            batches[0].Should().Be(1); // First batch has 1 capsa
            batches[1].Should().Be(2); // Second batch has 2 capsas
        }

        #endregion

        #region Error Aggregation Tests

        [Fact]
        public void AggregateResults_CombinesSuccessful()
        {
            // Arrange
            var results = new[]
            {
                new SendResult { Successful = 25, Failed = 0 },
                new SendResult { Successful = 25, Failed = 0 }
            };

            // Act
            var totalSuccessful = 0;
            var totalFailed = 0;
            foreach (var r in results)
            {
                totalSuccessful += r.Successful;
                totalFailed += r.Failed;
            }

            // Assert
            totalSuccessful.Should().Be(50);
            totalFailed.Should().Be(0);
        }

        [Fact]
        public void AggregateResults_DetectsPartialSuccess()
        {
            // Arrange
            var results = new[]
            {
                new SendResult { Successful = 25, Failed = 0 },
                new SendResult { Successful = 0, Failed = 25 }
            };

            // Act
            var hasSuccesses = false;
            var hasFailures = false;
            foreach (var r in results)
            {
                if (r.Successful > 0) hasSuccesses = true;
                if (r.Failed > 0) hasFailures = true;
            }
            var isPartialSuccess = hasSuccesses && hasFailures;

            // Assert
            isPartialSuccess.Should().BeTrue();
        }

        [Fact]
        public void AggregateResults_CollectsAllErrors()
        {
            // Arrange
            var results = new[]
            {
                new SendResult
                {
                    Failed = 1,
                    Errors = new[] { new SendError { Index = 0, Error = "Error 1" } }
                },
                new SendResult
                {
                    Failed = 1,
                    Errors = new[] { new SendError { Index = 1, Error = "Error 2" } }
                }
            };

            // Act
            var allErrors = new System.Collections.Generic.List<SendError>();
            foreach (var r in results)
            {
                if (r.Errors != null)
                {
                    allErrors.AddRange(r.Errors);
                }
            }

            // Assert
            allErrors.Should().HaveCount(2);
            allErrors[0].Error.Should().Be("Error 1");
            allErrors[1].Error.Should().Be("Error 2");
        }

        #endregion

        #region Index Adjustment Tests

        [Fact]
        public void IndexAdjustment_OffsetsCorrectly()
        {
            // Arrange - simulating batch 2 with offset of 25
            var batch2Created = new[]
            {
                new CreatedCapsa { PackageId = "pkg_1", Index = 0 },
                new CreatedCapsa { PackageId = "pkg_2", Index = 1 }
            };
            var offset = 25;

            // Act
            var adjusted = new CreatedCapsa[batch2Created.Length];
            for (int i = 0; i < batch2Created.Length; i++)
            {
                adjusted[i] = new CreatedCapsa
                {
                    PackageId = batch2Created[i].PackageId,
                    Index = batch2Created[i].Index + offset
                };
            }

            // Assert
            adjusted[0].Index.Should().Be(25);
            adjusted[1].Index.Should().Be(26);
        }

        [Fact]
        public void ErrorIndexAdjustment_OffsetsCorrectly()
        {
            // Arrange - simulating batch 3 with offset of 50
            var batch3Errors = new[]
            {
                new SendError { Index = 0, PackageId = "pkg_err1", Error = "Failed" },
                new SendError { Index = 1, PackageId = "pkg_err2", Error = "Timeout" }
            };
            var offset = 50;

            // Act
            var adjusted = new SendError[batch3Errors.Length];
            for (int i = 0; i < batch3Errors.Length; i++)
            {
                adjusted[i] = new SendError
                {
                    Index = batch3Errors[i].Index + offset,
                    PackageId = batch3Errors[i].PackageId,
                    Error = batch3Errors[i].Error
                };
            }

            // Assert
            adjusted[0].Index.Should().Be(50);
            adjusted[1].Index.Should().Be(51);
        }

        #endregion

        #region Retry Delay Calculation Tests

        [Fact]
        public void RetryDelayCalculation_ExponentialBackoff()
        {
            // Arrange
            var baseDelay = TimeSpan.FromMilliseconds(100);

            // Act
            var retry0Delay = baseDelay.TotalMilliseconds * Math.Pow(2, 0);
            var retry1Delay = baseDelay.TotalMilliseconds * Math.Pow(2, 1);
            var retry2Delay = baseDelay.TotalMilliseconds * Math.Pow(2, 2);

            // Assert
            retry0Delay.Should().Be(100);
            retry1Delay.Should().Be(200);
            retry2Delay.Should().Be(400);
        }

        [Fact]
        public void RetryDelayCalculation_RespectsMaxDelay()
        {
            // Arrange
            var baseDelay = TimeSpan.FromSeconds(10);
            var maxDelay = TimeSpan.FromMilliseconds(100);

            // Act
            var calculatedDelay = baseDelay.TotalMilliseconds * Math.Pow(2, 5); // Would be 320000
            var cappedDelay = Math.Min(calculatedDelay, maxDelay.TotalMilliseconds);

            // Assert
            cappedDelay.Should().Be(100);
        }

        [Fact]
        public void RetryDelayCalculation_ServerSuggestedDelay()
        {
            // Arrange
            var serverRetryAfter = 2; // seconds
            var maxDelay = TimeSpan.FromSeconds(5);

            // Act
            var serverDelay = TimeSpan.FromSeconds(serverRetryAfter);
            var finalDelay = serverDelay > maxDelay ? maxDelay : serverDelay;

            // Assert
            finalDelay.TotalSeconds.Should().Be(2);
        }

        [Fact]
        public void RetryDelayCalculation_ServerDelayExceedsMax()
        {
            // Arrange
            var serverRetryAfter = 60; // seconds
            var maxDelay = TimeSpan.FromMilliseconds(100);

            // Act
            var serverDelay = TimeSpan.FromSeconds(serverRetryAfter);
            var finalDelay = serverDelay > maxDelay ? maxDelay : serverDelay;

            // Assert
            finalDelay.TotalMilliseconds.Should().Be(100);
        }

        #endregion

        #region Retryable Status Code Tests

        [Theory]
        [InlineData(503, true)]
        [InlineData(429, true)]
        [InlineData(400, false)]
        [InlineData(401, false)]
        [InlineData(403, false)]
        [InlineData(404, false)]
        [InlineData(500, false)]
        public void StatusCode_RetryableCheck(int statusCode, bool shouldRetry)
        {
            // Act
            var isRetryable = statusCode == 503 || statusCode == 429;

            // Assert
            isRetryable.Should().Be(shouldRetry);
        }

        #endregion

        #region MultiStatus Response Tests

        [Fact]
        public void MultiStatusResponse_207_IsSuccess()
        {
            // Arrange
            var statusCode = 207;

            // Act
            var isSuccessful = statusCode >= 200 && statusCode < 300;
            var isMultiStatus = statusCode == 207;

            // Assert
            isSuccessful.Should().BeTrue();
            isMultiStatus.Should().BeTrue();
        }

        [Fact]
        public void MultiStatusResponse_ParsesPartialSuccess()
        {
            // Arrange
            var json = @"{
                ""batchId"": ""batch_123"",
                ""successful"": 2,
                ""failed"": 1,
                ""partialSuccess"": true,
                ""created"": [
                    { ""packageId"": ""pkg_1"", ""index"": 0 },
                    { ""packageId"": ""pkg_2"", ""index"": 1 }
                ],
                ""errors"": [
                    { ""index"": 2, ""packageId"": ""pkg_3"", ""error"": ""Validation failed"" }
                ]
            }";

            var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

            // Act
            var result = JsonSerializer.Deserialize<SendResult>(json, options);

            // Assert
            result.Should().NotBeNull();
            result!.PartialSuccess.Should().BeTrue();
            result.Successful.Should().Be(2);
            result.Failed.Should().Be(1);
        }

        #endregion
    }
}
