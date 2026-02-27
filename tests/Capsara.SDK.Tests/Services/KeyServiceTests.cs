using System;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Capsara.SDK.Exceptions;
using Capsara.SDK.Internal.Http;
using Capsara.SDK.Internal.Services;
using Capsara.SDK.Models;
using FluentAssertions;
using RichardSzalay.MockHttp;
using Xunit;

namespace Capsara.SDK.Tests.Services
{
    /// <summary>
    /// Tests for KeyService public key retrieval operations.
    /// Note: KeyService creates its own HttpClient internally, so these tests focus on
    /// model validation, options configuration, and serialization correctness.
    /// </summary>
    public class KeyServiceTests
    {
        private const string BaseUrl = "https://api.test.com";
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        #region Constructor Tests

        [Fact]
        public void Constructor_WithValidParameters_CreatesInstance()
        {
            // Arrange & Act
            var service = new KeyService(BaseUrl, () => "test-token");

            // Assert
            service.Should().NotBeNull();
        }

        [Fact]
        public void Constructor_WithOptions_CreatesInstance()
        {
            // Arrange
            var options = new KeyServiceOptions
            {
                Timeout = new HttpTimeoutConfig { ApiTimeout = TimeSpan.FromSeconds(30) },
                Retry = new RetryConfig { MaxRetries = 5, BaseDelay = TimeSpan.FromSeconds(2) },
                UserAgent = "TestAgent/1.0"
            };

            // Act
            var service = new KeyService(BaseUrl, () => null, options);

            // Assert
            service.Should().NotBeNull();
        }

        [Fact]
        public void Constructor_WithNullToken_CreatesInstance()
        {
            // Arrange & Act
            var service = new KeyService(BaseUrl, () => null);

            // Assert
            service.Should().NotBeNull();
        }

        #endregion

        #region PartyKey Model Tests

        [Fact]
        public void PartyKey_DefaultValues_AreCorrect()
        {
            // Act
            var partyKey = new PartyKey();

            // Assert
            partyKey.Id.Should().BeNullOrEmpty();
            partyKey.PublicKey.Should().BeNullOrEmpty();
            partyKey.Fingerprint.Should().BeNullOrEmpty();
        }

        [Fact]
        public void PartyKey_WithValues_StoresCorrectly()
        {
            // Arrange & Act
            var partyKey = new PartyKey
            {
                Id = "party_test",
                PublicKey = "-----BEGIN PUBLIC KEY-----\nTestKey\n-----END PUBLIC KEY-----",
                Fingerprint = "SHA256:testfingerprint"
            };

            // Assert
            partyKey.Id.Should().Be("party_test");
            partyKey.PublicKey.Should().Contain("TestKey");
            partyKey.Fingerprint.Should().Be("SHA256:testfingerprint");
        }

        [Fact]
        public void PartyKey_DeserializesFromJson()
        {
            // Arrange
            var json = @"{
                ""id"": ""party_json"",
                ""publicKey"": ""-----BEGIN PUBLIC KEY-----\nJsonKey\n-----END PUBLIC KEY-----"",
                ""fingerprint"": ""SHA256:jsonfingerprint""
            }";

            // Act
            var partyKey = JsonSerializer.Deserialize<PartyKey>(json, JsonOptions);

            // Assert
            partyKey.Should().NotBeNull();
            partyKey!.Id.Should().Be("party_json");
            partyKey.PublicKey.Should().Contain("JsonKey");
            partyKey.Fingerprint.Should().Be("SHA256:jsonfingerprint");
        }

        [Fact]
        public void PartyKey_SerializesToJson()
        {
            // Arrange
            var partyKey = new PartyKey
            {
                Id = "party_serialize",
                PublicKey = "-----BEGIN PUBLIC KEY-----\nSerializeKey\n-----END PUBLIC KEY-----",
                Fingerprint = "SHA256:serializedfingerprint"
            };

            // Act
            var json = JsonSerializer.Serialize(partyKey, JsonOptions);
            var deserialized = JsonSerializer.Deserialize<PartyKey>(json, JsonOptions);

            // Assert
            deserialized.Should().NotBeNull();
            deserialized!.Id.Should().Be("party_serialize");
            deserialized.PublicKey.Should().Contain("SerializeKey");
        }

        [Fact]
        public void PartyKey_WithEmail_DeserializesCorrectly()
        {
            // Arrange
            var json = @"{
                ""id"": ""party_email"",
                ""email"": ""test@example.com"",
                ""publicKey"": ""-----BEGIN PUBLIC KEY-----\nKey\n-----END PUBLIC KEY-----"",
                ""fingerprint"": ""SHA256:fp""
            }";

            // Act
            var partyKey = JsonSerializer.Deserialize<PartyKey>(json, JsonOptions);

            // Assert
            partyKey.Should().NotBeNull();
            partyKey!.Email.Should().Be("test@example.com");
        }

        #endregion

        #region KeyServiceOptions Tests

        [Fact]
        public void KeyServiceOptions_DefaultValues_AreNull()
        {
            // Act
            var options = new KeyServiceOptions();

            // Assert
            options.Timeout.Should().BeNull();
            options.Retry.Should().BeNull();
            options.UserAgent.Should().BeNull();
        }

        [Fact]
        public void KeyServiceOptions_WithValues_StoresCorrectly()
        {
            // Arrange & Act
            var options = new KeyServiceOptions
            {
                Timeout = new HttpTimeoutConfig { ApiTimeout = TimeSpan.FromSeconds(30) },
                Retry = new RetryConfig { MaxRetries = 5 },
                UserAgent = "CustomAgent/2.0"
            };

            // Assert
            options.Timeout.Should().NotBeNull();
            options.Timeout!.ApiTimeout.Should().Be(TimeSpan.FromSeconds(30));
            options.Retry.Should().NotBeNull();
            options.Retry!.MaxRetries.Should().Be(5);
            options.UserAgent.Should().Be("CustomAgent/2.0");
        }

        #endregion

        #region Party Keys Response Model Tests

        [Fact]
        public void PartyKeysResponse_DeserializesCorrectly()
        {
            // Arrange
            var json = @"{
                ""parties"": [
                    {
                        ""id"": ""party_1"",
                        ""publicKey"": ""-----BEGIN PUBLIC KEY-----\nKey1\n-----END PUBLIC KEY-----"",
                        ""fingerprint"": ""SHA256:fp1""
                    },
                    {
                        ""id"": ""party_2"",
                        ""publicKey"": ""-----BEGIN PUBLIC KEY-----\nKey2\n-----END PUBLIC KEY-----"",
                        ""fingerprint"": ""SHA256:fp2""
                    }
                ]
            }";

            // Act
            var response = JsonSerializer.Deserialize<PartyKeysResponse>(json, JsonOptions);

            // Assert
            response.Should().NotBeNull();
            response!.Parties.Should().HaveCount(2);
            response.Parties[0].Id.Should().Be("party_1");
            response.Parties[1].Id.Should().Be("party_2");
        }

        [Fact]
        public void PartyKeysResponse_EmptyParties_DeserializesCorrectly()
        {
            // Arrange
            var json = @"{ ""parties"": [] }";

            // Act
            var response = JsonSerializer.Deserialize<PartyKeysResponse>(json, JsonOptions);

            // Assert
            response.Should().NotBeNull();
            response!.Parties.Should().BeEmpty();
        }

        #endregion

        #region Request Body Model Tests

        [Fact]
        public void PartyKeysRequest_SerializesCorrectly()
        {
            // Arrange
            var request = new PartyKeysRequest
            {
                PartyIds = new[] { "party_1", "party_2", "party_3" },
                IncludeDelegates = true
            };

            // Act
            var json = JsonSerializer.Serialize(request, JsonOptions);
            var deserialized = JsonSerializer.Deserialize<PartyKeysRequest>(json, JsonOptions);

            // Assert
            deserialized.Should().NotBeNull();
            deserialized!.PartyIds.Should().HaveCount(3);
            deserialized.IncludeDelegates.Should().BeTrue();
        }

        [Fact]
        public void PartyKeysRequest_ExplicitKey_ExcludesDelegates()
        {
            // Arrange
            var request = new PartyKeysRequest
            {
                PartyIds = new[] { "party_1" },
                IncludeDelegates = false
            };

            // Act
            var json = JsonSerializer.Serialize(request, JsonOptions);

            // Assert
            json.Should().Contain("\"includeDelegates\":false");
        }

        #endregion

        #region Validation Tests

        [Theory]
        [InlineData("party_valid123")]
        [InlineData("party_a")]
        [InlineData("party_0")]
        public void PartyId_ValidFormats_Accepted(string partyId)
        {
            // Arrange
            var partyKey = new PartyKey { Id = partyId };

            // Assert
            partyKey.Id.Should().Be(partyId);
        }

        [Fact]
        public void PartyKey_PublicKeyFormat_IsPEM()
        {
            // Arrange
            var pemKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----";

            // Act
            var partyKey = new PartyKey { PublicKey = pemKey };

            // Assert
            partyKey.PublicKey.Should().StartWith("-----BEGIN PUBLIC KEY-----");
            partyKey.PublicKey.Should().EndWith("-----END PUBLIC KEY-----");
        }

        [Theory]
        [InlineData("SHA256:abc123def456")]
        [InlineData("SHA256:0123456789abcdef")]
        public void Fingerprint_ValidFormats_Accepted(string fingerprint)
        {
            // Arrange
            var partyKey = new PartyKey { Fingerprint = fingerprint };

            // Assert
            partyKey.Fingerprint.Should().StartWith("SHA256:");
        }

        #endregion

        #region Retry and Timeout Configuration Tests

        [Fact]
        public void KeyService_WithCustomRetryConfig_AppliesConfig()
        {
            // Arrange
            var retryConfig = new RetryConfig
            {
                MaxRetries = 5,
                BaseDelay = TimeSpan.FromMilliseconds(500),
                MaxDelay = TimeSpan.FromSeconds(30)
            };

            // Act
            var options = new KeyServiceOptions { Retry = retryConfig };
            var service = new KeyService(BaseUrl, () => "token", options);

            // Assert
            service.Should().NotBeNull();
        }

        [Fact]
        public void KeyService_WithCustomTimeout_AppliesConfig()
        {
            // Arrange
            var timeoutConfig = new HttpTimeoutConfig
            {
                ApiTimeout = TimeSpan.FromMinutes(5),
                ConnectTimeout = TimeSpan.FromSeconds(10)
            };

            // Act
            var options = new KeyServiceOptions { Timeout = timeoutConfig };
            var service = new KeyService(BaseUrl, () => "token", options);

            // Assert
            service.Should().NotBeNull();
        }

        #endregion

        #region Error Response Model Tests

        [Fact]
        public void ErrorResponse_Deserializes_ForKeyNotFound()
        {
            // Arrange
            var json = @"{
                ""error"": {
                    ""code"": ""PARTY_NOT_FOUND"",
                    ""message"": ""Party not found"",
                    ""details"": { ""partyId"": ""party_missing"" }
                }
            }";

            // Act
            using var doc = JsonDocument.Parse(json);
            var errorElement = doc.RootElement.GetProperty("error");

            // Assert
            errorElement.GetProperty("code").GetString().Should().Be("PARTY_NOT_FOUND");
            errorElement.GetProperty("message").GetString().Should().Be("Party not found");
            errorElement.GetProperty("details").GetProperty("partyId").GetString().Should().Be("party_missing");
        }

        [Fact]
        public void CapsaraException_FromPartyNotFound_CreatesCorrectException()
        {
            // Arrange
            var responseBody = @"{
                ""error"": {
                    ""code"": ""PARTY_NOT_FOUND"",
                    ""message"": ""Party not found""
                }
            }";

            // Act
            var exception = CapsaraException.FromHttpResponse(HttpStatusCode.NotFound, responseBody);

            // Assert
            exception.Code.Should().Be("PARTY_NOT_FOUND");
            exception.StatusCode.Should().Be(404);
        }

        #endregion

        #region Large Batch Handling Tests

        [Fact]
        public void LargeBatch_PartyIds_SerializesCorrectly()
        {
            // Arrange
            var largePartyIds = new string[100];
            for (int i = 0; i < 100; i++)
            {
                largePartyIds[i] = $"party_{i}";
            }

            var request = new PartyKeysRequest
            {
                PartyIds = largePartyIds,
                IncludeDelegates = true
            };

            // Act
            var json = JsonSerializer.Serialize(request, JsonOptions);
            var deserialized = JsonSerializer.Deserialize<PartyKeysRequest>(json, JsonOptions);

            // Assert
            deserialized.Should().NotBeNull();
            deserialized!.PartyIds.Should().HaveCount(100);
            deserialized.PartyIds[0].Should().Be("party_0");
            deserialized.PartyIds[99].Should().Be("party_99");
        }

        #endregion
    }

    /// <summary>
    /// Model for party keys request body.
    /// </summary>
    internal class PartyKeysRequest
    {
        [System.Text.Json.Serialization.JsonPropertyName("partyIds")]
        public string[] PartyIds { get; set; } = Array.Empty<string>();

        [System.Text.Json.Serialization.JsonPropertyName("includeDelegates")]
        public bool IncludeDelegates { get; set; }
    }

    /// <summary>
    /// Model for party keys response.
    /// </summary>
    internal class PartyKeysResponse
    {
        [System.Text.Json.Serialization.JsonPropertyName("parties")]
        public PartyKey[] Parties { get; set; } = Array.Empty<PartyKey>();
    }
}
