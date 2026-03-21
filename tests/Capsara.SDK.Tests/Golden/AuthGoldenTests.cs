using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Capsara.SDK.Exceptions;
using Capsara.SDK.Models;
using Capsara.SDK.Tests.Helpers;
using FluentAssertions;
using RichardSzalay.MockHttp;
using Xunit;

namespace Capsara.SDK.Tests.Golden
{
    /// <summary>
    /// Golden tests for authentication state management, credential validation, and token state.
    /// </summary>
    public class AuthGoldenTests
    {
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        #region Client Authentication State Tests

        [Fact]
        public void NewClient_IsNotAuthenticated()
        {
            // Arrange & Act
            using var client = new CapsaraClient("https://api.test.com");

            // Assert
            client.IsAuthenticated.Should().BeFalse();
        }

        [Fact]
        public void NewClient_WithAccessToken_IsAuthenticated()
        {
            // Arrange
            var options = new CapsaraClientOptions { AccessToken = "mock-token" };

            // Act
            using var client = new CapsaraClient("https://api.test.com", options);

            // Assert
            client.IsAuthenticated.Should().BeTrue();
        }

        [Fact]
        public void Constructor_NullBaseUrl_Throws()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => new CapsaraClient(null!));
        }

        [Fact]
        public void Constructor_WithOptions_DoesNotThrow()
        {
            // Arrange
            var options = new CapsaraClientOptions
            {
                ExpectedIssuer = "test-issuer",
                ExpectedAudience = "test-audience",
                MaxBatchSize = 50
            };

            // Act
            using var client = new CapsaraClient("https://api.test.com", options);

            // Assert
            client.Should().NotBeNull();
        }

        #endregion

        #region Credential Validation Tests

        [Fact]
        public void AuthCredentials_DefaultConstructor_SetsEmptyStrings()
        {
            // Act
            var credentials = new AuthCredentials();

            // Assert
            credentials.Email.Should().Be(string.Empty);
            credentials.Password.Should().Be(string.Empty);
        }

        [Fact]
        public void AuthCredentials_ParameterizedConstructor_SetsValues()
        {
            // Act
            var credentials = new AuthCredentials("user@example.com", "secureP@ssw0rd");

            // Assert
            credentials.Email.Should().Be("user@example.com");
            credentials.Password.Should().Be("secureP@ssw0rd");
        }

        [Fact]
        public void AuthCredentials_SerializesCorrectly()
        {
            // Arrange
            var credentials = new AuthCredentials("test@test.com", "password123");

            // Act
            var json = JsonSerializer.Serialize(credentials, JsonOptions);

            // Assert
            json.Should().Contain("\"email\":\"test@test.com\"");
            json.Should().Contain("\"password\":\"password123\"");
        }

        [Fact]
        public void AuthCredentials_DeserializesCorrectly()
        {
            // Arrange
            var json = "{\"email\":\"user@test.com\",\"password\":\"pass\"}";

            // Act
            var credentials = JsonSerializer.Deserialize<AuthCredentials>(json, JsonOptions);

            // Assert
            credentials.Should().NotBeNull();
            credentials!.Email.Should().Be("user@test.com");
            credentials.Password.Should().Be("pass");
        }

        #endregion

        #region AuthResponse Model Tests

        [Fact]
        public void AuthResponse_DefaultConstructor_SetsDefaults()
        {
            // Act
            var response = new AuthResponse();

            // Assert
            response.Party.Should().NotBeNull();
            response.AccessToken.Should().Be(string.Empty);
            response.RefreshToken.Should().Be(string.Empty);
            response.ExpiresIn.Should().Be(0);
        }

        [Fact]
        public void AuthResponse_DeserializesFromJson()
        {
            // Arrange
            var json = JsonSerializer.Serialize(new
            {
                party = new { id = "party_123", email = "test@test.com", name = "Test", kind = "user" },
                accessToken = "jwt-token",
                refreshToken = "refresh-token",
                expiresIn = 3600
            }, JsonOptions);

            // Act
            var response = JsonSerializer.Deserialize<AuthResponse>(json, JsonOptions);

            // Assert
            response.Should().NotBeNull();
            response!.Party.Id.Should().Be("party_123");
            response.AccessToken.Should().Be("jwt-token");
            response.RefreshToken.Should().Be("refresh-token");
            response.ExpiresIn.Should().Be(3600);
        }

        [Fact]
        public void PartyInfo_DeserializesAllFields()
        {
            // Arrange
            var json = JsonSerializer.Serialize(new
            {
                id = "party_abc",
                email = "alice@example.com",
                name = "Alice",
                kind = "user",
                publicKey = "-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----",
                publicKeyFingerprint = "abc123"
            }, JsonOptions);

            // Act
            var party = JsonSerializer.Deserialize<PartyInfo>(json, JsonOptions);

            // Assert
            party.Should().NotBeNull();
            party!.Id.Should().Be("party_abc");
            party.Email.Should().Be("alice@example.com");
            party.Name.Should().Be("Alice");
            party.Kind.Should().Be("user");
            party.PublicKey.Should().Contain("BEGIN PUBLIC KEY");
            party.PublicKeyFingerprint.Should().Be("abc123");
        }

        #endregion

        #region SetPrivateKey Tests

        [Fact]
        public void SetPrivateKey_NullPrivateKey_Throws()
        {
            // Arrange
            using var client = new CapsaraClient("https://api.test.com");

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => client.SetPrivateKey(null!));
        }

        [Fact]
        public async Task CreateCapsaBuilderAsync_WithoutIdentity_Throws()
        {
            // Arrange
            using var client = new CapsaraClient("https://api.test.com");

            // Act & Assert
            await Assert.ThrowsAsync<InvalidOperationException>(
                () => client.CreateCapsaBuilderAsync());
        }

        #endregion
    }
}
