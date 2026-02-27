using System;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Capsara.SDK.Internal.Http;
using Capsara.SDK.Internal.Services;
using Capsara.SDK.Models;
using FluentAssertions;
using Xunit;

namespace Capsara.SDK.Tests.Services
{
    /// <summary>
    /// Tests for AuthService authentication and token management.
    /// Note: AuthService creates its own HttpClient internally, so these tests focus on
    /// state management, token handling, and JWT decoding that don't require network access.
    /// </summary>
    public class AuthServiceTests : IDisposable
    {
        private readonly string _baseUrl = "https://api.test.com";

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        public AuthServiceTests()
        {
        }

        public void Dispose()
        {
        }

        #region Token Management Tests

        [Fact]
        public void SetToken_SetsAccessToken()
        {
            // Arrange
            var authService = CreateAuthService();

            // Act
            authService.SetToken("test-token");

            // Assert
            authService.GetToken().Should().Be("test-token");
            authService.IsAuthenticated.Should().BeTrue();
        }

        [Fact]
        public void SetRefreshToken_SetsRefreshToken()
        {
            // Arrange
            var authService = CreateAuthService();

            // Act
            authService.SetRefreshToken("refresh-token");

            // Assert
            authService.GetRefreshToken().Should().Be("refresh-token");
            authService.CanRefresh.Should().BeTrue();
        }

        [Fact]
        public void SetTokens_SetsBothTokens()
        {
            // Arrange
            var authService = CreateAuthService();

            // Act
            authService.SetTokens("access-token", "refresh-token");

            // Assert
            authService.GetToken().Should().Be("access-token");
            authService.GetRefreshToken().Should().Be("refresh-token");
            authService.IsAuthenticated.Should().BeTrue();
            authService.CanRefresh.Should().BeTrue();
        }

        [Fact]
        public void SetTokens_WithNullRefresh_OnlyStoresAccess()
        {
            // Arrange
            var authService = CreateAuthService();

            // Act
            authService.SetTokens("access-token", null!);

            // Assert
            authService.GetToken().Should().Be("access-token");
            authService.GetRefreshToken().Should().BeNull();
            authService.CanRefresh.Should().BeFalse();
        }

        #endregion

        #region JWT Token Expiration Tests

        [Fact]
        public void IsTokenExpired_WithNoToken_ReturnsTrue()
        {
            // Arrange
            var authService = CreateAuthService();

            // Act & Assert
            authService.IsTokenExpired().Should().BeTrue();
        }

        [Fact]
        public void IsTokenExpired_WithValidJwtToken_ReturnsFalse()
        {
            // Arrange
            var authService = CreateAuthService();

            // Create a JWT with exp in the future (1 hour from now)
            var expiry = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds();
            var payload = Convert.ToBase64String(
                Encoding.UTF8.GetBytes($"{{\"exp\":{expiry}}}"))
                .Replace('+', '-').Replace('/', '_').TrimEnd('=');
            var token = $"header.{payload}.signature";

            authService.SetToken(token);

            // Act & Assert
            authService.IsTokenExpired().Should().BeFalse();
        }

        [Fact]
        public void IsTokenExpired_WithExpiredJwtToken_ReturnsTrue()
        {
            // Arrange
            var authService = CreateAuthService();

            // Create a JWT with exp in the past
            var expiry = DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds();
            var payload = Convert.ToBase64String(
                Encoding.UTF8.GetBytes($"{{\"exp\":{expiry}}}"))
                .Replace('+', '-').Replace('/', '_').TrimEnd('=');
            var token = $"header.{payload}.signature";

            authService.SetToken(token);

            // Act & Assert
            authService.IsTokenExpired().Should().BeTrue();
        }

        [Fact]
        public void IsTokenExpired_WithBuffer_ExpiresEarly()
        {
            // Arrange
            var authService = CreateAuthService();

            // Create a JWT that expires in 20 seconds
            var expiry = DateTimeOffset.UtcNow.AddSeconds(20).ToUnixTimeSeconds();
            var payload = Convert.ToBase64String(
                Encoding.UTF8.GetBytes($"{{\"exp\":{expiry}}}"))
                .Replace('+', '-').Replace('/', '_').TrimEnd('=');
            var token = $"header.{payload}.signature";

            authService.SetToken(token);

            // Act & Assert
            authService.IsTokenExpired(bufferSeconds: 30).Should().BeTrue(); // With 30s buffer, should be expired
            authService.IsTokenExpired(bufferSeconds: 10).Should().BeFalse(); // With 10s buffer, should not be expired
        }

        [Fact]
        public void IsTokenExpired_WithMalformedToken_ReturnsTrue()
        {
            // Arrange
            var authService = CreateAuthService();
            authService.SetToken("not-a-valid-jwt");

            // Act & Assert
            authService.IsTokenExpired().Should().BeTrue();
        }

        [Fact]
        public void IsTokenExpired_WithTokenMissingExp_ReturnsTrue()
        {
            // Arrange
            var authService = CreateAuthService();

            // Create a JWT without exp claim
            var payload = Convert.ToBase64String(
                Encoding.UTF8.GetBytes("{\"sub\":\"user123\"}"))
                .Replace('+', '-').Replace('/', '_').TrimEnd('=');
            var token = $"header.{payload}.signature";

            authService.SetToken(token);

            // Act & Assert
            authService.IsTokenExpired().Should().BeTrue();
        }

        #endregion

        #region Authentication State Tests

        [Fact]
        public void NewAuthService_IsNotAuthenticated()
        {
            // Arrange
            var authService = CreateAuthService();

            // Assert
            authService.IsAuthenticated.Should().BeFalse();
            authService.CanRefresh.Should().BeFalse();
            authService.GetToken().Should().BeNull();
            authService.GetRefreshToken().Should().BeNull();
        }

        [Fact]
        public void IsAuthenticated_WithToken_ReturnsTrue()
        {
            // Arrange
            var authService = CreateAuthService();

            // Act
            authService.SetToken("any-token");

            // Assert
            authService.IsAuthenticated.Should().BeTrue();
        }

        [Fact]
        public void CanRefresh_WithRefreshToken_ReturnsTrue()
        {
            // Arrange
            var authService = CreateAuthService();

            // Act
            authService.SetTokens("access-token", "refresh-token");

            // Assert
            authService.CanRefresh.Should().BeTrue();
        }

        [Fact]
        public void CanRefresh_WithoutRefreshToken_ReturnsFalse()
        {
            // Arrange
            var authService = CreateAuthService();

            // Act
            authService.SetToken("access-token");

            // Assert
            authService.CanRefresh.Should().BeFalse();
        }

        [Fact]
        public async Task RefreshAsync_WithoutRefreshToken_ReturnsFalse()
        {
            // Arrange
            var authService = CreateAuthService();
            authService.SetToken("access-token-only"); // No refresh token

            // Act - This doesn't make a network call because there's no refresh token
            var result = await authService.RefreshAsync();

            // Assert
            result.Should().BeFalse();
        }

        #endregion

        #region AuthServiceOptions Tests

        [Fact]
        public void AuthServiceOptions_DefaultValues_AreNull()
        {
            // Act
            var options = new AuthServiceOptions();

            // Assert
            options.ExpectedIssuer.Should().BeNull();
            options.ExpectedAudience.Should().BeNull();
            options.Timeout.Should().BeNull();
            options.Retry.Should().BeNull();
            options.UserAgent.Should().BeNull();
        }

        [Fact]
        public void AuthServiceOptions_WithValues_StoresCorrectly()
        {
            // Arrange & Act
            var options = new AuthServiceOptions
            {
                ExpectedIssuer = "test-issuer",
                ExpectedAudience = "test-audience",
                Timeout = new HttpTimeoutConfig { ApiTimeout = TimeSpan.FromSeconds(30) },
                Retry = new RetryConfig { MaxRetries = 5 },
                UserAgent = "TestAgent/1.0"
            };

            // Assert
            options.ExpectedIssuer.Should().Be("test-issuer");
            options.ExpectedAudience.Should().Be("test-audience");
            options.Timeout!.ApiTimeout.Should().Be(TimeSpan.FromSeconds(30));
            options.Retry!.MaxRetries.Should().Be(5);
            options.UserAgent.Should().Be("TestAgent/1.0");
        }

        #endregion

        #region AuthCredentials Model Tests

        [Fact]
        public void AuthCredentials_StoresValues()
        {
            // Act
            var credentials = new AuthCredentials("test@example.com", "password123");

            // Assert
            credentials.Email.Should().Be("test@example.com");
            credentials.Password.Should().Be("password123");
        }

        [Fact]
        public void AuthCredentials_SerializesToJson()
        {
            // Arrange
            var credentials = new AuthCredentials("test@example.com", "password123");

            // Act
            var json = JsonSerializer.Serialize(credentials, JsonOptions);
            var deserialized = JsonSerializer.Deserialize<AuthCredentials>(json, JsonOptions);

            // Assert
            deserialized.Should().NotBeNull();
            deserialized!.Email.Should().Be("test@example.com");
            deserialized.Password.Should().Be("password123");
        }

        #endregion

        #region AuthResponse Model Tests

        [Fact]
        public void AuthResponse_DeserializesFromJson()
        {
            // Arrange
            var json = @"{
                ""accessToken"": ""test-access-token"",
                ""refreshToken"": ""test-refresh-token"",
                ""expiresIn"": 3600,
                ""party"": {
                    ""id"": ""party_123"",
                    ""email"": ""test@example.com"",
                    ""name"": ""Test User"",
                    ""kind"": ""user""
                }
            }";

            // Act
            var response = JsonSerializer.Deserialize<AuthResponse>(json, JsonOptions);

            // Assert
            response.Should().NotBeNull();
            response!.AccessToken.Should().Be("test-access-token");
            response.RefreshToken.Should().Be("test-refresh-token");
            response.ExpiresIn.Should().Be(3600);
            response.Party.Should().NotBeNull();
            response.Party!.Id.Should().Be("party_123");
            response.Party.Email.Should().Be("test@example.com");
        }

        [Fact]
        public void AuthResponse_DefaultValues_AreCorrect()
        {
            // Act
            var response = new AuthResponse();

            // Assert
            response.AccessToken.Should().BeNullOrEmpty();
            response.RefreshToken.Should().BeNullOrEmpty();
            response.ExpiresIn.Should().Be(0);
        }

        #endregion

        #region AuthStateChangedEventArgs Tests

        [Fact]
        public void AuthStateChangedEventArgs_StoresValues()
        {
            // Act
            var args = new AuthStateChangedEventArgs(true, "login");

            // Assert
            args.IsAuthenticated.Should().BeTrue();
            args.Event.Should().Be("login");
        }

        [Theory]
        [InlineData(true, "login")]
        [InlineData(false, "logout")]
        [InlineData(true, "refresh")]
        [InlineData(false, "expired")]
        public void AuthStateChangedEventArgs_AcceptsVariousStates(bool isAuthenticated, string eventType)
        {
            // Act
            var args = new AuthStateChangedEventArgs(isAuthenticated, eventType);

            // Assert
            args.IsAuthenticated.Should().Be(isAuthenticated);
            args.Event.Should().Be(eventType);
        }

        #endregion

        #region PartyInfo Model Tests

        [Fact]
        public void PartyInfo_DeserializesFromJson()
        {
            // Arrange
            var json = @"{
                ""id"": ""party_123"",
                ""email"": ""test@example.com"",
                ""name"": ""Test User"",
                ""kind"": ""user""
            }";

            // Act
            var party = JsonSerializer.Deserialize<PartyInfo>(json, JsonOptions);

            // Assert
            party.Should().NotBeNull();
            party!.Id.Should().Be("party_123");
            party.Email.Should().Be("test@example.com");
            party.Name.Should().Be("Test User");
            party.Kind.Should().Be("user");
        }

        #endregion

        private AuthService CreateAuthService()
        {
            return new AuthService(_baseUrl, new AuthServiceOptions());
        }
    }
}
