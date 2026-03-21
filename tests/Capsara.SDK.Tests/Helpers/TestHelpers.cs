using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Capsara.SDK.Internal.Crypto;
using Capsara.SDK.Models;
using RichardSzalay.MockHttp;

namespace Capsara.SDK.Tests.Helpers
{
    /// <summary>
    /// Test helper utilities for SDK tests.
    /// </summary>
    public static class TestHelpers
    {
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        /// <summary>
        /// Create a mock HTTP client with the given handler.
        /// </summary>
        public static HttpClient CreateMockHttpClient(MockHttpMessageHandler mockHandler, string baseUrl = "https://api.test.com")
        {
            var client = mockHandler.ToHttpClient();
            client.BaseAddress = new Uri(baseUrl);
            return client;
        }

        /// <summary>
        /// Create a mock HTTP response with JSON content.
        /// </summary>
        public static StringContent JsonContent<T>(T data)
        {
            return new StringContent(
                JsonSerializer.Serialize(data, JsonOptions),
                Encoding.UTF8,
                "application/json");
        }

        /// <summary>
        /// Create a JSON response string.
        /// </summary>
        public static string ToJson<T>(T data)
        {
            return JsonSerializer.Serialize(data, JsonOptions);
        }

        /// <summary>
        /// Generate a test RSA key pair.
        /// On .NET Framework 4.8, RSACryptoServiceProvider can fail with some key formats.
        /// This method retries key generation until it produces a compatible key.
        /// </summary>
        public static GeneratedKeyPairResult GenerateTestKeyPair()
        {
            // On .NET Core/.NET 5+, key generation always works
            if (RuntimeInformation.FrameworkDescription.Contains(".NET Core") ||
                RuntimeInformation.FrameworkDescription.Contains(".NET 8") ||
                RuntimeInformation.FrameworkDescription.Contains(".NET 9"))
            {
                return KeyGenerator.GenerateKeyPair();
            }

            // On .NET Framework 4.8, sometimes keys fail to import with RSACryptoServiceProvider
            // Retry up to 10 times to get a compatible key
            for (int i = 0; i < 10; i++)
            {
                var keyPair = KeyGenerator.GenerateKeyPair();
                if (ValidateKeyPairOnNetFramework(keyPair))
                {
                    return keyPair;
                }
            }

            // If all retries fail, return the last generated key and let the test handle it
            return KeyGenerator.GenerateKeyPair();
        }

        /// <summary>
        /// Validates that a key pair works with RSACryptoServiceProvider on .NET Framework 4.8.
        /// </summary>
        private static bool ValidateKeyPairOnNetFramework(GeneratedKeyPairResult keyPair)
        {
            try
            {
                // Test that the private key can be imported
                using var rsa = new RSACryptoServiceProvider(4096);
                PemHelper.ImportPrivateKey(rsa, keyPair.PrivateKey);
                return true;
            }
            catch (CryptographicException)
            {
                return false;
            }
        }

        /// <summary>
        /// Generate a test AES-256 master key.
        /// </summary>
        public static byte[] GenerateTestMasterKey()
        {
            var key = new byte[32];
            using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
            rng.GetBytes(key);
            return key;
        }

        /// <summary>
        /// Create a test party ID.
        /// </summary>
        public static string GeneratePartyId()
        {
            return $"party_{Guid.NewGuid():N}".Substring(0, 20);
        }

        /// <summary>
        /// Create a test capsa ID.
        /// </summary>
        public static string GenerateCapsaId()
        {
            return $"pkg_{Guid.NewGuid():N}".Substring(0, 20);
        }

        /// <summary>
        /// Create a test file ID.
        /// </summary>
        public static string GenerateFileId()
        {
            return $"file_{Guid.NewGuid():N}".Substring(0, 20);
        }

        /// <summary>
        /// Create a test IV (12 bytes for AES-GCM).
        /// </summary>
        public static byte[] GenerateTestIV()
        {
            var iv = new byte[12];
            using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
            rng.GetBytes(iv);
            return iv;
        }

        /// <summary>
        /// Create a mock AuthResponse.
        /// </summary>
        public static AuthResponse CreateMockAuthResponse(string? partyId = null)
        {
            return new AuthResponse
            {
                Party = new PartyInfo
                {
                    Id = partyId ?? GeneratePartyId(),
                    Email = "test@example.com",
                    Name = "Test User",
                    Kind = "user"
                },
                AccessToken = "mock-access-token",
                RefreshToken = "mock-refresh-token",
                ExpiresIn = 3600
            };
        }

        /// <summary>
        /// Create a mock PartyKey.
        /// </summary>
        public static PartyKey CreateMockPartyKey(string? partyId = null, GeneratedKeyPairResult? keyPair = null)
        {
            keyPair ??= GenerateTestKeyPair();
            return new PartyKey
            {
                Id = partyId ?? GeneratePartyId(),
                Email = "test@example.com",
                PublicKey = keyPair.PublicKey,
                Fingerprint = keyPair.Fingerprint
            };
        }

        /// <summary>
        /// Create a mock Capsa response.
        /// </summary>
        public static Capsa CreateMockCapsa(
            string? capsaId = null,
            string? creatorId = null,
            EncryptedFile[]? files = null)
        {
            return new Capsa
            {
                Id = capsaId ?? GenerateCapsaId(),
                Creator = creatorId ?? GeneratePartyId(),
                CreatedAt = DateTimeOffset.UtcNow.ToString("o"),
                UpdatedAt = DateTimeOffset.UtcNow.ToString("o"),
                Status = "active",
                Files = files ?? Array.Empty<EncryptedFile>(),
                Keychain = new CapsaKeychain
                {
                    Algorithm = "RSA-OAEP-SHA256",
                    Keys = Array.Empty<KeychainEntry>()
                },
                Signature = new CapsaSignature
                {
                    Protected = "eyJhbGciOiJSUzI1NiJ9",
                    Payload = "eyJ0ZXN0IjoidGVzdCJ9",
                    Signature = Base64Url.Encode(new byte[512])
                },
                AccessControl = new CapsaAccessControl(),
                TotalSize = 0
            };
        }

        /// <summary>
        /// Create a mock EncryptedFile.
        /// </summary>
        public static EncryptedFile CreateMockEncryptedFile(string? fileId = null)
        {
            return new EncryptedFile
            {
                FileId = fileId ?? GenerateFileId(),
                Hash = HashProvider.ComputeHash(Encoding.UTF8.GetBytes("test")),
                Size = 100,
                OriginalSize = 100,
                IV = Base64Url.Encode(GenerateTestIV()),
                AuthTag = Base64Url.Encode(new byte[16]),
                EncryptedFilename = Base64Url.Encode(Encoding.UTF8.GetBytes("test.txt")),
                FilenameIV = Base64Url.Encode(GenerateTestIV()),
                FilenameAuthTag = Base64Url.Encode(new byte[16]),
                Mimetype = "text/plain",
                Compressed = false
            };
        }

        /// <summary>
        /// Create a mock AuditEntry.
        /// </summary>
        public static AuditEntry CreateMockAuditEntry(string action = "created", string? partyId = null)
        {
            return new AuditEntry
            {
                Timestamp = DateTimeOffset.UtcNow.ToString("o"),
                Party = partyId ?? GeneratePartyId(),
                Action = action,
                IpAddress = "127.0.0.1"
            };
        }

        /// <summary>
        /// Create a mock error response JSON.
        /// </summary>
        public static string CreateErrorResponse(string code, string message, Dictionary<string, object>? details = null)
        {
            var error = new
            {
                error = new
                {
                    code,
                    message,
                    details
                }
            };
            return JsonSerializer.Serialize(error, JsonOptions);
        }
    }

    /// <summary>
    /// Mock HTTP message handler for testing retry logic.
    /// </summary>
    public class MockRetryHandler : HttpMessageHandler
    {
        private readonly Queue<Func<HttpRequestMessage, HttpResponseMessage>> _responses = new();
        private readonly List<HttpRequestMessage> _requests = new();

        public IReadOnlyList<HttpRequestMessage> Requests => _requests;
        public int RequestCount => _requests.Count;

        public void AddResponse(HttpStatusCode statusCode, string? content = null)
        {
            _responses.Enqueue(_ => new HttpResponseMessage(statusCode)
            {
                // Always set Content to avoid null reference in RetryHandler.GetServerSuggestedDelayAsync
                Content = new StringContent(content ?? "", Encoding.UTF8, "application/json")
            });
        }

        public void AddResponse(Func<HttpRequestMessage, HttpResponseMessage> responseFactory)
        {
            _responses.Enqueue(responseFactory);
        }

        public void AddException(Exception exception)
        {
            _responses.Enqueue(_ => throw exception);
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            _requests.Add(request);

            if (_responses.Count == 0)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
            }

            var factory = _responses.Dequeue();
            return Task.FromResult(factory(request));
        }
    }
}
