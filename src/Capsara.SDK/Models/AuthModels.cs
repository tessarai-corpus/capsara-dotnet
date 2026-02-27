using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Capsara.SDK.Models
{
    /// <summary>
    /// Custom converter for isDelegate which can be boolean or string[].
    /// </summary>
    internal sealed class IsDelegateConverter : JsonConverter<string[]?>
    {
        public override string[]? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType == JsonTokenType.Null)
            {
                return null;
            }

            if (reader.TokenType == JsonTokenType.True)
            {
                return Array.Empty<string>();
            }

            if (reader.TokenType == JsonTokenType.False)
            {
                return null;
            }

            if (reader.TokenType == JsonTokenType.StartArray)
            {
                var list = new System.Collections.Generic.List<string>();
                while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
                {
                    if (reader.TokenType == JsonTokenType.String)
                    {
                        list.Add(reader.GetString() ?? string.Empty);
                    }
                }
                return list.ToArray();
            }

            throw new JsonException($"Unexpected token type for isDelegate: {reader.TokenType}");
        }

        public override void Write(Utf8JsonWriter writer, string[]? value, JsonSerializerOptions options)
        {
            if (value == null)
            {
                writer.WriteNullValue();
            }
            else if (value.Length == 0)
            {
                writer.WriteBooleanValue(true);
            }
            else
            {
                writer.WriteStartArray();
                foreach (var item in value)
                {
                    writer.WriteStringValue(item);
                }
                writer.WriteEndArray();
            }
        }
    }

    /// <summary>Login credentials for party authentication.</summary>
    public sealed class AuthCredentials
    {
        /// <summary>Email address of the party.</summary>
        [JsonPropertyName("email")]
        public string Email { get; set; } = string.Empty;

        /// <summary>Password for the party account.</summary>
        [JsonPropertyName("password")]
        public string Password { get; set; } = string.Empty;

        /// <summary>Initializes a new instance of <see cref="AuthCredentials"/>.</summary>
        public AuthCredentials() { }

        /// <summary>Initializes a new instance of <see cref="AuthCredentials"/> with the specified email and password.</summary>
        /// <param name="email">Email address of the party.</param>
        /// <param name="password">Password for the party account.</param>
        public AuthCredentials(string email, string password)
        {
            Email = email;
            Password = password;
        }
    }

    /// <summary>Authenticated party profile returned after login.</summary>
    public sealed class PartyInfo
    {
        /// <summary>Unique identifier for the party.</summary>
        [JsonPropertyName("id")]
        public string Id { get; set; } = string.Empty;

        /// <summary>Email address of the party.</summary>
        [JsonPropertyName("email")]
        public string Email { get; set; } = string.Empty;

        /// <summary>Display name of the party.</summary>
        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        /// <summary>Party kind (e.g., "user", "system").</summary>
        [JsonPropertyName("kind")]
        public string Kind { get; set; } = string.Empty;

        /// <summary>PEM format.</summary>
        [JsonPropertyName("publicKey")]
        public string? PublicKey { get; set; }

        /// <summary>SHA-256 hex.</summary>
        [JsonPropertyName("publicKeyFingerprint")]
        public string? PublicKeyFingerprint { get; set; }
    }

    /// <summary>Authentication response containing tokens and party profile.</summary>
    public sealed class AuthResponse
    {
        /// <summary>Authenticated party profile.</summary>
        [JsonPropertyName("party")]
        public PartyInfo Party { get; set; } = new();

        /// <summary>JWT access token for API authorization.</summary>
        [JsonPropertyName("accessToken")]
        public string AccessToken { get; set; } = string.Empty;

        /// <summary>Refresh token for obtaining new access tokens.</summary>
        [JsonPropertyName("refreshToken")]
        public string RefreshToken { get; set; } = string.Empty;

        /// <summary>Expiration in seconds.</summary>
        [JsonPropertyName("expiresIn")]
        public int ExpiresIn { get; set; }
    }

    /// <summary>Public key record for a party, used for encrypting master keys.</summary>
    public sealed class PartyKey
    {
        /// <summary>Unique identifier for the party.</summary>
        [JsonPropertyName("id")]
        public string Id { get; set; } = string.Empty;

        /// <summary>Email address of the party.</summary>
        [JsonPropertyName("email")]
        public string Email { get; set; } = string.Empty;

        /// <summary>PEM format.</summary>
        [JsonPropertyName("publicKey")]
        public string PublicKey { get; set; } = string.Empty;

        /// <summary>SHA-256 hex.</summary>
        [JsonPropertyName("fingerprint")]
        public string Fingerprint { get; set; } = string.Empty;

        /// <summary>
        /// Party IDs this delegate acts for, or null if not a delegate.
        /// An empty array indicates a delegate without specific targets.
        /// </summary>
        [JsonPropertyName("isDelegate")]
        [JsonConverter(typeof(IsDelegateConverter))]
        public string[]? IsDelegate { get; set; }
    }

    /// <summary>Configuration for a capsa recipient, including permissions and delegation.</summary>
    public sealed class RecipientConfig
    {
        /// <summary>Unique identifier of the recipient party.</summary>
        [JsonPropertyName("partyId")]
        public string PartyId { get; set; } = string.Empty;

        /// <summary>Permissions granted to this recipient (e.g., "read", "delegate").</summary>
        [JsonPropertyName("permissions")]
        public string[] Permissions { get; set; } = new[] { "read" };

        /// <summary>Party IDs this delegate represents.</summary>
        [JsonPropertyName("actingFor")]
        public string[]? ActingFor { get; set; }

        /// <summary>Initializes a new instance of <see cref="RecipientConfig"/>.</summary>
        public RecipientConfig() { }

        /// <summary>Initializes a new instance of <see cref="RecipientConfig"/> with the specified party ID and permissions.</summary>
        /// <param name="partyId">Unique identifier of the recipient party.</param>
        /// <param name="permissions">Permissions to grant. Defaults to "read" if none specified.</param>
        public RecipientConfig(string partyId, params string[] permissions)
        {
            PartyId = partyId;
            Permissions = permissions.Length > 0 ? permissions : new[] { "read" };
        }
    }
}
