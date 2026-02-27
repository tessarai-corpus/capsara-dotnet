using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Capsara.SDK.Builder;
using Capsara.SDK.Internal.Crypto;
using Capsara.SDK.Internal.Decryptor;
using Capsara.SDK.Models;
using Capsara.SDK.Tests.Helpers;
using FluentAssertions;
using Xunit;

namespace Capsara.SDK.Tests.Golden
{
    /// <summary>
    /// Golden tests for CapsaDecryptor: wrong private key, signature verification,
    /// encrypted key length validation, and master key size validation.
    /// </summary>
    [Collection("SharedKeys")]
    public class ReceiveGoldenTests
    {
        private readonly GeneratedKeyPairResult _creatorKeyPair;
        private readonly GeneratedKeyPairResult _recipientKeyPair;
        private readonly GeneratedKeyPairResult _wrongKeyPair;
        private readonly string _creatorId;

        public ReceiveGoldenTests(SharedKeyFixture fixture)
        {
            _creatorKeyPair = fixture.PrimaryKeyPair;
            _recipientKeyPair = fixture.SecondaryKeyPair;
            _wrongKeyPair = fixture.TertiaryKeyPair;
            _creatorId = TestHelpers.GeneratePartyId();
        }

        #region Wrong Private Key Tests

        [Fact]
        public async Task Decrypt_WithWrongPrivateKey_Throws()
        {
            // Arrange - Build a capsa with creator key
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput { Filename = "test.txt", Data = Encoding.UTF8.GetBytes("secret data") });
            builder.Subject = "Secret Subject";

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };
            var built = await builder.BuildAsync(partyKeys);

            // Create a Capsa model from the built result
            var capsa = CreateCapsaFromBuilt(built, _creatorId);

            // Act & Assert - Trying to decrypt with wrong private key should fail
            Assert.ThrowsAny<Exception>(() =>
                CapsaDecryptor.Decrypt(capsa, _wrongKeyPair.PrivateKey, _creatorId, _creatorKeyPair.PublicKey, true));
        }

        [Fact]
        public async Task Decrypt_WithCorrectPrivateKey_Succeeds()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput { Filename = "test.txt", Data = Encoding.UTF8.GetBytes("content") });
            builder.Subject = "My Subject";

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };
            var built = await builder.BuildAsync(partyKeys);

            var capsa = CreateCapsaFromBuilt(built, _creatorId);

            // Act
            var decrypted = CapsaDecryptor.Decrypt(capsa, _creatorKeyPair.PrivateKey, _creatorId, _creatorKeyPair.PublicKey, true);

            // Assert
            decrypted.Should().NotBeNull();
            decrypted.Subject.Should().Be("My Subject");
        }

        #endregion

        #region Signature Verification Tests

        [Fact]
        public async Task Decrypt_WithSignatureVerification_InvalidSignature_Throws()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput { Filename = "test.txt", Data = new byte[10] });

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };
            var built = await builder.BuildAsync(partyKeys);

            var capsa = CreateCapsaFromBuilt(built, _creatorId);

            // Tamper with signature
            capsa.Signature.Signature = Base64Url.Encode(new byte[512]);

            // Act & Assert - Signature verification should fail
            Assert.ThrowsAny<Exception>(() =>
                CapsaDecryptor.Decrypt(capsa, _creatorKeyPair.PrivateKey, _creatorId, _creatorKeyPair.PublicKey, true));
        }

        [Fact]
        public async Task Decrypt_SkipSignatureVerification_Succeeds()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput { Filename = "test.txt", Data = new byte[10] });

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };
            var built = await builder.BuildAsync(partyKeys);

            var capsa = CreateCapsaFromBuilt(built, _creatorId);

            // Tamper with signature
            capsa.Signature.Signature = Base64Url.Encode(new byte[512]);

            // Act - Skip signature verification
            var decrypted = CapsaDecryptor.Decrypt(capsa, _creatorKeyPair.PrivateKey, _creatorId, null, false);

            // Assert
            decrypted.Should().NotBeNull();
        }

        [Fact]
        public async Task Decrypt_WithVerificationButNoPublicKey_Throws()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput { Filename = "test.txt", Data = new byte[10] });

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };
            var built = await builder.BuildAsync(partyKeys);

            var capsa = CreateCapsaFromBuilt(built, _creatorId);

            // Act & Assert - Requesting verification without providing public key
            Assert.Throws<InvalidOperationException>(() =>
                CapsaDecryptor.Decrypt(capsa, _creatorKeyPair.PrivateKey, _creatorId, null, true));
        }

        [Fact]
        public void Decrypt_MissingSignature_Throws()
        {
            // Arrange - Capsa with no signature
            var capsa = TestHelpers.CreateMockCapsa();
            capsa.Signature = new CapsaSignature();
            capsa.Keychain = new CapsaKeychain
            {
                Algorithm = "RSA-OAEP-SHA256",
                Keys = new[] { new KeychainEntry { Party = _creatorId, EncryptedKey = "test" } }
            };

            // Act & Assert
            Assert.ThrowsAny<Exception>(() =>
                CapsaDecryptor.Decrypt(capsa, _creatorKeyPair.PrivateKey, _creatorId, _creatorKeyPair.PublicKey, true));
        }

        #endregion

        #region Encrypted Key Length Tests

        [Fact]
        public void Decrypt_InvalidEncryptedKeyLength_Throws()
        {
            // Arrange - Capsa with wrong-length encrypted key
            var capsa = TestHelpers.CreateMockCapsa();
            capsa.Keychain = new CapsaKeychain
            {
                Algorithm = "RSA-OAEP-SHA256",
                Keys = new[]
                {
                    new KeychainEntry
                    {
                        Party = _creatorId,
                        EncryptedKey = Base64Url.Encode(new byte[256]) // Wrong size: should be 512
                    }
                }
            };

            // Act & Assert
            Assert.ThrowsAny<Exception>(() =>
                CapsaDecryptor.Decrypt(capsa, _creatorKeyPair.PrivateKey, _creatorId, null, false));
        }

        [Fact]
        public void Decrypt_EmptyEncryptedKey_Throws()
        {
            // Arrange
            var capsa = TestHelpers.CreateMockCapsa();
            capsa.Keychain = new CapsaKeychain
            {
                Algorithm = "RSA-OAEP-SHA256",
                Keys = new[]
                {
                    new KeychainEntry
                    {
                        Party = _creatorId,
                        EncryptedKey = "" // Empty - delegated recipient with no key
                    }
                }
            };

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() =>
                CapsaDecryptor.Decrypt(capsa, _creatorKeyPair.PrivateKey, _creatorId, null, false));
        }

        #endregion

        #region Master Key Size Validation Tests

        [Fact]
        public async Task Decrypt_ProducesMasterKeyOf32Bytes()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput { Filename = "test.txt", Data = new byte[10] });

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };
            var built = await builder.BuildAsync(partyKeys);

            var capsa = CreateCapsaFromBuilt(built, _creatorId);

            // Act
            using var decrypted = CapsaDecryptor.Decrypt(capsa, _creatorKeyPair.PrivateKey, _creatorId, _creatorKeyPair.PublicKey, true);

            // Assert - Master key should be exactly 32 bytes (AES-256)
            var masterKey = decrypted.GetMasterKey();
            masterKey.Length.Should().Be(32);
        }

        [Fact]
        public async Task DecryptedCapsa_DisposeClearsMasterKey()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput { Filename = "test.txt", Data = new byte[10] });

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };
            var built = await builder.BuildAsync(partyKeys);

            var capsa = CreateCapsaFromBuilt(built, _creatorId);

            // Act
            var decrypted = CapsaDecryptor.Decrypt(capsa, _creatorKeyPair.PrivateKey, _creatorId, _creatorKeyPair.PublicKey, true);
            decrypted.Dispose();

            // Assert - Accessing master key after dispose should throw
            Assert.Throws<ObjectDisposedException>(() => decrypted.GetMasterKey());
        }

        #endregion

        #region Party Not Found Tests

        [Fact]
        public void Decrypt_PartyNotInKeychain_Throws()
        {
            // Arrange
            var capsa = TestHelpers.CreateMockCapsa();
            capsa.Keychain = new CapsaKeychain
            {
                Algorithm = "RSA-OAEP-SHA256",
                Keys = new[]
                {
                    new KeychainEntry
                    {
                        Party = "other_party",
                        EncryptedKey = Base64Url.Encode(new byte[512])
                    }
                }
            };

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() =>
                CapsaDecryptor.Decrypt(capsa, _creatorKeyPair.PrivateKey, _creatorId, null, false));
        }

        [Fact]
        public void Decrypt_EmptyKeychain_Throws()
        {
            // Arrange
            var capsa = TestHelpers.CreateMockCapsa();
            capsa.Keychain = new CapsaKeychain
            {
                Algorithm = "RSA-OAEP-SHA256",
                Keys = Array.Empty<KeychainEntry>()
            };

            // Act & Assert - No party ID, empty keychain
            Assert.Throws<InvalidOperationException>(() =>
                CapsaDecryptor.Decrypt(capsa, _creatorKeyPair.PrivateKey, null, null, false));
        }

        #endregion

        #region Helpers

        private static Capsa CreateCapsaFromBuilt(BuiltCapsa built, string creatorId)
        {
            return new Capsa
            {
                Id = built.Capsa.PackageId,
                Creator = creatorId,
                CreatedAt = DateTimeOffset.UtcNow.ToString("o"),
                UpdatedAt = DateTimeOffset.UtcNow.ToString("o"),
                Status = "active",
                Files = built.Capsa.Files,
                Keychain = built.Capsa.Keychain,
                Signature = built.Capsa.Signature,
                AccessControl = built.Capsa.AccessControl,
                EncryptedSubject = built.Capsa.EncryptedSubject,
                SubjectIV = built.Capsa.SubjectIV,
                SubjectAuthTag = built.Capsa.SubjectAuthTag,
                EncryptedBody = built.Capsa.EncryptedBody,
                BodyIV = built.Capsa.BodyIV,
                BodyAuthTag = built.Capsa.BodyAuthTag,
                EncryptedStructured = built.Capsa.EncryptedStructured,
                StructuredIV = built.Capsa.StructuredIV,
                StructuredAuthTag = built.Capsa.StructuredAuthTag,
                TotalSize = built.Capsa.Files.Sum(f => f.Size)
            };
        }

        #endregion
    }
}
