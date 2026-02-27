using System;
using System.Text;
using Capsara.SDK.Internal.Crypto;
using Capsara.SDK.Tests.Helpers;
using FluentAssertions;
using Xunit;

namespace Capsara.SDK.Tests.Crypto
{
    /// <summary>
    /// Tests for RSA-4096-OAEP encryption/decryption operations.
    /// Uses shared key fixture to avoid expensive RSA key generation per test class.
    /// </summary>
    [Collection("SharedKeys")]
    public class RsaProviderTests
    {
        private readonly GeneratedKeyPairResult _keyPair;
        private readonly GeneratedKeyPairResult _otherKeyPair;
        private readonly GeneratedKeyPairResult _thirdKeyPair;

        public RsaProviderTests(SharedKeyFixture fixture)
        {
            _keyPair = fixture.PrimaryKeyPair;
            _otherKeyPair = fixture.SecondaryKeyPair;
            _thirdKeyPair = fixture.TertiaryKeyPair;
        }

        #region Basic Round-Trip Tests

        [Fact]
        public void EncryptDecrypt_MasterKey_RoundTrip()
        {
            var masterKey = SecureMemory.GenerateRandomBytes(32);

            var encrypted = RsaProvider.EncryptMasterKey(masterKey, _keyPair.PublicKey);
            var decrypted = RsaProvider.DecryptMasterKey(encrypted, _keyPair.PrivateKey);

            Assert.Equal(masterKey, decrypted);
        }

        [Fact]
        public void EncryptDecrypt_MultipleKeys_AllSucceed()
        {
            for (int i = 0; i < 5; i++)
            {
                var masterKey = SecureMemory.GenerateRandomBytes(32);
                var encrypted = RsaProvider.EncryptMasterKey(masterKey, _keyPair.PublicKey);
                var decrypted = RsaProvider.DecryptMasterKey(encrypted, _keyPair.PrivateKey);

                decrypted.Should().Equal(masterKey);
            }
        }

        #endregion

        #region Encryption Output Tests

        [Fact]
        public void EncryptMasterKey_ProducesBase64UrlOutput()
        {
            var masterKey = SecureMemory.GenerateRandomBytes(32);

            var encrypted = RsaProvider.EncryptMasterKey(masterKey, _keyPair.PublicKey);

            // Should be valid base64url
            Assert.DoesNotContain("+", encrypted);
            Assert.DoesNotContain("/", encrypted);
            Assert.DoesNotContain("=", encrypted);
        }

        [Fact]
        public void EncryptMasterKey_RSA4096_Produces512Bytes()
        {
            var masterKey = SecureMemory.GenerateRandomBytes(32);

            var encrypted = RsaProvider.EncryptMasterKey(masterKey, _keyPair.PublicKey);
            var encryptedBytes = Base64Url.Decode(encrypted);

            // RSA-4096 OAEP produces 512-byte output
            Assert.Equal(512, encryptedBytes.Length);
        }

        [Fact]
        public void EncryptMasterKey_ProducesDifferentOutputsWithSameInput()
        {
            var masterKey = SecureMemory.GenerateRandomBytes(32);

            var encrypted1 = RsaProvider.EncryptMasterKey(masterKey, _keyPair.PublicKey);
            var encrypted2 = RsaProvider.EncryptMasterKey(masterKey, _keyPair.PublicKey);

            // RSA-OAEP uses random padding, so encryptions should differ
            Assert.NotEqual(encrypted1, encrypted2);
        }

        [Fact]
        public void EncryptMasterKey_Base64UrlOutput_ValidCharacters()
        {
            var masterKey = SecureMemory.GenerateRandomBytes(32);
            var encrypted = RsaProvider.EncryptMasterKey(masterKey, _keyPair.PublicKey);

            // Base64url uses only A-Z, a-z, 0-9, -, _
            foreach (var c in encrypted)
            {
                var isValid = (c >= 'A' && c <= 'Z') ||
                             (c >= 'a' && c <= 'z') ||
                             (c >= '0' && c <= '9') ||
                             c == '-' || c == '_';
                isValid.Should().BeTrue($"Character '{c}' should be valid base64url");
            }
        }

        #endregion

        #region Decryption Failure Tests

        [Fact]
        public void DecryptMasterKey_WithWrongPrivateKey_Throws()
        {
            var masterKey = SecureMemory.GenerateRandomBytes(32);

            var encrypted = RsaProvider.EncryptMasterKey(masterKey, _keyPair.PublicKey);

            Assert.ThrowsAny<Exception>(() =>
                RsaProvider.DecryptMasterKey(encrypted, _otherKeyPair.PrivateKey));
        }

        [Fact]
        public void DecryptMasterKey_CorruptedCiphertext_Throws()
        {
            var masterKey = SecureMemory.GenerateRandomBytes(32);
            var encrypted = RsaProvider.EncryptMasterKey(masterKey, _keyPair.PublicKey);

            // Corrupt the ciphertext by changing the first character
            var corrupted = encrypted[0] == 'A' ? 'B' + encrypted.Substring(1) : 'A' + encrypted.Substring(1);

            Assert.ThrowsAny<Exception>(() =>
                RsaProvider.DecryptMasterKey(corrupted, _keyPair.PrivateKey));
        }

        [Fact]
        public void DecryptMasterKey_TruncatedCiphertext_Throws()
        {
            var masterKey = SecureMemory.GenerateRandomBytes(32);
            var encrypted = RsaProvider.EncryptMasterKey(masterKey, _keyPair.PublicKey);

            // Truncate ciphertext
            var truncated = encrypted.Substring(0, encrypted.Length / 2);

            Assert.ThrowsAny<Exception>(() =>
                RsaProvider.DecryptMasterKey(truncated, _keyPair.PrivateKey));
        }

        #endregion

        #region Master Key Validation Tests

        [Fact]
        public void EncryptMasterKey_InvalidKeySize_Throws()
        {
            // SDK only supports AES-256 (32-byte) master keys
            var key16 = SecureMemory.GenerateRandomBytes(16);  // AES-128
            var key24 = SecureMemory.GenerateRandomBytes(24);  // AES-192

            Assert.Throws<ArgumentException>(() =>
                RsaProvider.EncryptMasterKey(key16, _keyPair.PublicKey));

            Assert.Throws<ArgumentException>(() =>
                RsaProvider.EncryptMasterKey(key24, _keyPair.PublicKey));
        }

        [Fact]
        public void EncryptMasterKey_31ByteKey_Throws()
        {
            var key31 = SecureMemory.GenerateRandomBytes(31);  // Off by one

            Assert.Throws<ArgumentException>(() =>
                RsaProvider.EncryptMasterKey(key31, _keyPair.PublicKey));
        }

        [Fact]
        public void EncryptMasterKey_33ByteKey_Throws()
        {
            var key33 = SecureMemory.GenerateRandomBytes(33);  // Off by one

            Assert.Throws<ArgumentException>(() =>
                RsaProvider.EncryptMasterKey(key33, _keyPair.PublicKey));
        }

        [Fact]
        public void EncryptMasterKey_EmptyKey_Throws()
        {
            var emptyKey = Array.Empty<byte>();

            Assert.Throws<ArgumentException>(() =>
                RsaProvider.EncryptMasterKey(emptyKey, _keyPair.PublicKey));
        }

        #endregion

        #region Fingerprint Tests

        [Fact]
        public void ComputeFingerprint_ReturnsConsistentValue()
        {
            var fingerprint1 = RsaProvider.ComputeFingerprint(_keyPair.PublicKey);
            var fingerprint2 = RsaProvider.ComputeFingerprint(_keyPair.PublicKey);

            Assert.Equal(fingerprint1, fingerprint2);
            Assert.Equal(64, fingerprint1.Length); // SHA-256 hex = 64 chars
            Assert.Matches("^[a-f0-9]+$", fingerprint1); // Lowercase hex
        }

        [Fact]
        public void ComputeFingerprint_DifferentKeys_DifferentFingerprints()
        {
            var fingerprint1 = RsaProvider.ComputeFingerprint(_keyPair.PublicKey);
            var fingerprint2 = RsaProvider.ComputeFingerprint(_otherKeyPair.PublicKey);

            fingerprint1.Should().NotBe(fingerprint2);
        }

        [Fact]
        public void ComputeFingerprint_AlwaysLowercase()
        {
            var fingerprint = RsaProvider.ComputeFingerprint(_keyPair.PublicKey);

            fingerprint.Should().Be(fingerprint.ToLowerInvariant());
            fingerprint.Should().NotMatchRegex("[A-F]"); // No uppercase hex
        }

        [Fact]
        public void ComputeFingerprint_ReturnsValidSha256Hex()
        {
            var fingerprint = RsaProvider.ComputeFingerprint(_keyPair.PublicKey);

            fingerprint.Should().HaveLength(64); // SHA-256 = 256 bits = 32 bytes = 64 hex chars
            fingerprint.Should().MatchRegex("^[a-f0-9]+$");
        }

        #endregion

        #region Key Validation Tests

        [Fact]
        public void ValidateKeySize_ValidKey_ReturnsTrue()
        {
            Assert.True(RsaProvider.ValidateKeySize(_keyPair.PublicKey));
        }

        [Fact]
        public void ValidateKeySize_NullOrEmpty_ReturnsFalse()
        {
            Assert.False(RsaProvider.ValidateKeySize(null!));
            Assert.False(RsaProvider.ValidateKeySize(""));
        }

        [Fact]
        public void ValidateKeySize_WhitespaceOnly_ReturnsFalse()
        {
            Assert.False(RsaProvider.ValidateKeySize("   "));
            Assert.False(RsaProvider.ValidateKeySize("\t\n"));
        }

        [Fact]
        public void ValidateKeySize_InvalidPem_ReturnsFalse()
        {
            Assert.False(RsaProvider.ValidateKeySize("not a valid pem key"));
        }

        #endregion

        #region PEM Format Tests

        [Fact]
        public void PublicKey_HasCorrectPemFormat()
        {
            _keyPair.PublicKey.Should().StartWith("-----BEGIN PUBLIC KEY-----");
            _keyPair.PublicKey.TrimEnd().Should().EndWith("-----END PUBLIC KEY-----");
        }

        [Fact]
        public void PrivateKey_HasCorrectPemFormat()
        {
            // .NET Framework uses "RSA PRIVATE KEY" format, .NET Core uses "PRIVATE KEY"
            var isValidStart = _keyPair.PrivateKey.StartsWith("-----BEGIN PRIVATE KEY-----") ||
                              _keyPair.PrivateKey.StartsWith("-----BEGIN RSA PRIVATE KEY-----");
            isValidStart.Should().BeTrue("Private key should start with valid PEM header");

            var trimmed = _keyPair.PrivateKey.TrimEnd();
            var isValidEnd = trimmed.EndsWith("-----END PRIVATE KEY-----") ||
                            trimmed.EndsWith("-----END RSA PRIVATE KEY-----");
            isValidEnd.Should().BeTrue("Private key should end with valid PEM footer");
        }

        #endregion

        #region Multi-Party Encryption Tests

        [Fact]
        public void EncryptMasterKey_ForMultipleParties_AllCanDecrypt()
        {
            var party1Keys = _keyPair;
            var party2Keys = _otherKeyPair;
            var party3Keys = _thirdKeyPair;

            var masterKey = SecureMemory.GenerateRandomBytes(32);

            // Encrypt for each party
            var encryptedForParty1 = RsaProvider.EncryptMasterKey(masterKey, party1Keys.PublicKey);
            var encryptedForParty2 = RsaProvider.EncryptMasterKey(masterKey, party2Keys.PublicKey);
            var encryptedForParty3 = RsaProvider.EncryptMasterKey(masterKey, party3Keys.PublicKey);

            // Each party can decrypt with their private key
            var decrypted1 = RsaProvider.DecryptMasterKey(encryptedForParty1, party1Keys.PrivateKey);
            var decrypted2 = RsaProvider.DecryptMasterKey(encryptedForParty2, party2Keys.PrivateKey);
            var decrypted3 = RsaProvider.DecryptMasterKey(encryptedForParty3, party3Keys.PrivateKey);

            decrypted1.Should().Equal(masterKey);
            decrypted2.Should().Equal(masterKey);
            decrypted3.Should().Equal(masterKey);
        }

        [Fact]
        public void EncryptMasterKey_PartyCannotDecryptOthersData()
        {
            var party1Keys = _keyPair;
            var party2Keys = _otherKeyPair;

            var masterKey = SecureMemory.GenerateRandomBytes(32);

            // Encrypt only for party1
            var encryptedForParty1 = RsaProvider.EncryptMasterKey(masterKey, party1Keys.PublicKey);

            // Party2 cannot decrypt
            Action decrypt = () => RsaProvider.DecryptMasterKey(encryptedForParty1, party2Keys.PrivateKey);
            decrypt.Should().Throw<Exception>();
        }

        #endregion

        #region Integration Workflow Tests

        [Fact]
        public void CompleteEnvelopeWorkflow_RsaKeyOperations()
        {
            // Simulate the full envelope encryption workflow
            // 1. Generate master key
            var masterKey = SecureMemory.GenerateRandomBytes(32);
            masterKey.Length.Should().Be(32);

            // 2. Encrypt master key for recipient
            var encryptedMasterKey = RsaProvider.EncryptMasterKey(masterKey, _keyPair.PublicKey);
            encryptedMasterKey.Should().NotBeNullOrEmpty();

            // 3. Recipient decrypts master key
            var decryptedMasterKey = RsaProvider.DecryptMasterKey(encryptedMasterKey, _keyPair.PrivateKey);
            decryptedMasterKey.Should().Equal(masterKey);

            // 4. Verify fingerprint matches
            var fingerprint1 = RsaProvider.ComputeFingerprint(_keyPair.PublicKey);
            var fingerprint2 = RsaProvider.ComputeFingerprint(_keyPair.PublicKey);
            fingerprint1.Should().Be(fingerprint2);
        }

        #endregion
    }
}
