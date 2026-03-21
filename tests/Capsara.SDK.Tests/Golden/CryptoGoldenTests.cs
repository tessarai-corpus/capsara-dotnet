using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Capsara.SDK.Internal.Crypto;
using Capsara.SDK.Tests.Helpers;
using FluentAssertions;
using Xunit;

namespace Capsara.SDK.Tests.Golden
{
    /// <summary>
    /// Golden tests for cryptographic operations: AES-GCM roundtrip/errors, RSA roundtrip/errors,
    /// key generation, signatures, IV uniqueness, and SHA-256 hashing.
    /// </summary>
    [Collection("SharedKeys")]
    public class CryptoGoldenTests : IDisposable
    {
        private readonly GeneratedKeyPairResult _keyPair;
        private readonly GeneratedKeyPairResult _otherKeyPair;
        private bool _disposed;

        public CryptoGoldenTests(SharedKeyFixture fixture)
        {
            _keyPair = fixture.PrimaryKeyPair;
            _otherKeyPair = fixture.SecondaryKeyPair;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
        }

        #region AES-GCM Roundtrip Tests

        [Fact]
        public void AesGcm_EncryptDecrypt_RoundTrip_SmallData()
        {
            using var provider = AesGcmProviderFactory.Create();
            var key = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);
            var plaintext = Encoding.UTF8.GetBytes("Hello, cryptography!");

            var result = provider.Encrypt(plaintext, key, iv);
            var decrypted = provider.Decrypt(result.Ciphertext, key, result.IvBytes, result.AuthTagBytes);

            decrypted.Should().Equal(plaintext);
        }

        [Fact]
        public void AesGcm_EncryptDecrypt_RoundTrip_LargeData()
        {
            using var provider = AesGcmProviderFactory.Create();
            var key = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);
            var plaintext = SecureMemory.GenerateRandomBytes(1024 * 50); // 50 KB

            var result = provider.Encrypt(plaintext, key, iv);
            var decrypted = provider.Decrypt(result.Ciphertext, key, result.IvBytes, result.AuthTagBytes);

            decrypted.Should().Equal(plaintext);
        }

        [Fact]
        public void AesGcm_EncryptDecrypt_EmptyData()
        {
            using var provider = AesGcmProviderFactory.Create();
            var key = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);
            var plaintext = Array.Empty<byte>();

            var result = provider.Encrypt(plaintext, key, iv);
            var decrypted = provider.Decrypt(result.Ciphertext, key, result.IvBytes, result.AuthTagBytes);

            decrypted.Should().BeEmpty();
        }

        #endregion

        #region AES-GCM Error Tests

        [Fact]
        public void AesGcm_Decrypt_WrongKey_Throws()
        {
            using var provider = AesGcmProviderFactory.Create();
            var key = SecureMemory.GenerateRandomBytes(32);
            var wrongKey = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);
            var plaintext = Encoding.UTF8.GetBytes("Secret");

            var result = provider.Encrypt(plaintext, key, iv);

            Assert.ThrowsAny<Exception>(() =>
                provider.Decrypt(result.Ciphertext, wrongKey, result.IvBytes, result.AuthTagBytes));
        }

        [Fact]
        public void AesGcm_Decrypt_TamperedCiphertext_Throws()
        {
            using var provider = AesGcmProviderFactory.Create();
            var key = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);
            var plaintext = Encoding.UTF8.GetBytes("Secret data");

            var result = provider.Encrypt(plaintext, key, iv);
            var tampered = (byte[])result.Ciphertext.Clone();
            tampered[0] ^= 0xFF;

            Assert.ThrowsAny<Exception>(() =>
                provider.Decrypt(tampered, key, result.IvBytes, result.AuthTagBytes));
        }

        [Fact]
        public void AesGcm_Decrypt_TamperedAuthTag_Throws()
        {
            using var provider = AesGcmProviderFactory.Create();
            var key = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);
            var plaintext = Encoding.UTF8.GetBytes("Secret data");

            var result = provider.Encrypt(plaintext, key, iv);
            var tamperedTag = (byte[])result.AuthTagBytes.Clone();
            tamperedTag[0] ^= 0xFF;

            Assert.ThrowsAny<Exception>(() =>
                provider.Decrypt(result.Ciphertext, key, result.IvBytes, tamperedTag));
        }

        [Fact]
        public void AesGcm_AuthTag_Is16Bytes()
        {
            using var provider = AesGcmProviderFactory.Create();
            var key = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);

            var result = provider.Encrypt(Encoding.UTF8.GetBytes("test"), key, iv);

            result.AuthTagBytes.Length.Should().Be(16, "AES-GCM auth tag should be 128 bits");
        }

        #endregion

        #region RSA Roundtrip Tests

        [Fact]
        public void Rsa_EncryptDecrypt_MasterKey_RoundTrip()
        {
            // Arrange
            var masterKey = SecureMemory.GenerateRandomBytes(32);

            // Act
            var encrypted = RsaProvider.EncryptMasterKey(masterKey, _keyPair.PublicKey);
            var decrypted = RsaProvider.DecryptMasterKey(encrypted, _keyPair.PrivateKey);

            // Assert
            decrypted.Should().Equal(masterKey);
        }

        [Fact]
        public void Rsa_EncryptedKey_Is512Bytes()
        {
            // Arrange
            var masterKey = SecureMemory.GenerateRandomBytes(32);

            // Act
            var encrypted = RsaProvider.EncryptMasterKey(masterKey, _keyPair.PublicKey);
            var encryptedBytes = Base64Url.Decode(encrypted);

            // Assert - RSA-4096 produces 512-byte output
            encryptedBytes.Length.Should().Be(512);
        }

        #endregion

        #region RSA Error Tests

        [Fact]
        public void Rsa_Decrypt_WithWrongKey_Throws()
        {
            // Arrange
            var masterKey = SecureMemory.GenerateRandomBytes(32);
            var encrypted = RsaProvider.EncryptMasterKey(masterKey, _keyPair.PublicKey);

            // Act & Assert
            Assert.ThrowsAny<Exception>(() =>
                RsaProvider.DecryptMasterKey(encrypted, _otherKeyPair.PrivateKey));
        }

        [Fact]
        public void Rsa_EncryptMasterKey_WrongKeySize_Throws()
        {
            // Arrange - Master key must be exactly 32 bytes
            var wrongSizeKey = SecureMemory.GenerateRandomBytes(16);

            // Act & Assert
            Assert.Throws<ArgumentException>(() =>
                RsaProvider.EncryptMasterKey(wrongSizeKey, _keyPair.PublicKey));
        }

        [Fact]
        public void Rsa_DecryptMasterKey_WrongEncryptedLength_Throws()
        {
            // Arrange - Encrypted key must be exactly 512 bytes
            var wrongLength = Base64Url.Encode(new byte[256]);

            // Act & Assert
            Assert.Throws<ArgumentException>(() =>
                RsaProvider.DecryptMasterKey(wrongLength, _keyPair.PrivateKey));
        }

        #endregion

        #region Key Generation Tests

        [Fact]
        public void KeyGenerator_GeneratesRsa4096()
        {
            // Act
            var keyPair = TestHelpers.GenerateTestKeyPair();

            // Assert
            keyPair.KeySize.Should().Be(4096);
            KeyGenerator.GetKeySize(keyPair.PublicKey).Should().Be(4096);
        }

        [Fact]
        public void KeyGenerator_SmallKeySize_Throws()
        {
            // Act & Assert
            Assert.Throws<ArgumentOutOfRangeException>(() =>
                KeyGenerator.GenerateKeyPair(1024));
        }

        #endregion

        #region Signature Tests

        [Fact]
        public void Signature_CreateAndVerify_RoundTrip()
        {
            // Arrange
            var canonicalString = "capsa_123|1.0.0|1000|RSA-OAEP-SHA256|hash1|iv1|fniv1";

            // Act
            var signature = SignatureProvider.CreateJws(canonicalString, _keyPair.PrivateKey);
            var isValid = SignatureProvider.VerifyJws(
                signature.Protected, signature.Payload, signature.Signature, _keyPair.PublicKey);

            // Assert
            isValid.Should().BeTrue();
        }

        [Fact]
        public void Signature_VerifyWithWrongKey_ReturnsFalse()
        {
            // Arrange
            var canonicalString = "capsa_123|1.0.0|500|RSA-OAEP-SHA256";
            var signature = SignatureProvider.CreateJws(canonicalString, _keyPair.PrivateKey);

            // Act
            var isValid = SignatureProvider.VerifyJws(
                signature.Protected, signature.Payload, signature.Signature, _otherKeyPair.PublicKey);

            // Assert
            isValid.Should().BeFalse();
        }

        #endregion

        #region IV Uniqueness Tests

        [Fact]
        public void GeneratedIVs_AreUnique()
        {
            // Arrange
            var ivs = new HashSet<string>();

            // Act
            for (int i = 0; i < 100; i++)
            {
                var iv = SecureMemory.GenerateRandomBytes(12);
                ivs.Add(Convert.ToBase64String(iv));
            }

            // Assert
            ivs.Count.Should().Be(100, "All generated IVs should be unique");
        }

        [Fact]
        public void GeneratedIV_Is12Bytes()
        {
            // Act
            var iv = SecureMemory.GenerateIv();

            // Assert
            iv.Length.Should().Be(12, "AES-GCM IV should be 96 bits (12 bytes)");
        }

        #endregion

        #region SHA-256 Tests

        [Fact]
        public void HashProvider_ComputeHash_ProducesConsistentResults()
        {
            // Arrange
            var data = Encoding.UTF8.GetBytes("test data");

            // Act
            var hash1 = HashProvider.ComputeHash(data);
            var hash2 = HashProvider.ComputeHash(data);

            // Assert
            hash1.Should().Be(hash2);
            hash1.Should().HaveLength(64); // SHA-256 = 64 hex chars
        }

        [Fact]
        public void HashProvider_VerifyHash_ValidData_ReturnsTrue()
        {
            // Arrange
            var data = Encoding.UTF8.GetBytes("verify me");
            var hash = HashProvider.ComputeHash(data);

            // Act
            var result = HashProvider.VerifyHash(data, hash);

            // Assert
            result.Should().BeTrue();
        }

        [Fact]
        public void HashProvider_VerifyHash_TamperedData_ReturnsFalse()
        {
            // Arrange
            var data = Encoding.UTF8.GetBytes("original");
            var hash = HashProvider.ComputeHash(data);
            var tampered = Encoding.UTF8.GetBytes("tampered");

            // Act
            var result = HashProvider.VerifyHash(tampered, hash);

            // Assert
            result.Should().BeFalse();
        }

        #endregion
    }
}
