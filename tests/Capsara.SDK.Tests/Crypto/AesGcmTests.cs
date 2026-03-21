using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Capsara.SDK.Internal.Crypto;
using FluentAssertions;
using Xunit;

namespace Capsara.SDK.Tests.Crypto
{
    /// <summary>
    /// Tests for AES-256-GCM encryption/decryption operations.
    /// </summary>
    public class AesGcmTests : IDisposable
    {
        private bool _disposed;

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            // No class-level resources to dispose
            // Individual tests use 'using' statements for IAesGcmProvider
        }

        #region Basic Round-Trip Tests

        [Fact]
        public void Encrypt_Decrypt_RoundTrip()
        {
            using var provider = AesGcmProviderFactory.Create();
            var key = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);
            var plaintext = Encoding.UTF8.GetBytes("Hello, World!");

            var result = provider.Encrypt(plaintext, key, iv);
            var decrypted = provider.Decrypt(result.Ciphertext, key, result.IvBytes, result.AuthTagBytes);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void Encrypt_Decrypt_EmptyData()
        {
            using var provider = AesGcmProviderFactory.Create();
            var key = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);
            var plaintext = Array.Empty<byte>();

            var result = provider.Encrypt(plaintext, key, iv);
            var decrypted = provider.Decrypt(result.Ciphertext, key, result.IvBytes, result.AuthTagBytes);

            decrypted.Should().BeEmpty();
        }

        [Fact]
        public void Encrypt_Decrypt_SingleByte()
        {
            using var provider = AesGcmProviderFactory.Create();
            var key = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);
            var plaintext = new byte[] { 0x42 };

            var result = provider.Encrypt(plaintext, key, iv);
            var decrypted = provider.Decrypt(result.Ciphertext, key, result.IvBytes, result.AuthTagBytes);

            decrypted.Should().Equal(plaintext);
        }

        [Fact]
        public void Encrypt_Decrypt_LargeData()
        {
            using var provider = AesGcmProviderFactory.Create();
            var key = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);
            var plaintext = SecureMemory.GenerateRandomBytes(1024 * 100); // 100 KB

            var result = provider.Encrypt(plaintext, key, iv);
            var decrypted = provider.Decrypt(result.Ciphertext, key, result.IvBytes, result.AuthTagBytes);

            decrypted.Should().Equal(plaintext);
        }

        [Fact]
        public void Encrypt_Decrypt_AllByteValues()
        {
            using var provider = AesGcmProviderFactory.Create();
            var key = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);
            var plaintext = new byte[256];
            for (int i = 0; i < 256; i++)
            {
                plaintext[i] = (byte)i;
            }

            var result = provider.Encrypt(plaintext, key, iv);
            var decrypted = provider.Decrypt(result.Ciphertext, key, result.IvBytes, result.AuthTagBytes);

            decrypted.Should().Equal(plaintext);
        }

        [Fact]
        public void Encrypt_Decrypt_Utf8WithSpecialCharacters()
        {
            using var provider = AesGcmProviderFactory.Create();
            var key = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);
            var originalText = "Unicode: 😀 中文 éèê ñ ü";
            var plaintext = Encoding.UTF8.GetBytes(originalText);

            var result = provider.Encrypt(plaintext, key, iv);
            var decrypted = provider.Decrypt(result.Ciphertext, key, result.IvBytes, result.AuthTagBytes);

            Encoding.UTF8.GetString(decrypted).Should().Be(originalText);
        }

        #endregion

        #region Encryption Output Tests

        [Fact]
        public void Encrypt_ProducesAuthTag()
        {
            using var provider = AesGcmProviderFactory.Create();
            var key = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);
            var plaintext = Encoding.UTF8.GetBytes("Test data");

            var result = provider.Encrypt(plaintext, key, iv);

            Assert.NotNull(result.AuthTagBytes);
            Assert.Equal(16, result.AuthTagBytes.Length); // 128-bit auth tag
        }

        [Fact]
        public void Encrypt_ReturnsProvidedIV()
        {
            using var provider = AesGcmProviderFactory.Create();
            var key = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);
            var plaintext = Encoding.UTF8.GetBytes("Test data");

            var result = provider.Encrypt(plaintext, key, iv);

            result.IvBytes.Should().Equal(iv);
        }

        [Fact]
        public void Encrypt_CiphertextLengthMatchesPlaintext()
        {
            using var provider = AesGcmProviderFactory.Create();
            var key = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);
            var plaintext = Encoding.UTF8.GetBytes("Test data for length check");

            var result = provider.Encrypt(plaintext, key, iv);

            // AES-GCM produces ciphertext same length as plaintext (unlike block modes)
            result.Ciphertext.Length.Should().Be(plaintext.Length);
        }

        [Fact]
        public void Encrypt_ProducesDifferentCiphertextWithDifferentIV()
        {
            using var provider = AesGcmProviderFactory.Create();
            var key = SecureMemory.GenerateRandomBytes(32);
            var iv1 = SecureMemory.GenerateRandomBytes(12);
            var iv2 = SecureMemory.GenerateRandomBytes(12);
            var plaintext = Encoding.UTF8.GetBytes("Same plaintext");

            var result1 = provider.Encrypt(plaintext, key, iv1);
            var result2 = provider.Encrypt(plaintext, key, iv2);

            result1.Ciphertext.Should().NotEqual(result2.Ciphertext);
        }

        [Fact]
        public void Encrypt_SamePlaintextAndIV_ProducesSameCiphertext()
        {
            using var provider = AesGcmProviderFactory.Create();
            var key = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);
            var plaintext = Encoding.UTF8.GetBytes("Deterministic test");

            var result1 = provider.Encrypt(plaintext, key, iv);
            var result2 = provider.Encrypt(plaintext, key, iv);

            result1.Ciphertext.Should().Equal(result2.Ciphertext);
            result1.AuthTagBytes.Should().Equal(result2.AuthTagBytes);
        }

        #endregion

        #region Authentication Failure Tests

        [Fact]
        public void Decrypt_WithWrongKey_Throws()
        {
            using var provider = AesGcmProviderFactory.Create();
            var key = SecureMemory.GenerateRandomBytes(32);
            var wrongKey = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);
            var plaintext = Encoding.UTF8.GetBytes("Secret data");

            var result = provider.Encrypt(plaintext, key, iv);

            Assert.ThrowsAny<Exception>(() =>
                provider.Decrypt(result.Ciphertext, wrongKey, result.IvBytes, result.AuthTagBytes));
        }

        [Fact]
        public void Decrypt_WithWrongIV_Throws()
        {
            using var provider = AesGcmProviderFactory.Create();
            var key = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);
            var wrongIv = SecureMemory.GenerateRandomBytes(12);
            var plaintext = Encoding.UTF8.GetBytes("Secret data");

            var result = provider.Encrypt(plaintext, key, iv);

            Assert.ThrowsAny<Exception>(() =>
                provider.Decrypt(result.Ciphertext, key, wrongIv, result.AuthTagBytes));
        }

        [Fact]
        public void Decrypt_WithTamperedCiphertext_Throws()
        {
            using var provider = AesGcmProviderFactory.Create();
            var key = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);
            var plaintext = Encoding.UTF8.GetBytes("Secret data");

            var result = provider.Encrypt(plaintext, key, iv);

            // Tamper with ciphertext
            var tampered = (byte[])result.Ciphertext.Clone();
            tampered[0] ^= 0xFF;

            Assert.ThrowsAny<Exception>(() =>
                provider.Decrypt(tampered, key, result.IvBytes, result.AuthTagBytes));
        }

        [Fact]
        public void Decrypt_WithTamperedAuthTag_Throws()
        {
            using var provider = AesGcmProviderFactory.Create();
            var key = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);
            var plaintext = Encoding.UTF8.GetBytes("Secret data");

            var result = provider.Encrypt(plaintext, key, iv);

            // Tamper with auth tag
            var tamperedTag = (byte[])result.AuthTagBytes.Clone();
            tamperedTag[0] ^= 0xFF;

            Assert.ThrowsAny<Exception>(() =>
                provider.Decrypt(result.Ciphertext, key, result.IvBytes, tamperedTag));
        }

        [Fact]
        public void Decrypt_WithIVFromDifferentEncryption_Throws()
        {
            using var provider = AesGcmProviderFactory.Create();
            var key = SecureMemory.GenerateRandomBytes(32);
            var iv1 = SecureMemory.GenerateRandomBytes(12);
            var iv2 = SecureMemory.GenerateRandomBytes(12);
            var plaintext = Encoding.UTF8.GetBytes("Test data");

            var result = provider.Encrypt(plaintext, key, iv1);

            // Use IV from different encryption
            Assert.ThrowsAny<Exception>(() =>
                provider.Decrypt(result.Ciphertext, key, iv2, result.AuthTagBytes));
        }

        [Fact]
        public void Decrypt_TruncatedCiphertext_Throws()
        {
            using var provider = AesGcmProviderFactory.Create();
            var key = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);
            var plaintext = Encoding.UTF8.GetBytes("Secret data that will be truncated");

            var result = provider.Encrypt(plaintext, key, iv);

            // Truncate ciphertext
            var truncated = result.Ciphertext.Take(result.Ciphertext.Length / 2).ToArray();

            Assert.ThrowsAny<Exception>(() =>
                provider.Decrypt(truncated, key, result.IvBytes, result.AuthTagBytes));
        }

        [Fact]
        public void Decrypt_ExtendedCiphertext_Throws()
        {
            using var provider = AesGcmProviderFactory.Create();
            var key = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);
            var plaintext = Encoding.UTF8.GetBytes("Test data");

            var result = provider.Encrypt(plaintext, key, iv);

            // Extend ciphertext with extra bytes
            var extended = result.Ciphertext.Concat(new byte[] { 0x00, 0x01, 0x02 }).ToArray();

            Assert.ThrowsAny<Exception>(() =>
                provider.Decrypt(extended, key, result.IvBytes, result.AuthTagBytes));
        }

        [Fact]
        public void Decrypt_SingleBitFlipInMiddle_Throws()
        {
            using var provider = AesGcmProviderFactory.Create();
            var key = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);
            var plaintext = Encoding.UTF8.GetBytes("Test data for bit flip detection");

            var result = provider.Encrypt(plaintext, key, iv);

            // Flip single bit in middle of ciphertext
            var tampered = (byte[])result.Ciphertext.Clone();
            tampered[result.Ciphertext.Length / 2] ^= 0x01;

            Assert.ThrowsAny<Exception>(() =>
                provider.Decrypt(tampered, key, result.IvBytes, result.AuthTagBytes));
        }

        [Fact]
        public void Decrypt_SingleBitFlipInAuthTag_Throws()
        {
            using var provider = AesGcmProviderFactory.Create();
            var key = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);
            var plaintext = Encoding.UTF8.GetBytes("Test data");

            var result = provider.Encrypt(plaintext, key, iv);

            // Flip single bit in auth tag
            var tamperedTag = (byte[])result.AuthTagBytes.Clone();
            tamperedTag[8] ^= 0x01;

            Assert.ThrowsAny<Exception>(() =>
                provider.Decrypt(result.Ciphertext, key, result.IvBytes, tamperedTag));
        }

        #endregion

        #region Multiple Round-Trip Tests

        [Fact]
        public void Encrypt_Decrypt_MultipleConsecutive()
        {
            using var provider = AesGcmProviderFactory.Create();
            var key = SecureMemory.GenerateRandomBytes(32);

            var testData = new[]
            {
                Array.Empty<byte>(),
                new byte[] { 0x00 },
                Encoding.UTF8.GetBytes("short"),
                Encoding.UTF8.GetBytes("medium length string for testing"),
                SecureMemory.GenerateRandomBytes(1000)
            };

            foreach (var plaintext in testData)
            {
                var iv = SecureMemory.GenerateRandomBytes(12);
                var result = provider.Encrypt(plaintext, key, iv);
                var decrypted = provider.Decrypt(result.Ciphertext, key, result.IvBytes, result.AuthTagBytes);
                decrypted.Should().Equal(plaintext);
            }
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(16)]
        [InlineData(1024)]
        [InlineData(65536)]
        public void Encrypt_Decrypt_VariousLengths(int length)
        {
            using var provider = AesGcmProviderFactory.Create();
            var key = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);
            var plaintext = new byte[length];
            // Use RandomNumberGenerator for cryptographically secure random bytes
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(plaintext);

            var result = provider.Encrypt(plaintext, key, iv);
            var decrypted = provider.Decrypt(result.Ciphertext, key, result.IvBytes, result.AuthTagBytes);

            Assert.Equal(plaintext, decrypted);
        }

        #endregion

        #region IV Size Tests

        [Fact]
        public void IV_ShouldBe12Bytes()
        {
            var iv = SecureMemory.GenerateRandomBytes(12);
            iv.Length.Should().Be(12);
        }

        [Fact]
        public void GeneratedIVs_ShouldBeUnique()
        {
            var ivs = new HashSet<string>();
            for (int i = 0; i < 100; i++)
            {
                var iv = SecureMemory.GenerateRandomBytes(12);
                ivs.Add(Convert.ToBase64String(iv));
            }

            ivs.Count.Should().Be(100, "All generated IVs should be unique");
        }

        #endregion

        #region Key Size Tests

        [Fact]
        public void Key_ShouldBe32Bytes()
        {
            var key = SecureMemory.GenerateRandomBytes(32);
            key.Length.Should().Be(32);
        }

        [Fact]
        public void GeneratedKeys_ShouldBeUnique()
        {
            var keys = new HashSet<string>();
            for (int i = 0; i < 100; i++)
            {
                var key = SecureMemory.GenerateRandomBytes(32);
                keys.Add(Convert.ToBase64String(key));
            }

            keys.Count.Should().Be(100, "All generated keys should be unique");
        }

        [Fact]
        public void GeneratedKeys_ShouldHaveGoodByteDistribution()
        {
            var byteCounts = new Dictionary<byte, int>();
            const int keyCount = 100;

            for (int i = 0; i < keyCount; i++)
            {
                var key = SecureMemory.GenerateRandomBytes(32);
                foreach (var b in key)
                {
                    if (!byteCounts.ContainsKey(b))
                        byteCounts[b] = 0;
                    byteCounts[b]++;
                }
            }

            // With 3200 bytes (100 keys * 32 bytes), expect roughly uniform distribution
            // across 256 possible byte values. At least 200 unique values should appear.
            byteCounts.Count.Should().BeGreaterThan(200, "Key bytes should have good distribution");
        }

        #endregion

        #region AuthTag Size Tests

        [Fact]
        public void AuthTag_ShouldBe16Bytes()
        {
            using var provider = AesGcmProviderFactory.Create();
            var key = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);
            var plaintext = Encoding.UTF8.GetBytes("Test");

            var result = provider.Encrypt(plaintext, key, iv);

            result.AuthTagBytes.Length.Should().Be(16, "Auth tag should be 128 bits (16 bytes)");
        }

        [Fact]
        public void AuthTag_ShouldBeDifferentForDifferentPlaintexts()
        {
            using var provider = AesGcmProviderFactory.Create();
            var key = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);

            var result1 = provider.Encrypt(Encoding.UTF8.GetBytes("Hello"), key, iv);
            // Need different IV for different plaintext to avoid nonce reuse
            var iv2 = SecureMemory.GenerateRandomBytes(12);
            var result2 = provider.Encrypt(Encoding.UTF8.GetBytes("World"), key, iv2);

            result1.AuthTagBytes.Should().NotEqual(result2.AuthTagBytes);
        }

        #endregion

        #region Factory Tests

        [Fact]
        public void AesGcmProviderFactory_CreatesProvider()
        {
            using var provider = AesGcmProviderFactory.Create();
            provider.Should().NotBeNull();
        }

        [Fact]
        public void AesGcmProvider_ImplementsIDisposable()
        {
            var provider = AesGcmProviderFactory.Create();
            provider.Should().BeAssignableTo<IDisposable>();
            provider.Dispose();
        }

        [Fact]
        public void MultipleProviders_CanWorkIndependently()
        {
            using var provider1 = AesGcmProviderFactory.Create();
            using var provider2 = AesGcmProviderFactory.Create();

            var key = SecureMemory.GenerateRandomBytes(32);
            var iv1 = SecureMemory.GenerateRandomBytes(12);
            var iv2 = SecureMemory.GenerateRandomBytes(12);
            var plaintext = Encoding.UTF8.GetBytes("Test data");

            var result1 = provider1.Encrypt(plaintext, key, iv1);
            var result2 = provider2.Encrypt(plaintext, key, iv2);

            var decrypted1 = provider1.Decrypt(result2.Ciphertext, key, result2.IvBytes, result2.AuthTagBytes);
            var decrypted2 = provider2.Decrypt(result1.Ciphertext, key, result1.IvBytes, result1.AuthTagBytes);

            decrypted1.Should().Equal(plaintext);
            decrypted2.Should().Equal(plaintext);
        }

        #endregion

        #region Cross-Encryption Tests

        [Fact]
        public void DifferentProviderInstances_CanDecryptEachOthersData()
        {
            var key = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);
            var plaintext = Encoding.UTF8.GetBytes("Cross-instance test data");

            byte[] ciphertext;
            byte[] authTag;

            using (var encryptor = AesGcmProviderFactory.Create())
            {
                var result = encryptor.Encrypt(plaintext, key, iv);
                ciphertext = result.Ciphertext;
                authTag = result.AuthTagBytes;
            }

            using (var decryptor = AesGcmProviderFactory.Create())
            {
                var decrypted = decryptor.Decrypt(ciphertext, key, iv, authTag);
                decrypted.Should().Equal(plaintext);
            }
        }

        #endregion
    }
}
