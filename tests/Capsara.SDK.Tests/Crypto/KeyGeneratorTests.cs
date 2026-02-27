using System;
using Capsara.SDK.Internal.Crypto;
using Xunit;

namespace Capsara.SDK.Tests.Crypto
{
    public class KeyGeneratorTests : IDisposable
    {
        private bool _disposed;

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            // GeneratedKeyPairResult is a data class with no unmanaged resources
            // Following IDisposable pattern for consistency with other test classes
        }

        [Fact]
        public void GenerateKeyPair_ReturnsValidKeys()
        {
            var result = KeyGenerator.GenerateKeyPair();

            Assert.NotNull(result);
            Assert.NotEmpty(result.PublicKey);
            Assert.NotEmpty(result.PrivateKey);
            Assert.NotEmpty(result.Fingerprint);
        }

        [Fact]
        public void GenerateKeyPair_PublicKeyIsPemFormatted()
        {
            var result = KeyGenerator.GenerateKeyPair();

            Assert.Contains("BEGIN PUBLIC KEY", result.PublicKey);
            Assert.Contains("END PUBLIC KEY", result.PublicKey);
        }

        [Fact]
        public void GenerateKeyPair_PrivateKeyIsPemFormatted()
        {
            var result = KeyGenerator.GenerateKeyPair();

            Assert.Contains("BEGIN", result.PrivateKey);
            Assert.Contains("PRIVATE KEY", result.PrivateKey);
            Assert.Contains("END", result.PrivateKey);
        }

        [Fact]
        public void GenerateKeyPair_FingerprintIs64HexChars()
        {
            var result = KeyGenerator.GenerateKeyPair();

            Assert.Equal(64, result.Fingerprint.Length);
            Assert.Matches("^[a-f0-9]{64}$", result.Fingerprint);
        }

        [Fact]
        public void GenerateKeyPair_DefaultKeySize4096()
        {
            var result = KeyGenerator.GenerateKeyPair();

            Assert.Equal(4096, result.KeySize);
        }

        [Fact]
        public void GenerateKeyPair_UniqueKeysEachTime()
        {
            var result1 = KeyGenerator.GenerateKeyPair();
            var result2 = KeyGenerator.GenerateKeyPair();

            Assert.NotEqual(result1.PublicKey, result2.PublicKey);
            Assert.NotEqual(result1.PrivateKey, result2.PrivateKey);
            Assert.NotEqual(result1.Fingerprint, result2.Fingerprint);
        }

        [Fact]
        public void CalculateFingerprint_SameKeyProducesSameFingerprint()
        {
            var result = KeyGenerator.GenerateKeyPair();
            var fingerprint = KeyGenerator.CalculateFingerprint(result.PublicKey);

            Assert.Equal(result.Fingerprint, fingerprint);
        }

        [Fact]
        public void ValidateKeySize_4096Key_ReturnsTrue()
        {
            var result = KeyGenerator.GenerateKeyPair(4096);

            Assert.True(KeyGenerator.ValidateKeySize(result.PublicKey));
        }

        [Fact]
        public void ValidateKeySize_2048Key_ReturnsFalseForDefault()
        {
            var result = KeyGenerator.GenerateKeyPair(2048);

            // Default minimum is 4096
            Assert.False(KeyGenerator.ValidateKeySize(result.PublicKey));
        }

        [Fact]
        public void ValidateKeySize_WithLowerMinimum_ReturnsTrue()
        {
            var result = KeyGenerator.GenerateKeyPair(2048);

            Assert.True(KeyGenerator.ValidateKeySize(result.PublicKey, 2048));
        }

        [Fact]
        public void GetKeySize_ReturnsCorrectSize()
        {
            var result4096 = KeyGenerator.GenerateKeyPair(4096);
            var result2048 = KeyGenerator.GenerateKeyPair(2048);

            Assert.Equal(4096, KeyGenerator.GetKeySize(result4096.PublicKey));
            Assert.Equal(2048, KeyGenerator.GetKeySize(result2048.PublicKey));
        }
    }
}
