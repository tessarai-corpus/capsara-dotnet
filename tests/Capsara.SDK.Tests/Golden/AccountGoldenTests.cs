using System;
using Capsara.SDK.Internal.Crypto;
using Capsara.SDK.Tests.Helpers;
using FluentAssertions;
using Xunit;

namespace Capsara.SDK.Tests.Golden
{
    /// <summary>
    /// Golden tests for account operations: key pair generation, fingerprint matching, format validation.
    /// </summary>
    public class AccountGoldenTests
    {
        #region Key Pair Generation Tests

        [Fact]
        public void GenerateKeyPair_ProducesValidKeyPair()
        {
            // Act
            var keyPair = TestHelpers.GenerateTestKeyPair();

            // Assert
            keyPair.Should().NotBeNull();
            keyPair.PublicKey.Should().Contain("-----BEGIN PUBLIC KEY-----");
            keyPair.PublicKey.Should().Contain("-----END PUBLIC KEY-----");
            keyPair.PrivateKey.Should().Contain("-----BEGIN");
            keyPair.PrivateKey.Should().Contain("-----END");
            keyPair.Fingerprint.Should().NotBeNullOrEmpty();
            keyPair.KeySize.Should().Be(4096);
            keyPair.Algorithm.Should().Be("RSA-4096");
            keyPair.PublicExponent.Should().Be(65537);
        }

        [Fact]
        public void GenerateKeyPair_TwoKeys_AreDifferent()
        {
            // Act
            var keyPair1 = TestHelpers.GenerateTestKeyPair();
            var keyPair2 = TestHelpers.GenerateTestKeyPair();

            // Assert
            keyPair1.PublicKey.Should().NotBe(keyPair2.PublicKey);
            keyPair1.PrivateKey.Should().NotBe(keyPair2.PrivateKey);
            keyPair1.Fingerprint.Should().NotBe(keyPair2.Fingerprint);
        }

        #endregion

        #region Fingerprint Matching Tests

        [Fact]
        public void Fingerprint_MatchesComputedFingerprint()
        {
            // Arrange
            var keyPair = TestHelpers.GenerateTestKeyPair();

            // Act - Recompute fingerprint from the public key
            var recomputed = KeyGenerator.CalculateFingerprint(keyPair.PublicKey);

            // Assert
            recomputed.Should().Be(keyPair.Fingerprint);
        }

        [Fact]
        public void Fingerprint_Is64CharHexString()
        {
            // Arrange
            var keyPair = TestHelpers.GenerateTestKeyPair();

            // Assert - SHA-256 produces 32 bytes = 64 hex characters
            keyPair.Fingerprint.Should().HaveLength(64);
            keyPair.Fingerprint.Should().MatchRegex("^[0-9a-f]{64}$");
        }

        #endregion

        #region Format Validation Tests

        [Fact]
        public void ValidateKeySize_ValidKey_ReturnsTrue()
        {
            // Arrange
            var keyPair = TestHelpers.GenerateTestKeyPair();

            // Act
            var isValid = KeyGenerator.ValidateKeySize(keyPair.PublicKey);

            // Assert
            isValid.Should().BeTrue();
        }

        #endregion
    }
}
