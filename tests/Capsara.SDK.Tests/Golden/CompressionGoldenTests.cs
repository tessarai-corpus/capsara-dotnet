using System;
using System.Text;
using Capsara.SDK.Internal.Crypto;
using FluentAssertions;
using Xunit;

namespace Capsara.SDK.Tests.Golden
{
    /// <summary>
    /// Golden tests for compression operations: roundtrip, threshold, and invalid data.
    /// </summary>
    public class CompressionGoldenTests
    {
        #region Roundtrip Tests

        [Fact]
        public void Compress_Decompress_RoundTrip_TextData()
        {
            // Arrange
            var original = Encoding.UTF8.GetBytes("This is test data that should be compressible because it has repeating patterns.");

            // Act
            var compressResult = CompressionProvider.Compress(original);
            var decompressed = CompressionProvider.Decompress(compressResult.CompressedData);

            // Assert
            decompressed.Should().Equal(original);
            compressResult.CompressionAlgorithm.Should().Be("gzip");
            compressResult.OriginalSize.Should().Be(original.Length);
            compressResult.WasCompressed.Should().BeTrue();
        }

        [Fact]
        public void Compress_Decompress_RoundTrip_BinaryData()
        {
            // Arrange
            var original = new byte[5000];
            new Random(42).NextBytes(original);

            // Act
            var compressResult = CompressionProvider.Compress(original);
            var decompressed = CompressionProvider.Decompress(compressResult.CompressedData);

            // Assert
            decompressed.Should().Equal(original);
        }

        [Fact]
        public void CompressIfBeneficial_LargeRepetitiveData_Compresses()
        {
            // Arrange
            var original = new byte[10000];
            for (int i = 0; i < original.Length; i++) original[i] = (byte)'A';

            // Act
            var result = CompressionProvider.CompressIfBeneficial(original);

            // Assert
            result.WasCompressed.Should().BeTrue();
            result.CompressedSize.Should().BeLessThan(result.OriginalSize);
            result.CompressionRatio.Should().BeLessThan(1.0);
        }

        #endregion

        #region Threshold Tests

        [Fact]
        public void ShouldCompress_BelowThreshold_ReturnsFalse()
        {
            // Assert
            CompressionProvider.ShouldCompress(0).Should().BeFalse();
            CompressionProvider.ShouldCompress(100).Should().BeFalse();
            CompressionProvider.ShouldCompress(149).Should().BeFalse();
        }

        [Fact]
        public void ShouldCompress_AtOrAboveThreshold_ReturnsTrue()
        {
            // Assert - threshold is 150 bytes
            CompressionProvider.ShouldCompress(150).Should().BeTrue();
            CompressionProvider.ShouldCompress(1024).Should().BeTrue();
            CompressionProvider.ShouldCompress(1024 * 1024).Should().BeTrue();
        }

        #endregion

        #region Invalid Data Tests

        [Fact]
        public void Decompress_InvalidGzipData_Throws()
        {
            // Arrange - random bytes are not valid gzip
            var invalidData = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };

            // Act & Assert
            Assert.ThrowsAny<Exception>(() =>
                CompressionProvider.Decompress(invalidData));
        }

        #endregion
    }
}
