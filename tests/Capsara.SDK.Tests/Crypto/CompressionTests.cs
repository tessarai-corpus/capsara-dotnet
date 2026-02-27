using System;
using System.Text;
using Capsara.SDK.Internal.Crypto;
using Xunit;

namespace Capsara.SDK.Tests.Crypto
{
    public class CompressionTests
    {
        [Fact]
        public void Compress_Decompress_RoundTrip()
        {
            var original = Encoding.UTF8.GetBytes("Hello, World! This is some test data.");
            var compressResult = CompressionProvider.Compress(original);
            var decompressed = CompressionProvider.Decompress(compressResult.CompressedData);

            Assert.Equal(original, decompressed);
        }

        [Fact]
        public void Compress_EmptyData_ReturnsValidCompressed()
        {
            var compressResult = CompressionProvider.Compress(Array.Empty<byte>());
            var decompressed = CompressionProvider.Decompress(compressResult.CompressedData);

            Assert.Empty(decompressed);
        }

        [Fact]
        public void Compress_RepetitiveData_ReducesSize()
        {
            var original = new byte[10000];
            for (int i = 0; i < original.Length; i++) original[i] = (byte)'A';

            var compressResult = CompressionProvider.Compress(original);

            Assert.True(compressResult.CompressedSize < original.Length);
        }

        [Fact]
        public void Compress_RandomData_HandlesGracefully()
        {
            var original = new byte[1000];
            new Random(42).NextBytes(original);

            var compressResult = CompressionProvider.Compress(original);
            var decompressed = CompressionProvider.Decompress(compressResult.CompressedData);

            Assert.Equal(original, decompressed);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(100)]
        [InlineData(1024)]
        [InlineData(65536)]
        public void Compress_Decompress_VariousLengths(int length)
        {
            var original = new byte[length];
            new Random(42).NextBytes(original);

            var compressResult = CompressionProvider.Compress(original);
            var decompressed = CompressionProvider.Decompress(compressResult.CompressedData);

            Assert.Equal(original, decompressed);
        }

        [Fact]
        public void ShouldCompress_SmallFile_ReturnsFalse()
        {
            Assert.False(CompressionProvider.ShouldCompress(100)); // 100 bytes
            Assert.False(CompressionProvider.ShouldCompress(149)); // just under threshold
        }

        [Fact]
        public void ShouldCompress_LargeFile_ReturnsTrue()
        {
            // Threshold in CompressionProvider is 150 bytes
            Assert.True(CompressionProvider.ShouldCompress(150)); // exactly at threshold
            Assert.True(CompressionProvider.ShouldCompress(1024)); // 1 KB
            Assert.True(CompressionProvider.ShouldCompress(10000)); // 10 KB
        }
    }
}
