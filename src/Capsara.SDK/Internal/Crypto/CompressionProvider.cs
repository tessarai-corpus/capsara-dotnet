using System;
using System.IO;
using System.IO.Compression;
using System.Threading;
using System.Threading.Tasks;

namespace Capsara.SDK.Internal.Crypto
{
    /// <summary>
    /// Gzip compression/decompression applied before encryption.
    /// </summary>
    internal static class CompressionProvider
    {
        /// <summary>
        /// Below 150 bytes, gzip header overhead negates compression benefit.
        /// </summary>
        private const int MinCompressionSize = 150;

        /// <summary>Determine if data should be compressed based on size.</summary>
        public static bool ShouldCompress(int size)
        {
            return size >= MinCompressionSize;
        }

        /// <summary>Compress data using gzip.</summary>
        public static CompressionResult Compress(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            using var output = new MemoryStream();
            using (var gzip = new GZipStream(output, CompressionLevel.Optimal))
            {
                gzip.Write(data, 0, data.Length);
            }

            byte[] compressed = output.ToArray();

            return new CompressionResult(
                compressedData: compressed,
                originalSize: data.Length,
                compressedSize: compressed.Length,
                compressionAlgorithm: "gzip"
            );
        }

        /// <summary>Compress data using gzip asynchronously.</summary>
        public static async Task<CompressionResult> CompressAsync(byte[] data, CancellationToken cancellationToken = default)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            using var output = new MemoryStream();
#if NET6_0_OR_GREATER
            await using (var gzip = new GZipStream(output, CompressionLevel.Optimal))
            {
                await gzip.WriteAsync(data.AsMemory(), cancellationToken);
            }
#else
            using (var gzip = new GZipStream(output, CompressionLevel.Optimal))
            {
                await gzip.WriteAsync(data, 0, data.Length, cancellationToken);
            }
#endif

            byte[] compressed = output.ToArray();

            return new CompressionResult(
                compressedData: compressed,
                originalSize: data.Length,
                compressedSize: compressed.Length,
                compressionAlgorithm: "gzip"
            );
        }

        /// <summary>Decompress gzip data.</summary>
        public static byte[] Decompress(byte[] compressedData)
        {
            if (compressedData == null) throw new ArgumentNullException(nameof(compressedData));

            using var input = new MemoryStream(compressedData);
            using var gzip = new GZipStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();

            gzip.CopyTo(output);
            return output.ToArray();
        }

        /// <summary>Decompress gzip data asynchronously.</summary>
        public static async Task<byte[]> DecompressAsync(byte[] compressedData, CancellationToken cancellationToken = default)
        {
            if (compressedData == null) throw new ArgumentNullException(nameof(compressedData));

            using var input = new MemoryStream(compressedData);
#if NET6_0_OR_GREATER
            await using var gzip = new GZipStream(input, CompressionMode.Decompress);
#else
            using var gzip = new GZipStream(input, CompressionMode.Decompress);
#endif
            using var output = new MemoryStream();

            await gzip.CopyToAsync(output, 81920, cancellationToken);
            return output.ToArray();
        }

        /// <summary>Compress data only if it results in size reduction.</summary>
        public static CompressionResult CompressIfBeneficial(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            if (!ShouldCompress(data.Length))
            {
                return new CompressionResult(
                    compressedData: data,
                    originalSize: data.Length,
                    compressedSize: data.Length,
                    compressionAlgorithm: null,
                    wasCompressed: false
                );
            }

            var result = Compress(data);

            // Only use compression if it actually reduces size
            if (result.CompressedSize >= result.OriginalSize)
            {
                return new CompressionResult(
                    compressedData: data,
                    originalSize: data.Length,
                    compressedSize: data.Length,
                    compressionAlgorithm: null,
                    wasCompressed: false
                );
            }

            return result;
        }
    }

    /// <summary>Result of compression operation.</summary>
    internal sealed class CompressionResult
    {
        /// <summary>Compressed data (or original if compression was not beneficial).</summary>
        public byte[] CompressedData { get; }

        public int OriginalSize { get; }
        public int CompressedSize { get; }

        /// <summary>Algorithm used ("gzip") or null if not compressed.</summary>
        public string? CompressionAlgorithm { get; }

        public bool WasCompressed { get; }

        /// <summary>Compressed/original ratio. Less than 1 means compression helped.</summary>
        public double CompressionRatio => OriginalSize > 0 ? (double)CompressedSize / OriginalSize : 1.0;

        public CompressionResult(
            byte[] compressedData,
            int originalSize,
            int compressedSize,
            string? compressionAlgorithm,
            bool wasCompressed = true)
        {
            CompressedData = compressedData ?? throw new ArgumentNullException(nameof(compressedData));
            OriginalSize = originalSize;
            CompressedSize = compressedSize;
            CompressionAlgorithm = compressionAlgorithm;
            WasCompressed = wasCompressed && compressionAlgorithm != null;
        }
    }
}
