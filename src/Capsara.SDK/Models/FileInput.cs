using System;
using System.IO;

namespace Capsara.SDK.Models
{
    /// <summary>Input descriptor for a file to be encrypted and added to a capsa.</summary>
    public sealed class FileInput
    {
        /// <summary>Mutually exclusive with Data and Stream.</summary>
        public string? Path { get; set; }

        /// <summary>Mutually exclusive with Path and Stream.</summary>
        public byte[]? Data { get; set; }

        /// <summary>Mutually exclusive with Path and Data.</summary>
        public Stream? Stream { get; set; }

        /// <summary>Name of the file (encrypted before storage).</summary>
        public string Filename { get; set; } = string.Empty;

        /// <summary>Auto-detected if not specified.</summary>
        public string? Mimetype { get; set; }

        /// <summary>Whether to gzip-compress the file before encryption.</summary>
        public bool? Compress { get; set; }

        /// <summary>File-level expiration timestamp, after which the file is no longer accessible.</summary>
        public DateTimeOffset? ExpiresAt { get; set; }

        /// <summary>One-way transform reference (URL or @partyId/id).</summary>
        public string? Transform { get; set; }

        /// <summary>Creates a <see cref="FileInput"/> from a file system path.</summary>
        /// <param name="path">Absolute or relative path to the file.</param>
        /// <param name="filename">Override filename. Defaults to the file name from the path.</param>
        /// <param name="mimetype">MIME type. Auto-detected if null.</param>
        /// <returns>A new <see cref="FileInput"/> configured to read from the specified path.</returns>
        public static FileInput FromPath(string path, string? filename = null, string? mimetype = null)
        {
            return new FileInput
            {
                Path = path,
                Filename = filename ?? System.IO.Path.GetFileName(path),
                Mimetype = mimetype
            };
        }

        /// <summary>Creates a <see cref="FileInput"/> from an in-memory byte array.</summary>
        /// <param name="data">Raw file contents.</param>
        /// <param name="filename">Name of the file.</param>
        /// <param name="mimetype">MIME type. Auto-detected if null.</param>
        /// <returns>A new <see cref="FileInput"/> configured with the specified byte data.</returns>
        public static FileInput FromData(byte[] data, string filename, string? mimetype = null)
        {
            return new FileInput
            {
                Data = data,
                Filename = filename,
                Mimetype = mimetype
            };
        }

        /// <summary>Creates a <see cref="FileInput"/> from a readable stream.</summary>
        /// <param name="stream">Stream containing the file contents.</param>
        /// <param name="filename">Name of the file.</param>
        /// <param name="mimetype">MIME type. Auto-detected if null.</param>
        /// <returns>A new <see cref="FileInput"/> configured to read from the specified stream.</returns>
        public static FileInput FromStream(Stream stream, string filename, string? mimetype = null)
        {
            return new FileInput
            {
                Stream = stream,
                Filename = filename,
                Mimetype = mimetype
            };
        }

        /// <summary>Sets the MIME type and returns this instance for fluent chaining.</summary>
        /// <param name="mimetype">MIME type to assign.</param>
        /// <returns>This <see cref="FileInput"/> instance.</returns>
        public FileInput WithMimetype(string mimetype)
        {
            Mimetype = mimetype;
            return this;
        }

        /// <summary>Sets whether to compress the file before encryption and returns this instance.</summary>
        /// <param name="compress">True to enable gzip compression.</param>
        /// <returns>This <see cref="FileInput"/> instance.</returns>
        public FileInput WithCompression(bool compress)
        {
            Compress = compress;
            return this;
        }

        /// <summary>Sets the file-level expiration and returns this instance.</summary>
        /// <param name="expiresAt">Expiration timestamp for the file.</param>
        /// <returns>This <see cref="FileInput"/> instance.</returns>
        public FileInput WithExpiration(DateTimeOffset expiresAt)
        {
            ExpiresAt = expiresAt;
            return this;
        }

        /// <summary>Sets the one-way transform reference and returns this instance.</summary>
        /// <param name="transform">Transform reference (URL or @partyId/id).</param>
        /// <returns>This <see cref="FileInput"/> instance.</returns>
        public FileInput WithTransform(string transform)
        {
            Transform = transform;
            return this;
        }
    }
}
