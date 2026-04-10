using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;

namespace Capsara.SDK.Internal.Upload
{
    /// <summary>
    /// Multipart form-data builder for capsa uploads (supports 1-500 capsas).
    /// </summary>
    internal sealed class MultipartBuilder
    {
        private readonly string _boundary;
        private readonly List<MultipartPart> _parts = new();
        private bool _metadataSet;

        public MultipartBuilder()
        {
            // Generate unique boundary
            var randomBytes = Crypto.SecureMemory.GenerateRandomBytes(16);
            _boundary = $"----CapsaBoundary{BitConverter.ToString(randomBytes).Replace("-", "").ToLowerInvariant()}";
        }

        /// <summary>
        /// Add capsa batch metadata (must be first).
        /// </summary>
        /// <param name="capsaCount">Number of capsas in request.</param>
        /// <param name="creator">Creator party ID.</param>
        public MultipartBuilder AddMetadata(int capsaCount, string creator)
        {
            if (_metadataSet)
            {
                throw new InvalidOperationException("Metadata already set");
            }

            var metadata = new { capsaCount, creator };
            _parts.Add(new MultipartPart
            {
                Name = "metadata",
                Content = JsonSerializer.Serialize(metadata),
                ContentType = "application/json"
            });

            _metadataSet = true;
            return this;
        }

        /// <summary>
        /// Add capsa metadata part with index.
        /// </summary>
        /// <param name="capsa">Capsa upload data.</param>
        /// <param name="capsaIndex">Capsa index in request.</param>
        public MultipartBuilder AddCapsaMetadata(object capsa, int capsaIndex)
        {
            if (!_metadataSet)
            {
                throw new InvalidOperationException("Must call AddMetadata() first");
            }

            var options = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
            };

            _parts.Add(new MultipartPart
            {
                Name = $"capsa_{capsaIndex}",
                Content = JsonSerializer.Serialize(capsa, options),
                ContentType = "application/json"
            });
            return this;
        }

        /// <summary>
        /// Add file binary part with file ID.
        /// </summary>
        /// <param name="fileData">Encrypted file data.</param>
        /// <param name="fileId">File ID from metadata (should include .enc extension).</param>
        public MultipartBuilder AddFileBinary(byte[] fileData, string fileId)
        {
            if (!_metadataSet)
            {
                throw new InvalidOperationException("Must call AddMetadata() first");
            }

            _parts.Add(new MultipartPart
            {
                Name = "file",
                BinaryContent = fileData,
                ContentType = "application/octet-stream",
                Filename = fileId
            });
            return this;
        }

        /// <summary>
        /// Build the complete multipart body.
        /// </summary>
        /// <returns>Multipart body as byte array.</returns>
        public byte[] Build()
        {
            if (!_metadataSet)
            {
                throw new InvalidOperationException("Must call AddMetadata() first");
            }

            using var ms = new MemoryStream();

            foreach (var part in _parts)
            {
                // Add boundary
                WriteString(ms, $"--{_boundary}\r\n");

                // Add Content-Disposition header
                var disposition = $"Content-Disposition: form-data; name=\"{part.Name}\"";
                if (!string.IsNullOrEmpty(part.Filename))
                {
                    disposition += $"; filename=\"{part.Filename}\"";
                }
                WriteString(ms, disposition + "\r\n");

                // Add Content-Type header
                if (!string.IsNullOrEmpty(part.ContentType))
                {
                    WriteString(ms, $"Content-Type: {part.ContentType}\r\n");
                }

                // Add blank line
                WriteString(ms, "\r\n");

                // Add content
                if (part.BinaryContent != null)
                {
                    ms.Write(part.BinaryContent, 0, part.BinaryContent.Length);
                }
                else if (part.Content != null)
                {
                    var contentBytes = Encoding.UTF8.GetBytes(part.Content);
                    ms.Write(contentBytes, 0, contentBytes.Length);
                }

                // Add trailing line break
                WriteString(ms, "\r\n");
            }

            // Add final boundary
            WriteString(ms, $"--{_boundary}--\r\n");

            return ms.ToArray();
        }

        /// <summary>
        /// Get the Content-Type header value.
        /// </summary>
        public string GetContentType() => $"multipart/form-data; boundary={_boundary}";

        /// <summary>
        /// Get the boundary string.
        /// </summary>
        public string GetBoundary() => _boundary;

        private static void WriteString(MemoryStream ms, string value)
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            ms.Write(bytes, 0, bytes.Length);
        }

        private sealed class MultipartPart
        {
            public string Name { get; set; } = string.Empty;
            public string? Content { get; set; }
            public byte[]? BinaryContent { get; set; }
            public string? ContentType { get; set; }
            public string? Filename { get; set; }
        }
    }
}
