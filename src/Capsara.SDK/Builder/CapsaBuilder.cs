using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Capsara.SDK.Internal;
using Capsara.SDK.Internal.Crypto;
using Capsara.SDK.Internal.Utils;
using Capsara.SDK.Models;

namespace Capsara.SDK.Builder
{
    /// <summary>Fluent capsa builder for creating encrypted capsas. Implements IDisposable to securely clear the master key.</summary>
    public sealed class CapsaBuilder : IDisposable
    {
        /// <summary>Maximum keychain entries (creator + recipients + delegates).</summary>
        public const int MaxKeychainKeys = 100;
        /// <summary>Maximum encrypted subject length in characters (base64url).</summary>
        public const int MaxEncryptedSubject = 65_536;
        /// <summary>Maximum encrypted body length in characters (base64url).</summary>
        public const int MaxEncryptedBody = 1_048_576;
        /// <summary>Maximum encrypted structured data length in characters (base64url).</summary>
        public const int MaxEncryptedStructured = 1_048_576;
        /// <summary>Maximum metadata label length in characters.</summary>
        public const int MaxMetadataLabel = 512;
        /// <summary>Maximum number of metadata tags.</summary>
        public const int MaxMetadataTags = 100;
        /// <summary>Maximum length of each metadata tag in characters.</summary>
        public const int MaxTagLength = 100;
        /// <summary>Maximum metadata notes length in characters.</summary>
        public const int MaxMetadataNotes = 10_240;
        /// <summary>Maximum number of related packages.</summary>
        public const int MaxRelatedPackages = 50;
        /// <summary>Maximum party ID length in characters.</summary>
        public const int MaxPartyIdLength = 100;
        /// <summary>Maximum encrypted filename length in characters (base64url).</summary>
        public const int MaxEncryptedFilename = 2_048;
        /// <summary>Maximum signature payload length in characters (base64url).</summary>
        public const int MaxSignaturePayload = 65_536;
        /// <summary>Maximum parties a delegate can act for.</summary>
        public const int MaxActingFor = 10;

        private readonly byte[] _masterKey;
        private readonly string _creatorId;
        private readonly string _creatorPrivateKey;
        private readonly SystemLimits _limits;
        private readonly List<RecipientConfig> _recipients = new();
        private readonly List<FileInput> _files = new();
        private DateTimeOffset? _expiresAt;
        private bool _disposed;

        /// <summary>Plaintext subject (encrypted before sending).</summary>
        public string? Subject { get; set; }
        /// <summary>Plaintext body (encrypted before sending).</summary>
        public string? Body { get; set; }
        /// <summary>Structured data fields (encrypted before sending).</summary>
        public Dictionary<string, object> Structured { get; } = new();

        /// <summary>
        /// Unencrypted metadata (visible to server for routing/display)
        /// </summary>
        public CapsaMetadata Metadata { get; } = new();

        /// <summary>Expiration date/time (rounded to minute granularity).</summary>
        public DateTimeOffset? ExpiresAt
        {
            get => _expiresAt;
            set
            {
                if (value == null)
                {
                    _expiresAt = null;
                    return;
                }
                // Round to minute granularity
                var dt = value.Value;
                _expiresAt = new DateTimeOffset(dt.Year, dt.Month, dt.Day, dt.Hour, dt.Minute, 0, dt.Offset);
            }
        }

        /// <summary>
        /// Create a new capsa builder
        /// </summary>
        /// <param name="creatorId">Creator party ID</param>
        /// <param name="creatorPrivateKey">Creator's RSA private key (PEM format)</param>
        /// <param name="limits">System limits for validation</param>
        public CapsaBuilder(string creatorId, string creatorPrivateKey, SystemLimits? limits = null)
        {
            _creatorId = creatorId ?? throw new ArgumentNullException(nameof(creatorId));
            _creatorPrivateKey = creatorPrivateKey ?? throw new ArgumentNullException(nameof(creatorPrivateKey));
            _limits = limits ?? SystemLimits.Default;
            _masterKey = SecureMemory.GenerateRandomBytes(32); // AES-256 key
        }

        /// <summary>
        /// Add a recipient to the capsa
        /// </summary>
        /// <param name="partyId">Party ID</param>
        public CapsaBuilder AddRecipient(string partyId)
        {
            if (string.IsNullOrEmpty(partyId))
            {
                throw new ArgumentException("Party ID cannot be empty.", nameof(partyId));
            }
            if (partyId.Length > MaxPartyIdLength)
            {
                throw new ArgumentException(
                    $"Party ID ({partyId.Length} chars) exceeds server limit of {MaxPartyIdLength} chars.", nameof(partyId));
            }

            // +1 for the creator who also gets a keychain entry
            if (_recipients.Count + 1 >= MaxKeychainKeys)
            {
                throw new InvalidOperationException(
                    $"Cannot add recipient: keychain would exceed {MaxKeychainKeys} entries (including creator). Server will reject this capsa.");
            }
            _recipients.Add(new RecipientConfig(partyId, "read"));
            return this;
        }

        /// <summary>
        /// Add multiple recipients to the capsa
        /// </summary>
        /// <param name="partyIds">Party IDs</param>
        public CapsaBuilder AddRecipients(params string[] partyIds)
        {
            foreach (var partyId in partyIds)
            {
                if (string.IsNullOrEmpty(partyId))
                {
                    throw new ArgumentException("Party ID cannot be empty.");
                }
                if (partyId.Length > MaxPartyIdLength)
                {
                    throw new ArgumentException(
                        $"Party ID ({partyId.Length} chars) exceeds server limit of {MaxPartyIdLength} chars.");
                }
            }

            // +1 for the creator who also gets a keychain entry
            if (_recipients.Count + partyIds.Length + 1 > MaxKeychainKeys)
            {
                throw new InvalidOperationException(
                    $"Cannot add {partyIds.Length} recipients: keychain would have {_recipients.Count + partyIds.Length + 1} entries (max {MaxKeychainKeys}). Server will reject this capsa.");
            }
            foreach (var partyId in partyIds)
            {
                _recipients.Add(new RecipientConfig(partyId, "read"));
            }
            return this;
        }

        /// <summary>
        /// Add multiple recipients to the capsa
        /// </summary>
        /// <param name="partyIds">Party IDs</param>
        public CapsaBuilder AddRecipients(IEnumerable<string> partyIds)
        {
            foreach (var partyId in partyIds)
            {
                AddRecipient(partyId);
            }
            return this;
        }

        /// <summary>
        /// Add a file to the capsa
        /// </summary>
        /// <param name="input">File input</param>
        public CapsaBuilder AddFile(FileInput input)
        {
            if (_files.Count >= _limits.MaxFilesPerCapsa)
            {
                throw new InvalidOperationException(
                    $"Cannot add file: capsa already has {_files.Count} files (max: {_limits.MaxFilesPerCapsa})");
            }

            long fileSize;
            if (input.Data != null)
            {
                fileSize = input.Data.Length;
            }
            else if (!string.IsNullOrEmpty(input.Path))
            {
                fileSize = new FileInfo(input.Path).Length;
            }
            else if (input.Stream != null)
            {
                fileSize = input.Stream.Length;
            }
            else
            {
                throw new ArgumentException("File input must have Data, Path, or Stream");
            }

            if (fileSize > _limits.MaxFileSize)
            {
                throw new InvalidOperationException(
                    $"File \"{input.Filename}\" exceeds maximum size of {_limits.MaxFileSize / 1024 / 1024}MB");
            }

            _files.Add(input);
            return this;
        }

        /// <summary>
        /// Add a file from a file path
        /// </summary>
        /// <param name="path">File path on disk</param>
        /// <param name="filename">Optional filename override (defaults to file name from path)</param>
        /// <param name="mimetype">Optional MIME type (auto-detected if not specified)</param>
        public CapsaBuilder AddFile(string path, string? filename = null, string? mimetype = null)
        {
            return AddFile(FileInput.FromPath(path, filename, mimetype));
        }

        /// <summary>
        /// Add a file from byte array
        /// </summary>
        /// <param name="data">File content as byte array</param>
        /// <param name="filename">Filename</param>
        /// <param name="mimetype">Optional MIME type (auto-detected if not specified)</param>
        public CapsaBuilder AddFile(byte[] data, string filename, string? mimetype = null)
        {
            return AddFile(FileInput.FromData(data, filename, mimetype));
        }

        /// <summary>
        /// Add a file from a stream
        /// </summary>
        /// <param name="stream">File content as stream (must support Length property)</param>
        /// <param name="filename">Filename</param>
        /// <param name="mimetype">Optional MIME type (auto-detected if not specified)</param>
        public CapsaBuilder AddFile(Stream stream, string filename, string? mimetype = null)
        {
            return AddFile(FileInput.FromStream(stream, filename, mimetype));
        }

        /// <summary>
        /// Add multiple files from file paths
        /// </summary>
        /// <param name="paths">File paths on disk</param>
        public CapsaBuilder AddFiles(params string[] paths)
        {
            foreach (var path in paths)
            {
                AddFile(FileInput.FromPath(path));
            }
            return this;
        }

        /// <summary>
        /// Add multiple files from file paths
        /// </summary>
        /// <param name="paths">File paths on disk</param>
        public CapsaBuilder AddFiles(IEnumerable<string> paths)
        {
            foreach (var path in paths)
            {
                AddFile(FileInput.FromPath(path));
            }
            return this;
        }

        /// <summary>
        /// Add multiple files from FileInput objects
        /// </summary>
        /// <param name="files">File inputs</param>
        public CapsaBuilder AddFiles(params FileInput[] files)
        {
            foreach (var file in files)
            {
                AddFile(file);
            }
            return this;
        }

        /// <summary>
        /// Add multiple files from FileInput objects
        /// </summary>
        /// <param name="files">File inputs</param>
        public CapsaBuilder AddFiles(IEnumerable<FileInput> files)
        {
            foreach (var file in files)
            {
                AddFile(file);
            }
            return this;
        }

        /// <summary>
        /// Add a text file from string content
        /// </summary>
        /// <param name="filename">Filename (e.g., "notes.txt")</param>
        /// <param name="content">Text content</param>
        /// <param name="encoding">Optional encoding (defaults to UTF-8)</param>
        public CapsaBuilder AddTextFile(string filename, string content, Encoding? encoding = null)
        {
            var bytes = (encoding ?? Encoding.UTF8).GetBytes(content);
            return AddFile(FileInput.FromData(bytes, filename, "text/plain"));
        }

        /// <summary>
        /// Add a JSON file from an object
        /// </summary>
        /// <param name="filename">Filename (e.g., "data.json")</param>
        /// <param name="data">Object to serialize as JSON</param>
        /// <param name="options">Optional JSON serializer options</param>
        public CapsaBuilder AddJsonFile(string filename, object data, JsonSerializerOptions? options = null)
        {
            var json = JsonSerializer.Serialize(data, options);
            var bytes = Encoding.UTF8.GetBytes(json);
            return AddFile(FileInput.FromData(bytes, filename, "application/json"));
        }

        /// <summary>
        /// Set a structured data field
        /// </summary>
        /// <param name="key">Field key</param>
        /// <param name="value">Field value</param>
        public CapsaBuilder WithStructured(string key, object value)
        {
            Structured[key] = value;
            return this;
        }

        /// <summary>
        /// Set multiple structured data fields from an object
        /// </summary>
        /// <param name="data">Object with properties to add as structured data</param>
        public CapsaBuilder WithStructured(object data)
        {
            var json = JsonSerializer.Serialize(data);
            var dict = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);
            if (dict != null)
            {
                foreach (var kvp in dict)
                {
                    Structured[kvp.Key] = ConvertJsonElement(kvp.Value);
                }
            }
            return this;
        }

        /// <summary>
        /// Set all structured data from a dictionary
        /// </summary>
        /// <param name="data">Dictionary of structured data</param>
        public CapsaBuilder WithStructured(IDictionary<string, object> data)
        {
            foreach (var kvp in data)
            {
                Structured[kvp.Key] = kvp.Value;
            }
            return this;
        }

        /// <summary>
        /// Set the subject
        /// </summary>
        /// <param name="subject">Subject text</param>
        public CapsaBuilder WithSubject(string subject)
        {
            Subject = subject;
            return this;
        }

        /// <summary>
        /// Set the body
        /// </summary>
        /// <param name="body">Body text</param>
        public CapsaBuilder WithBody(string body)
        {
            Body = body;
            return this;
        }

        /// <summary>
        /// Set the expiration
        /// </summary>
        /// <param name="expiresAt">Expiration date/time</param>
        public CapsaBuilder WithExpiration(DateTimeOffset expiresAt)
        {
            ExpiresAt = expiresAt;
            return this;
        }

        private static object ConvertJsonElement(JsonElement element)
        {
            return element.ValueKind switch
            {
                JsonValueKind.String => element.GetString()!,
                JsonValueKind.Number => element.TryGetInt64(out var l) ? l : element.GetDouble(),
                JsonValueKind.True => true,
                JsonValueKind.False => false,
                JsonValueKind.Null => null!,
                JsonValueKind.Array => element.EnumerateArray().Select(ConvertJsonElement).ToArray(),
                JsonValueKind.Object => element.EnumerateObject().ToDictionary(p => p.Name, p => ConvertJsonElement(p.Value)),
                _ => element.ToString()
            };
        }

        internal string[] GetRecipientIds() => _recipients.Select(r => r.PartyId).ToArray();

        internal int GetFileCount() => _files.Count;

        /// <summary>
        /// Build the capsa with encryption and signature
        /// </summary>
        /// <param name="partyKeys">Public keys for all recipients</param>
        /// <returns>Built capsa ready for upload</returns>
        public async Task<BuiltCapsa> BuildAsync(PartyKey[] partyKeys)
        {
            ThrowIfDisposed();

            // No-content guard: server requires files OR a message (subject/body)
            var hasContent = _files.Count > 0 || !string.IsNullOrEmpty(Subject) || !string.IsNullOrEmpty(Body);
            if (!hasContent)
            {
                throw new InvalidOperationException(
                    "Capsa must contain either files or a message (subject/body). Server will reject empty capsas.");
            }

            var packageId = $"capsa_{IdGenerator.Generate(22)}";
            using var aesProvider = AesGcmProviderFactory.Create();

            var encryptedFiles = new List<EncryptedFileData>();
            long totalSize = 0;

            foreach (var file in _files)
            {
                var fileData = await ReadFileDataAsync(file).ConfigureAwait(false);
                var originalSize = fileData.Length;

                // Compress if needed (>= 150 bytes - gzip header breakeven point)
                bool compressed = false;
                string? compressionAlgorithm = null;
                if (file.Compress != false && CompressionProvider.ShouldCompress(originalSize))
                {
                    var compressionResult = CompressionProvider.CompressIfBeneficial(fileData);
                    fileData = compressionResult.CompressedData;
                    compressed = compressionResult.WasCompressed;
                    compressionAlgorithm = compressionResult.CompressionAlgorithm;
                }

                var contentIV = SecureMemory.GenerateRandomBytes(12);
                var contentResult = aesProvider.Encrypt(fileData, _masterKey, contentIV);

                var hash = HashProvider.ComputeHash(contentResult.Ciphertext);

                var filenameIV = SecureMemory.GenerateRandomBytes(12);
                var filenameBytes = Encoding.UTF8.GetBytes(file.Filename);
                var filenameResult = aesProvider.Encrypt(filenameBytes, _masterKey, filenameIV);

                var mimetype = file.Mimetype ?? MimetypeLookup.Lookup(file.Filename) ?? "application/octet-stream";

                var encryptedFilenameStr = Base64Url.Encode(filenameResult.Ciphertext);
                if (encryptedFilenameStr.Length > MaxEncryptedFilename)
                {
                    throw new InvalidOperationException(
                        $"Encrypted filename for \"{file.Filename.Substring(0, Math.Min(30, file.Filename.Length))}...\" ({encryptedFilenameStr.Length} chars) exceeds server limit of {MaxEncryptedFilename} chars. Use a shorter filename.");
                }

                var fileMetadata = new EncryptedFile
                {
                    FileId = $"file_{IdGenerator.Generate(16)}.enc",
                    EncryptedFilename = encryptedFilenameStr,
                    FilenameIV = Base64Url.Encode(filenameIV),
                    FilenameAuthTag = Base64Url.Encode(filenameResult.AuthTagBytes),
                    IV = Base64Url.Encode(contentIV),
                    AuthTag = Base64Url.Encode(contentResult.AuthTagBytes),
                    Mimetype = mimetype,
                    Size = contentResult.Ciphertext.Length,
                    Hash = hash,
                    HashAlgorithm = "SHA-256",
                    Compressed = compressed ? true : null,
                    CompressionAlgorithm = compressionAlgorithm,
                    OriginalSize = compressed ? originalSize : null,
                    ExpiresAt = file.ExpiresAt?.ToString("o"),
                    Transform = file.Transform
                };

                encryptedFiles.Add(new EncryptedFileData
                {
                    Metadata = fileMetadata,
                    Data = contentResult.Ciphertext
                });

                totalSize += contentResult.Ciphertext.Length;
            }

            if (totalSize > _limits.MaxTotalSize)
            {
                throw new InvalidOperationException(
                    $"Total capsa size {totalSize} bytes exceeds maximum of {_limits.MaxTotalSize / 1024 / 1024}MB");
            }

            string? encryptedSubject = null, subjectIV = null, subjectAuthTag = null;
            string? encryptedBody = null, bodyIV = null, bodyAuthTag = null;
            string? encryptedStructured = null, structuredIV = null, structuredAuthTag = null;

            if (!string.IsNullOrEmpty(Subject))
            {
                var iv = SecureMemory.GenerateRandomBytes(12);
                var result = aesProvider.Encrypt(Encoding.UTF8.GetBytes(Subject), _masterKey, iv);
                encryptedSubject = Base64Url.Encode(result.Ciphertext);
                subjectIV = Base64Url.Encode(iv);
                subjectAuthTag = Base64Url.Encode(result.AuthTagBytes);

                if (encryptedSubject.Length > MaxEncryptedSubject)
                {
                    throw new InvalidOperationException(
                        $"Encrypted subject ({encryptedSubject.Length} chars) exceeds server limit of {MaxEncryptedSubject} chars. Reduce subject length.");
                }
            }

            if (!string.IsNullOrEmpty(Body))
            {
                var iv = SecureMemory.GenerateRandomBytes(12);
                var result = aesProvider.Encrypt(Encoding.UTF8.GetBytes(Body), _masterKey, iv);
                encryptedBody = Base64Url.Encode(result.Ciphertext);
                bodyIV = Base64Url.Encode(iv);
                bodyAuthTag = Base64Url.Encode(result.AuthTagBytes);

                if (encryptedBody.Length > MaxEncryptedBody)
                {
                    throw new InvalidOperationException(
                        $"Encrypted body ({encryptedBody.Length} chars) exceeds server limit of {MaxEncryptedBody} chars. Reduce body length.");
                }
            }

            if (Structured.Count > 0)
            {
                var json = JsonSerializer.Serialize(Structured);
                var iv = SecureMemory.GenerateRandomBytes(12);
                var result = aesProvider.Encrypt(Encoding.UTF8.GetBytes(json), _masterKey, iv);
                encryptedStructured = Base64Url.Encode(result.Ciphertext);
                structuredIV = Base64Url.Encode(iv);
                structuredAuthTag = Base64Url.Encode(result.AuthTagBytes);

                if (encryptedStructured.Length > MaxEncryptedStructured)
                {
                    throw new InvalidOperationException(
                        $"Encrypted structured data ({encryptedStructured.Length} chars) exceeds server limit of {MaxEncryptedStructured} chars. Reduce structured data size.");
                }
            }

            var keychainEntries = new List<KeychainEntry>();
            var recipientIds = _recipients.Select(r => r.PartyId).ToArray();

            foreach (var partyKey in partyKeys)
            {
                var recipient = _recipients.FirstOrDefault(r => r.PartyId == partyKey.Id);
                var isCreator = partyKey.Id == _creatorId;

                string[] permissions;
                string[]? actingFor = null;

                if (partyKey.IsDelegate != null && partyKey.IsDelegate.Length > 0)
                {
                    // Filter to only include recipients of THIS capsa
                    var relevantActingFor = partyKey.IsDelegate.Where(id => recipientIds.Contains(id)).ToArray();

                    if (relevantActingFor.Length == 0)
                    {
                        continue;
                    }

                    if (relevantActingFor.Length > MaxActingFor)
                    {
                        throw new InvalidOperationException(
                            $"Delegate \"{partyKey.Id}\" acting for {relevantActingFor.Length} parties exceeds server limit of {MaxActingFor}.");
                    }

                    permissions = new[] { "delegate" };
                    actingFor = relevantActingFor;
                }
                else if (isCreator)
                {
                    permissions = Array.Empty<string>();
                }
                else if (recipient != null)
                {
                    permissions = recipient.Permissions;
                    actingFor = recipient.ActingFor;
                }
                else
                {
                    continue;
                }

                // Creator always gets an encrypted key even with empty permissions
                var isDelegatedRecipient = permissions.Length == 0 && !isCreator;
                var keyIV = SecureMemory.GenerateRandomBytes(12);

                keychainEntries.Add(new KeychainEntry
                {
                    Party = partyKey.Id,
                    EncryptedKey = isDelegatedRecipient
                        ? string.Empty
                        : RsaKeyCache.Default.EncryptMasterKey(_masterKey, partyKey.PublicKey, partyKey.Fingerprint),
                    IV = Base64Url.Encode(keyIV),
                    Fingerprint = partyKey.Fingerprint,
                    Permissions = permissions,
                    ActingFor = actingFor,
                    Revoked = false
                });
            }

            var canonicalString = SignatureProvider.BuildCanonicalString(
                packageId,
                totalSize,
                "AES-256-GCM",
                encryptedFiles.Select(f => new FileHashData(f.Metadata.FileId, f.Metadata.Hash, f.Metadata.Size, f.Metadata.IV, f.Metadata.FilenameIV)).ToArray(),
                structuredIV,
                subjectIV,
                bodyIV);

            var signature = SignatureProvider.CreateJws(canonicalString, _creatorPrivateKey);

            if (signature.Payload.Length > MaxSignaturePayload)
            {
                throw new InvalidOperationException(
                    $"Signature payload ({signature.Payload.Length} chars) exceeds server limit of {MaxSignaturePayload} chars.");
            }

            var capsa = new CapsaUploadData
            {
                PackageId = packageId,
                Keychain = new CapsaKeychain
                {
                    Algorithm = "AES-256-GCM",
                    Keys = keychainEntries.ToArray()
                },
                Signature = signature,
                AccessControl = new CapsaAccessControl
                {
                    ExpiresAt = _expiresAt?.ToString("o")
                },
                DeliveryPriority = "normal",
                Files = encryptedFiles.Select(f => f.Metadata).ToArray(),
                EncryptedSubject = encryptedSubject,
                SubjectIV = subjectIV,
                SubjectAuthTag = subjectAuthTag,
                EncryptedBody = encryptedBody,
                BodyIV = bodyIV,
                BodyAuthTag = bodyAuthTag,
                EncryptedStructured = encryptedStructured,
                StructuredIV = structuredIV,
                StructuredAuthTag = structuredAuthTag
            };

            if (!string.IsNullOrEmpty(Metadata.Label) ||
                Metadata.Tags?.Length > 0 ||
                !string.IsNullOrEmpty(Metadata.Notes) ||
                Metadata.RelatedPackages?.Length > 0)
            {
                if (Metadata.Label != null && Metadata.Label.Length > MaxMetadataLabel)
                {
                    throw new InvalidOperationException(
                        $"Metadata label ({Metadata.Label.Length} chars) exceeds server limit of {MaxMetadataLabel} chars.");
                }
                if (Metadata.Tags != null && Metadata.Tags.Length > MaxMetadataTags)
                {
                    throw new InvalidOperationException(
                        $"Metadata tags count ({Metadata.Tags.Length}) exceeds server limit of {MaxMetadataTags}.");
                }
                if (Metadata.Tags != null)
                {
                    foreach (var tag in Metadata.Tags)
                    {
                        if (tag.Length > MaxTagLength)
                        {
                            throw new InvalidOperationException(
                                $"Metadata tag \"{tag.Substring(0, Math.Min(20, tag.Length))}...\" ({tag.Length} chars) exceeds server limit of {MaxTagLength} chars.");
                        }
                    }
                }
                if (Metadata.Notes != null && Metadata.Notes.Length > MaxMetadataNotes)
                {
                    throw new InvalidOperationException(
                        $"Metadata notes ({Metadata.Notes.Length} chars) exceeds server limit of {MaxMetadataNotes} chars.");
                }
                if (Metadata.RelatedPackages != null && Metadata.RelatedPackages.Length > MaxRelatedPackages)
                {
                    throw new InvalidOperationException(
                        $"Related packages count ({Metadata.RelatedPackages.Length}) exceeds server limit of {MaxRelatedPackages}.");
                }
                capsa.Metadata = Metadata;
            }

            // Defense-in-depth: detect duplicate IVs across all fields.
            // Server performs the same check and will reject duplicates.
            var allIVs = new HashSet<string>();
            var ivList = new List<string>();
            if (subjectIV != null) ivList.Add(subjectIV);
            if (bodyIV != null) ivList.Add(bodyIV);
            if (structuredIV != null) ivList.Add(structuredIV);
            foreach (var entry in keychainEntries)
            {
                if (entry.IV != null) ivList.Add(entry.IV);
            }
            foreach (var f in encryptedFiles)
            {
                ivList.Add(f.Metadata.IV);
                ivList.Add(f.Metadata.FilenameIV);
            }
            foreach (var iv in ivList)
            {
                if (!allIVs.Add(iv))
                {
                    throw new InvalidOperationException(
                        "Duplicate IV detected across capsa fields. This indicates a CSPRNG failure. Do not send this capsa.");
                }
            }

            return new BuiltCapsa
            {
                Capsa = capsa,
                Files = encryptedFiles.ToArray()
            };
        }

        private static async Task<byte[]> ReadFileDataAsync(FileInput file)
        {
            if (file.Data != null)
            {
                return file.Data;
            }

            if (!string.IsNullOrEmpty(file.Path))
            {
#if NET6_0_OR_GREATER
                return await File.ReadAllBytesAsync(file.Path).ConfigureAwait(false);
#else
                return await Task.FromResult(File.ReadAllBytes(file.Path)).ConfigureAwait(false);
#endif
            }

            if (file.Stream != null)
            {
                using var ms = new MemoryStream();
                await file.Stream.CopyToAsync(ms).ConfigureAwait(false);
                return ms.ToArray();
            }

            throw new InvalidOperationException("File input must have Data, Path, or Stream");
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(CapsaBuilder));
        }

        /// <summary>
        /// Securely clear the master key from memory.
        /// </summary>
        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            SecureMemory.Clear(_masterKey);
        }
    }
}
