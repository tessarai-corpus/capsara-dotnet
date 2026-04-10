using System;
using System.Collections.Generic;
using Capsara.SDK.Internal.Crypto;
using Capsara.SDK.Models;

namespace Capsara.SDK.Internal.Decryptor
{
    /// <summary>
    /// Decrypted capsa with accessible content and file metadata.
    /// </summary>
    public sealed class DecryptedCapsa : IDisposable
    {
        private byte[]? _masterKey;
        private bool _disposed;

        /// <summary>
        /// Capsa identifier
        /// </summary>
        public string Id { get; init; } = string.Empty;

        /// <summary>
        /// Creator party ID
        /// </summary>
        public string Creator { get; init; } = string.Empty;

        /// <summary>
        /// Creation timestamp (ISO 8601)
        /// </summary>
        public string CreatedAt { get; init; } = string.Empty;

        /// <summary>
        /// Last update timestamp (ISO 8601)
        /// </summary>
        public string UpdatedAt { get; init; } = string.Empty;

        /// <summary>
        /// Lifecycle status
        /// </summary>
        public CapsaStatus Status { get; init; }

        /// <summary>
        /// Decrypted subject
        /// </summary>
        public string? Subject { get; init; }

        /// <summary>
        /// Decrypted body/message
        /// </summary>
        public string? Body { get; init; }

        /// <summary>
        /// Decrypted structured data
        /// </summary>
        public Dictionary<string, object>? Structured { get; init; }

        /// <summary>
        /// Encrypted file metadata (files are still encrypted)
        /// </summary>
        public EncryptedFile[] Files { get; init; } = Array.Empty<EncryptedFile>();

        /// <summary>
        /// Access control settings
        /// </summary>
        public CapsaAccessControl AccessControl { get; init; } = new();

        /// <summary>
        /// Keychain entries
        /// </summary>
        public CapsaKeychain Keychain { get; init; } = new();

        /// <summary>
        /// Signature
        /// </summary>
        public CapsaSignature Signature { get; init; } = new();

        /// <summary>
        /// Public metadata (unencrypted)
        /// </summary>
        public CapsaMetadata? Metadata { get; init; }

        /// <summary>
        /// Total size of all files in bytes
        /// </summary>
        public long TotalSize { get; init; }

        /// <summary>
        /// File count
        /// </summary>
        public int FileCount => Files.Length;

        /// <summary>
        /// Original encrypted capsa
        /// </summary>
        public Capsa EncryptedCapsa { get; init; } = new();

        /// <summary>
        /// Get the decrypted master key for file decryption.
        ///
        /// SECURITY: This key is only valid for THIS capsa.
        /// Call Dispose() when done to zero the memory.
        /// </summary>
        internal byte[] GetMasterKey()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(DecryptedCapsa));
            if (_masterKey == null)
                throw new InvalidOperationException("Master key not available");
            return _masterKey;
        }

        /// <summary>
        /// Set the master key (internal use only)
        /// </summary>
        internal void SetMasterKey(byte[] key)
        {
            _masterKey = key;
        }

        /// <summary>
        /// Clear the master key from memory.
        /// </summary>
        public void ClearMasterKey()
        {
            if (_masterKey != null)
            {
                SecureMemory.ClearBuffer(_masterKey);
                _masterKey = null;
            }
        }

        /// <summary>
        /// Dispose and clear master key
        /// </summary>
        public void Dispose()
        {
            if (!_disposed)
            {
                ClearMasterKey();
                _disposed = true;
            }
        }
    }
}
