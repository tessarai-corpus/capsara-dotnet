using System;
using System.Collections.Generic;
using Capsara.SDK.Internal.Crypto;

namespace Capsara.SDK.Internal
{
    internal sealed class CachedFileMetadata
    {
        public string FileId { get; set; } = string.Empty;
        public string IV { get; set; } = string.Empty;
        public string AuthTag { get; set; } = string.Empty;
        public bool Compressed { get; set; }
        public string EncryptedFilename { get; set; } = string.Empty;
        public string FilenameIV { get; set; } = string.Empty;
        public string FilenameAuthTag { get; set; } = string.Empty;
    }

    internal sealed class CapsaCacheEntry : IDisposable
    {
        private byte[] _masterKey;
        private bool _disposed;

        public CapsaCacheEntry(byte[] masterKey)
        {
            _masterKey = masterKey ?? throw new ArgumentNullException(nameof(masterKey));
        }

        /// <summary>Caller is responsible for clearing the returned copy.</summary>
        public byte[] GetMasterKey()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(CapsaCacheEntry));

            var copy = new byte[_masterKey.Length];
            Array.Copy(_masterKey, copy, _masterKey.Length);
            return copy;
        }

        public Dictionary<string, CachedFileMetadata> Files { get; set; } = new();
        public DateTimeOffset CachedAt { get; set; }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            SecureMemory.Clear(_masterKey);
            _masterKey = Array.Empty<byte>();
        }
    }

    /// <summary>
    /// In-memory cache for decrypted capsa master keys and file metadata.
    /// Master keys stored in memory only; securely zeroed on eviction, Dispose, or TTL expiry.
    /// </summary>
    internal sealed class CapsaCache : IDisposable
    {
        private readonly Dictionary<string, CapsaCacheEntry> _cache = new();
        private readonly object _lock = new();
        private readonly TimeSpan _ttl;
        private readonly int _maxSize;
        private bool _disposed;

        public const int DefaultMaxSize = 100;

        public CapsaCache(TimeSpan? ttl = null, int? maxSize = null)
        {
            _ttl = ttl ?? TimeSpan.FromMinutes(5);
            _maxSize = maxSize ?? DefaultMaxSize;
        }

        public void Set(string capsaId, byte[] masterKey, CachedFileMetadata[] files)
        {
            ThrowIfDisposed();

            lock (_lock)
            {
                if (_cache.TryGetValue(capsaId, out var existing))
                {
                    existing.Dispose();
                    _cache.Remove(capsaId);
                }

                while (_cache.Count >= _maxSize)
                {
                    EvictOldest();
                }

                var fileDict = new Dictionary<string, CachedFileMetadata>();
                foreach (var file in files)
                {
                    fileDict[file.FileId] = file;
                }

                var keyCopy = new byte[masterKey.Length];
                Array.Copy(masterKey, keyCopy, masterKey.Length);

                _cache[capsaId] = new CapsaCacheEntry(keyCopy)
                {
                    Files = fileDict,
                    CachedAt = DateTimeOffset.UtcNow
                };
            }
        }

        /// <summary>Caller must clear the returned array.</summary>
        public byte[]? GetMasterKey(string capsaId)
        {
            ThrowIfDisposed();

            lock (_lock)
            {
                if (!_cache.TryGetValue(capsaId, out var entry))
                    return null;

                if (IsExpired(entry))
                {
                    entry.Dispose();
                    _cache.Remove(capsaId);
                    return null;
                }

                return entry.GetMasterKey();
            }
        }

        public CachedFileMetadata? GetFileMetadata(string capsaId, string fileId)
        {
            ThrowIfDisposed();

            lock (_lock)
            {
                if (!_cache.TryGetValue(capsaId, out var entry))
                    return null;

                if (IsExpired(entry))
                {
                    entry.Dispose();
                    _cache.Remove(capsaId);
                    return null;
                }

                return entry.Files.TryGetValue(fileId, out var metadata) ? metadata : null;
            }
        }

        public void Clear(string capsaId)
        {
            lock (_lock)
            {
                if (_cache.TryGetValue(capsaId, out var entry))
                {
                    entry.Dispose();
                    _cache.Remove(capsaId);
                }
            }
        }

        public void ClearAll()
        {
            lock (_lock)
            {
                foreach (var entry in _cache.Values)
                {
                    entry.Dispose();
                }
                _cache.Clear();
            }
        }

        public int Count
        {
            get
            {
                lock (_lock)
                {
                    return _cache.Count;
                }
            }
        }

        public void Prune()
        {
            lock (_lock)
            {
                var now = DateTimeOffset.UtcNow;
                var toRemove = new List<string>();

                foreach (var kvp in _cache)
                {
                    if (now - kvp.Value.CachedAt > _ttl)
                    {
                        toRemove.Add(kvp.Key);
                    }
                }

                foreach (var key in toRemove)
                {
                    if (_cache.TryGetValue(key, out var entry))
                    {
                        entry.Dispose();
                        _cache.Remove(key);
                    }
                }
            }
        }

        private void EvictOldest()
        {
            string? oldestKey = null;
            var oldestTime = DateTimeOffset.MaxValue;

            foreach (var kvp in _cache)
            {
                if (kvp.Value.CachedAt < oldestTime)
                {
                    oldestTime = kvp.Value.CachedAt;
                    oldestKey = kvp.Key;
                }
            }

            if (oldestKey != null && _cache.TryGetValue(oldestKey, out var entry))
            {
                entry.Dispose();
                _cache.Remove(oldestKey);
            }
        }

        private bool IsExpired(CapsaCacheEntry entry)
        {
            return DateTimeOffset.UtcNow - entry.CachedAt > _ttl;
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(CapsaCache));
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            ClearAll();
        }
    }
}
