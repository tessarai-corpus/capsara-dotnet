using System;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Capsara.SDK.Builder;
using Capsara.SDK.Internal;
using Capsara.SDK.Internal.Crypto;
using Capsara.SDK.Internal.Decryptor;
using Capsara.SDK.Internal.Http;
using Capsara.SDK.Internal.Services;
using Capsara.SDK.Models;

namespace Capsara.SDK
{
    /// <summary>Primary interface for zero-knowledge encrypted file sharing.</summary>
    public sealed class CapsaraClient : IDisposable
    {
        private readonly string _baseUrl;
        private readonly CapsaraClientOptions _options;
        private readonly AuthService _authService;
        private readonly KeyService _keyService;
        private readonly CapsaService _capsaService;
        private readonly DownloadService _downloadService;
        private readonly UploadService _uploadService;
        private readonly AuditService _auditService;
        private readonly AccountService _accountService;
        private readonly LimitsService _limitsService;
        private readonly HttpClient _httpClient;
        private readonly HttpClient _blobHttpClient;
        private readonly CapsaCache _capsaCache;

        private string? _creatorId;
        private string? _creatorPrivateKey;
        private bool _disposed;

        /// <summary>Create a new CapsaraClient.</summary>
        /// <param name="baseUrl">API base URL.</param>
        /// <param name="options">Client configuration options.</param>
        public CapsaraClient(string baseUrl, CapsaraClientOptions? options = null)
        {
            _baseUrl = baseUrl?.TrimEnd('/') ?? throw new ArgumentNullException(nameof(baseUrl));
            _options = options ?? new CapsaraClientOptions();

            _authService = new AuthService(baseUrl, new AuthServiceOptions
            {
                ExpectedIssuer = _options.ExpectedIssuer,
                ExpectedAudience = _options.ExpectedAudience,
                Timeout = _options.Timeout,
                Retry = _options.Retry,
                UserAgent = _options.UserAgent
            });

            _httpClient = HttpClientFactory.Create(
                baseUrl,
                () => _authService.GetToken(),
                _options.Timeout,
                _options.Retry,
                _options.UserAgent);

            // No auth headers — SAS URL contains credentials
            _blobHttpClient = HttpClientFactory.CreateForBlob(_options.Timeout);

            _keyService = new KeyService(baseUrl, () => _authService.GetToken(), new KeyServiceOptions
            {
                Timeout = _options.Timeout,
                Retry = _options.Retry,
                UserAgent = _options.UserAgent
            });

            _capsaService = new CapsaService(_httpClient, _keyService);

            _downloadService = new DownloadService(_httpClient, _blobHttpClient, new DownloadServiceOptions
            {
                TimeoutConfig = _options.Timeout,
                RetryConfig = _options.Retry,
                Logger = _options.Logger
            });

            _uploadService = new UploadService(
                _httpClient,
                _keyService,
                _options.MaxBatchSize,
                _options.Retry);

            _auditService = new AuditService(_httpClient);
            _accountService = new AccountService(_httpClient);
            _limitsService = new LimitsService(_httpClient);

            _capsaCache = new CapsaCache(_options.CacheTTL);

            if (!string.IsNullOrEmpty(_options.AccessToken))
            {
                _authService.SetToken(_options.AccessToken!);
            }
        }


        /// <summary>Authenticate with the Capsara API.</summary>
        /// <param name="credentials">Authentication credentials.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        public async Task<AuthResponse> LoginAsync(AuthCredentials credentials, CancellationToken cancellationToken = default)
        {
            var response = await _authService.LoginAsync(credentials, cancellationToken).ConfigureAwait(false);
            _creatorId = response.Party.Id;
            return response;
        }

        /// <summary>Log out and clear cached state.</summary>
        /// <returns>True if logout succeeded.</returns>
        /// <param name="cancellationToken">Cancellation token.</param>
        public async Task<bool> LogoutAsync(CancellationToken cancellationToken = default)
        {
            ClearCache();
            return await _authService.LogoutAsync(cancellationToken).ConfigureAwait(false);
        }

        /// <summary>Whether the client has a valid authentication token.</summary>
        public bool IsAuthenticated => _authService.IsAuthenticated;

        /// <summary>Set the creator's RSA private key for decryption and signing.</summary>
        /// <param name="privateKey">RSA private key (PEM).</param>
        public void SetPrivateKey(string privateKey)
        {
            _creatorPrivateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
        }


        /// <summary>Create a new CapsaBuilder for building encrypted capsas.</summary>
        /// <returns>CapsaBuilder configured with current identity and server limits.</returns>
        /// <param name="cancellationToken">Cancellation token.</param>
        public async Task<CapsaBuilder> CreateCapsaBuilderAsync(CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(_creatorId) || string.IsNullOrEmpty(_creatorPrivateKey))
            {
                throw new InvalidOperationException("Creator identity not set. Call LoginAsync() and SetPrivateKey() first.");
            }

            var limits = await GetLimitsAsync(cancellationToken).ConfigureAwait(false);
            return new CapsaBuilder(_creatorId!, _creatorPrivateKey!, limits);
        }

        /// <summary>Encrypt and upload one or more capsas.</summary>
        /// <param name="builders">CapsaBuilder instances to send.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        public async Task<SendResult> SendCapsasAsync(
            CapsaBuilder[] builders,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(_creatorId))
            {
                throw new InvalidOperationException("Creator identity not set. Call LoginAsync() and SetPrivateKey() first.");
            }

            return await _uploadService.SendCapsasAsync(builders, _creatorId!, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>Get capsa without decryption.</summary>
        /// <param name="capsaId">Capsa ID.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        public async Task<Capsa> GetCapsaAsync(string capsaId, CancellationToken cancellationToken = default)
        {
            return await _capsaService.GetCapsaAsync(capsaId, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>Get and decrypt a capsa. Concurrent requests for the same capsaId are deduplicated.</summary>
        /// <param name="capsaId">Capsa ID.</param>
        /// <param name="verifySignature">Whether to verify the creator's signature (default: true).</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        public async Task<DecryptedCapsa> GetDecryptedCapsaAsync(
            string capsaId,
            bool verifySignature = true,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(_creatorPrivateKey))
            {
                throw new InvalidOperationException("Private key required. Call LoginAsync() and SetPrivateKey() first.");
            }

            var capsa = await _capsaService.GetCapsaAsync(capsaId, cancellationToken).ConfigureAwait(false);

            string? creatorPublicKey = null;
            if (verifySignature)
            {
                creatorPublicKey = await _capsaService.GetCreatorPublicKeyAsync(capsa.Creator, cancellationToken).ConfigureAwait(false);
            }

            var decrypted = CapsaDecryptor.Decrypt(
                capsa,
                _creatorPrivateKey!,
                null, // Auto-detect party from keychain
                creatorPublicKey,
                verifySignature);

            var masterKey = decrypted.GetMasterKey();
            var cachedFiles = decrypted.Files.Select(f => new CachedFileMetadata
            {
                FileId = f.FileId,
                IV = f.IV,
                AuthTag = f.AuthTag,
                Compressed = f.Compressed ?? false,
                EncryptedFilename = f.EncryptedFilename,
                FilenameIV = f.FilenameIV,
                FilenameAuthTag = f.FilenameAuthTag
            }).ToArray();

            _capsaCache.Set(capsaId, masterKey, cachedFiles);

            return decrypted;
        }

        /// <summary>List capsas with optional filters.</summary>
        /// <param name="filters">Query filters.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        public async Task<CapsaListResponse> ListCapsasAsync(
            CapsaListFilters? filters = null,
            CancellationToken cancellationToken = default)
        {
            return await _capsaService.ListCapsasAsync(filters, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>Soft delete a capsa.</summary>
        /// <param name="capsaId">Capsa ID.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        public async Task DeleteCapsaAsync(string capsaId, CancellationToken cancellationToken = default)
        {
            _capsaCache.Clear(capsaId);
            await _capsaService.DeleteCapsaAsync(capsaId, cancellationToken).ConfigureAwait(false);
        }


        /// <summary>Download and decrypt a file from a capsa.</summary>
        /// <param name="capsaId">Capsa ID.</param>
        /// <param name="fileId">File ID.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        public async Task<DecryptedFileResult> DownloadFileAsync(
            string capsaId,
            string fileId,
            CancellationToken cancellationToken = default)
        {
            var masterKey = _capsaCache.GetMasterKey(capsaId);
            var cachedFile = _capsaCache.GetFileMetadata(capsaId, fileId);

            if (masterKey == null || cachedFile == null)
            {
                await GetDecryptedCapsaAsync(capsaId, true, cancellationToken).ConfigureAwait(false);
                masterKey = _capsaCache.GetMasterKey(capsaId);
                cachedFile = _capsaCache.GetFileMetadata(capsaId, fileId);
            }

            if (masterKey == null || cachedFile == null)
            {
                throw new InvalidOperationException($"File {fileId} not found in capsa {capsaId}");
            }

            try
            {
                var encryptedData = await _downloadService.DownloadEncryptedFileAsync(capsaId, fileId, cancellationToken).ConfigureAwait(false);

                var decryptedData = CapsaDecryptor.DecryptFile(
                    encryptedData,
                    masterKey,
                    cachedFile.IV,
                    cachedFile.AuthTag,
                    cachedFile.Compressed);

                var filename = CapsaDecryptor.DecryptFilename(
                    cachedFile.EncryptedFilename,
                    masterKey,
                    cachedFile.FilenameIV,
                    cachedFile.FilenameAuthTag);

                return new DecryptedFileResult
                {
                    Data = decryptedData,
                    Filename = filename
                };
            }
            finally
            {
                // Securely clear the master key copy from cache
                SecureMemory.Clear(masterKey);
            }
        }


        /// <summary>Get audit entries for a capsa.</summary>
        /// <param name="capsaId">Capsa ID.</param>
        /// <param name="filters">Query filters.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        public async Task<GetAuditEntriesResponse> GetAuditEntriesAsync(
            string capsaId,
            GetAuditEntriesFilters? filters = null,
            CancellationToken cancellationToken = default)
        {
            return await _auditService.GetAuditEntriesAsync(capsaId, filters, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>Create an audit entry for a capsa.</summary>
        /// <param name="capsaId">Capsa ID.</param>
        /// <param name="entry">Audit entry to create.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>True if successful.</returns>
        public async Task<bool> CreateAuditEntryAsync(
            string capsaId,
            CreateAuditEntryRequest entry,
            CancellationToken cancellationToken = default)
        {
            return await _auditService.CreateAuditEntryAsync(capsaId, entry, cancellationToken).ConfigureAwait(false);
        }


        /// <summary>Get the current public key for the authenticated party.</summary>
        /// <returns>Current public key info, or null if not set.</returns>
        /// <param name="cancellationToken">Cancellation token.</param>
        public async Task<PublicKeyInfo?> GetCurrentPublicKeyAsync(CancellationToken cancellationToken = default)
        {
            return await _accountService.GetCurrentPublicKeyAsync(cancellationToken).ConfigureAwait(false);
        }

        /// <summary>Add new public key (auto-rotates: moves current to history).</summary>
        /// <param name="publicKey">PEM-encoded public key.</param>
        /// <param name="fingerprint">SHA-256 fingerprint.</param>
        /// <param name="reason">Optional rotation reason.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        public async Task<PublicKeyInfo> AddPublicKeyAsync(
            string publicKey,
            string fingerprint,
            string? reason = null,
            CancellationToken cancellationToken = default)
        {
            return await _accountService.AddPublicKeyAsync(publicKey, fingerprint, reason, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>Get key rotation history.</summary>
        /// <returns>All historical keys including current.</returns>
        /// <param name="cancellationToken">Cancellation token.</param>
        public async Task<KeyHistoryEntry[]> GetKeyHistoryAsync(CancellationToken cancellationToken = default)
        {
            return await _accountService.GetKeyHistoryAsync(cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Generate new key pair and update on server.
        /// IMPORTANT: Application must store the returned private key securely.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        public async Task<KeyRotationResult> RotateKeyAsync(CancellationToken cancellationToken = default)
        {
            return await _accountService.RotateKeyAsync(cancellationToken).ConfigureAwait(false);
        }


        /// <summary>Get server-enforced limits (file size, batch size, etc.).</summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        public async Task<SystemLimits> GetLimitsAsync(CancellationToken cancellationToken = default)
        {
            return await _limitsService.GetLimitsAsync(cancellationToken).ConfigureAwait(false);
        }

        /// <summary>Generate an RSA-4096 key pair synchronously.</summary>
        public static GeneratedKeyPairResult GenerateKeyPair()
        {
            return KeyGenerator.GenerateKeyPair();
        }

        /// <summary>Generate an RSA-4096 key pair asynchronously.</summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        public static Task<GeneratedKeyPairResult> GenerateKeyPairAsync(CancellationToken cancellationToken = default)
        {
            return KeyGenerator.GenerateKeyPairAsync(cancellationToken);
        }

        /// <summary>Securely clear all cached master keys.</summary>
        public void ClearCache()
        {
            _capsaCache.ClearAll();
            _limitsService.ClearCache();
        }

        /// <summary>Release resources and securely clear cached keys.</summary>
        public void Dispose()
        {
            if (!_disposed)
            {
                _capsaCache.Dispose();
                _httpClient.Dispose();
                _blobHttpClient.Dispose();
                _creatorPrivateKey = null;
                _creatorId = null;
                _disposed = true;
            }
        }
    }
}
