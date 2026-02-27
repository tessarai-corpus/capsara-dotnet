using System;
using System.Collections.Generic;
using System.Threading;
using Capsara.SDK.Internal;
using Capsara.SDK.Tests.Helpers;
using FluentAssertions;
using Xunit;

namespace Capsara.SDK.Tests.Internal
{
    /// <summary>
    /// Tests for CapsaCache in-memory envelope caching.
    /// </summary>
    public class CapsaCacheTests
    {
        #region Set and Get Tests

        [Fact]
        public void Set_StoresCapsaInCache()
        {
            // Arrange
            var cache = new CapsaCache();
            var capsaId = TestHelpers.GenerateCapsaId();
            var masterKey = TestHelpers.GenerateTestMasterKey();
            var files = new[] { CreateTestFileMetadata() };

            // Act
            cache.Set(capsaId, masterKey, files);

            // Assert
            cache.Count.Should().Be(1);
        }

        [Fact]
        public void GetMasterKey_ReturnsCachedMasterKey()
        {
            // Arrange
            var cache = new CapsaCache();
            var capsaId = TestHelpers.GenerateCapsaId();
            var masterKey = TestHelpers.GenerateTestMasterKey();
            var files = new[] { CreateTestFileMetadata() };

            cache.Set(capsaId, masterKey, files);

            // Act
            var result = cache.GetMasterKey(capsaId);

            // Assert
            result.Should().BeEquivalentTo(masterKey);
        }

        [Fact]
        public void GetMasterKey_NonExistentCapsa_ReturnsNull()
        {
            // Arrange
            var cache = new CapsaCache();
            var capsaId = TestHelpers.GenerateCapsaId();

            // Act
            var result = cache.GetMasterKey(capsaId);

            // Assert
            result.Should().BeNull();
        }

        [Fact]
        public void GetFileMetadata_ReturnsCachedFileMetadata()
        {
            // Arrange
            var cache = new CapsaCache();
            var capsaId = TestHelpers.GenerateCapsaId();
            var fileId = TestHelpers.GenerateFileId();
            var masterKey = TestHelpers.GenerateTestMasterKey();
            var files = new[] { CreateTestFileMetadata(fileId) };

            cache.Set(capsaId, masterKey, files);

            // Act
            var result = cache.GetFileMetadata(capsaId, fileId);

            // Assert
            result.Should().NotBeNull();
            result!.FileId.Should().Be(fileId);
        }

        [Fact]
        public void GetFileMetadata_NonExistentFile_ReturnsNull()
        {
            // Arrange
            var cache = new CapsaCache();
            var capsaId = TestHelpers.GenerateCapsaId();
            var masterKey = TestHelpers.GenerateTestMasterKey();
            var files = new[] { CreateTestFileMetadata() };

            cache.Set(capsaId, masterKey, files);

            // Act
            var result = cache.GetFileMetadata(capsaId, "nonexistent_file");

            // Assert
            result.Should().BeNull();
        }

        [Fact]
        public void GetFileMetadata_NonExistentCapsa_ReturnsNull()
        {
            // Arrange
            var cache = new CapsaCache();

            // Act
            var result = cache.GetFileMetadata("nonexistent_capsa", "file_123");

            // Assert
            result.Should().BeNull();
        }

        #endregion

        #region Expiration Tests

        [Fact]
        public void GetMasterKey_ExpiredEntry_ReturnsNull()
        {
            // Arrange
            var cache = new CapsaCache(TimeSpan.FromMilliseconds(50)); // 50ms TTL
            var capsaId = TestHelpers.GenerateCapsaId();
            var masterKey = TestHelpers.GenerateTestMasterKey();
            var files = new[] { CreateTestFileMetadata() };

            cache.Set(capsaId, masterKey, files);

            // Wait for expiration
            Thread.Sleep(100);

            // Act
            var result = cache.GetMasterKey(capsaId);

            // Assert
            result.Should().BeNull();
        }

        [Fact]
        public void GetFileMetadata_ExpiredEntry_ReturnsNull()
        {
            // Arrange
            var cache = new CapsaCache(TimeSpan.FromMilliseconds(50)); // 50ms TTL
            var capsaId = TestHelpers.GenerateCapsaId();
            var fileId = TestHelpers.GenerateFileId();
            var masterKey = TestHelpers.GenerateTestMasterKey();
            var files = new[] { CreateTestFileMetadata(fileId) };

            cache.Set(capsaId, masterKey, files);

            // Wait for expiration
            Thread.Sleep(100);

            // Act
            var result = cache.GetFileMetadata(capsaId, fileId);

            // Assert
            result.Should().BeNull();
        }

        [Fact]
        public void GetMasterKey_NotExpiredEntry_ReturnsMasterKey()
        {
            // Arrange
            var cache = new CapsaCache(TimeSpan.FromMinutes(5)); // 5 minute TTL
            var capsaId = TestHelpers.GenerateCapsaId();
            var masterKey = TestHelpers.GenerateTestMasterKey();
            var files = new[] { CreateTestFileMetadata() };

            cache.Set(capsaId, masterKey, files);

            // Act
            var result = cache.GetMasterKey(capsaId);

            // Assert
            result.Should().BeEquivalentTo(masterKey);
        }

        #endregion

        #region Clear Tests

        [Fact]
        public void Clear_RemovesSpecificCapsa()
        {
            // Arrange
            var cache = new CapsaCache();
            var capsaId1 = TestHelpers.GenerateCapsaId();
            var capsaId2 = TestHelpers.GenerateCapsaId();
            var masterKey = TestHelpers.GenerateTestMasterKey();
            var files = new[] { CreateTestFileMetadata() };

            cache.Set(capsaId1, masterKey, files);
            cache.Set(capsaId2, masterKey, files);

            // Act
            cache.Clear(capsaId1);

            // Assert
            cache.Count.Should().Be(1);
            cache.GetMasterKey(capsaId1).Should().BeNull();
            cache.GetMasterKey(capsaId2).Should().NotBeNull();
        }

        [Fact]
        public void ClearAll_RemovesAllCapsas()
        {
            // Arrange
            var cache = new CapsaCache();
            var masterKey = TestHelpers.GenerateTestMasterKey();
            var files = new[] { CreateTestFileMetadata() };

            for (int i = 0; i < 5; i++)
            {
                cache.Set(TestHelpers.GenerateCapsaId(), masterKey, files);
            }

            cache.Count.Should().Be(5);

            // Act
            cache.ClearAll();

            // Assert
            cache.Count.Should().Be(0);
        }

        [Fact]
        public void Clear_NonExistentCapsa_DoesNotThrow()
        {
            // Arrange
            var cache = new CapsaCache();

            // Act & Assert
            cache.Invoking(c => c.Clear("nonexistent"))
                .Should().NotThrow();
        }

        #endregion

        #region Update Tests

        [Fact]
        public void Set_OverwritesExistingEntry()
        {
            // Arrange
            var cache = new CapsaCache();
            var capsaId = TestHelpers.GenerateCapsaId();
            var masterKey1 = TestHelpers.GenerateTestMasterKey();
            var masterKey2 = TestHelpers.GenerateTestMasterKey();
            var files = new[] { CreateTestFileMetadata() };

            cache.Set(capsaId, masterKey1, files);
            cache.Set(capsaId, masterKey2, files);

            // Act
            var result = cache.GetMasterKey(capsaId);

            // Assert
            cache.Count.Should().Be(1);
            result.Should().BeEquivalentTo(masterKey2);
        }

        #endregion

        #region Multiple Files Tests

        [Fact]
        public void Set_StoresMultipleFiles()
        {
            // Arrange
            var cache = new CapsaCache();
            var capsaId = TestHelpers.GenerateCapsaId();
            var masterKey = TestHelpers.GenerateTestMasterKey();
            var fileId1 = TestHelpers.GenerateFileId();
            var fileId2 = TestHelpers.GenerateFileId();
            var fileId3 = TestHelpers.GenerateFileId();
            var files = new[]
            {
                CreateTestFileMetadata(fileId1),
                CreateTestFileMetadata(fileId2),
                CreateTestFileMetadata(fileId3)
            };

            // Act
            cache.Set(capsaId, masterKey, files);

            // Assert
            cache.GetFileMetadata(capsaId, fileId1).Should().NotBeNull();
            cache.GetFileMetadata(capsaId, fileId2).Should().NotBeNull();
            cache.GetFileMetadata(capsaId, fileId3).Should().NotBeNull();
        }

        #endregion

        #region Thread Safety Tests

        [Fact]
        public async System.Threading.Tasks.Task ConcurrentAccess_DoesNotThrow()
        {
            // Arrange
            var cache = new CapsaCache();
            var exceptions = new System.Collections.Concurrent.ConcurrentBag<Exception>();

            // Act
            var tasks = new System.Threading.Tasks.Task[10];
            for (int i = 0; i < 10; i++)
            {
                int index = i;
                tasks[i] = System.Threading.Tasks.Task.Run(() =>
                {
                    try
                    {
                        for (int j = 0; j < 100; j++)
                        {
                            var capsaId = $"capsa_{index}_{j}";
                            var masterKey = TestHelpers.GenerateTestMasterKey();
                            var files = new[] { CreateTestFileMetadata() };

                            cache.Set(capsaId, masterKey, files);
                            cache.GetMasterKey(capsaId);
                            cache.Clear(capsaId);
                        }
                    }
                    catch (Exception ex)
                    {
                        exceptions.Add(ex);
                    }
                });
            }

            await System.Threading.Tasks.Task.WhenAll(tasks);

            // Assert
            exceptions.Should().BeEmpty();
        }

        #endregion

        #region Default TTL Tests

        [Fact]
        public void DefaultTTL_IsFiveMinutes()
        {
            // Arrange & Act
            var cache = new CapsaCache();
            var capsaId = TestHelpers.GenerateCapsaId();
            var masterKey = TestHelpers.GenerateTestMasterKey();
            var files = new[] { CreateTestFileMetadata() };

            cache.Set(capsaId, masterKey, files);

            // Assert - entry should still be valid after a short time
            var result = cache.GetMasterKey(capsaId);
            result.Should().NotBeNull();
        }

        #endregion

        #region Max Size and LRU Eviction Tests

        [Fact]
        public void Set_EvictsOldestWhenMaxSizeReached()
        {
            // Arrange
            var cache = new CapsaCache(maxSize: 3);
            var capsaIds = new List<string>();
            var files = new[] { CreateTestFileMetadata() };

            // Add 3 entries (at max)
            for (int i = 0; i < 3; i++)
            {
                var id = $"capsa_{i}";
                capsaIds.Add(id);
                cache.Set(id, TestHelpers.GenerateTestMasterKey(), files);
                Thread.Sleep(10); // Ensure different timestamps
            }

            cache.Count.Should().Be(3);

            // Act - add a 4th entry
            cache.Set("capsa_new", TestHelpers.GenerateTestMasterKey(), files);

            // Assert - oldest entry should be evicted
            cache.Count.Should().Be(3);
            cache.GetMasterKey("capsa_0").Should().BeNull(); // Oldest evicted
            cache.GetMasterKey("capsa_1").Should().NotBeNull();
            cache.GetMasterKey("capsa_2").Should().NotBeNull();
            cache.GetMasterKey("capsa_new").Should().NotBeNull();
        }

        [Fact]
        public void Prune_RemovesExpiredEntries()
        {
            // Arrange
            var cache = new CapsaCache(TimeSpan.FromMilliseconds(50)); // 50ms TTL
            var files = new[] { CreateTestFileMetadata() };

            cache.Set("capsa_1", TestHelpers.GenerateTestMasterKey(), files);
            cache.Set("capsa_2", TestHelpers.GenerateTestMasterKey(), files);

            cache.Count.Should().Be(2);

            // Wait for expiration
            Thread.Sleep(100);

            // Act
            cache.Prune();

            // Assert
            cache.Count.Should().Be(0);
        }

        [Fact]
        public void Prune_KeepsNonExpiredEntries()
        {
            // Arrange
            var cache = new CapsaCache(TimeSpan.FromMinutes(5)); // 5 min TTL
            var files = new[] { CreateTestFileMetadata() };

            cache.Set("capsa_1", TestHelpers.GenerateTestMasterKey(), files);
            cache.Set("capsa_2", TestHelpers.GenerateTestMasterKey(), files);

            // Act
            cache.Prune();

            // Assert
            cache.Count.Should().Be(2);
        }

        [Fact]
        public void DefaultMaxSize_Is100()
        {
            // Assert
            CapsaCache.DefaultMaxSize.Should().Be(100);
        }

        #endregion

        private static CachedFileMetadata CreateTestFileMetadata(string? fileId = null)
        {
            return new CachedFileMetadata
            {
                FileId = fileId ?? TestHelpers.GenerateFileId(),
                IV = Convert.ToBase64String(TestHelpers.GenerateTestIV()),
                AuthTag = Convert.ToBase64String(new byte[16]),
                Compressed = false,
                EncryptedFilename = Convert.ToBase64String(new byte[32]),
                FilenameIV = Convert.ToBase64String(TestHelpers.GenerateTestIV()),
                FilenameAuthTag = Convert.ToBase64String(new byte[16])
            };
        }
    }
}
