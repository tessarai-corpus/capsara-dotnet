using System;
using System.Threading;
using Capsara.SDK.Internal;
using Capsara.SDK.Tests.Helpers;
using FluentAssertions;
using Xunit;

namespace Capsara.SDK.Tests.Golden
{
    /// <summary>
    /// Golden tests for CapsaCache: set/get, TTL expiration, clear, and file metadata lookup.
    /// </summary>
    public class CacheGoldenTests
    {
        #region Set and Get Tests

        [Fact]
        public void Set_Get_RoundTrip()
        {
            // Arrange
            var cache = new CapsaCache();
            var capsaId = TestHelpers.GenerateCapsaId();
            var masterKey = TestHelpers.GenerateTestMasterKey();
            var files = new[] { CreateTestFileMetadata() };

            // Act
            cache.Set(capsaId, masterKey, files);
            var result = cache.GetMasterKey(capsaId);

            // Assert
            result.Should().BeEquivalentTo(masterKey);
        }

        [Fact]
        public void GetMasterKey_NonExistentKey_ReturnsNull()
        {
            // Arrange
            var cache = new CapsaCache();

            // Act
            var result = cache.GetMasterKey("nonexistent");

            // Assert
            result.Should().BeNull();
        }

        [Fact]
        public void Set_OverwritesExistingEntry()
        {
            // Arrange
            var cache = new CapsaCache();
            var capsaId = TestHelpers.GenerateCapsaId();
            var masterKey1 = TestHelpers.GenerateTestMasterKey();
            var masterKey2 = TestHelpers.GenerateTestMasterKey();
            var files = new[] { CreateTestFileMetadata() };

            // Act
            cache.Set(capsaId, masterKey1, files);
            cache.Set(capsaId, masterKey2, files);

            // Assert
            cache.Count.Should().Be(1);
            cache.GetMasterKey(capsaId).Should().BeEquivalentTo(masterKey2);
        }

        [Fact]
        public void Count_ReflectsNumberOfEntries()
        {
            // Arrange
            var cache = new CapsaCache();
            var files = new[] { CreateTestFileMetadata() };

            // Act
            cache.Set("capsa_1", TestHelpers.GenerateTestMasterKey(), files);
            cache.Set("capsa_2", TestHelpers.GenerateTestMasterKey(), files);
            cache.Set("capsa_3", TestHelpers.GenerateTestMasterKey(), files);

            // Assert
            cache.Count.Should().Be(3);
        }

        #endregion

        #region TTL Tests

        [Fact]
        public void GetMasterKey_ExpiredEntry_ReturnsNull()
        {
            // Arrange
            var cache = new CapsaCache(TimeSpan.FromMilliseconds(50));
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
        public void GetMasterKey_NotExpired_ReturnsMasterKey()
        {
            // Arrange
            var cache = new CapsaCache(TimeSpan.FromMinutes(5));
            var capsaId = TestHelpers.GenerateCapsaId();
            var masterKey = TestHelpers.GenerateTestMasterKey();
            var files = new[] { CreateTestFileMetadata() };

            cache.Set(capsaId, masterKey, files);

            // Act
            var result = cache.GetMasterKey(capsaId);

            // Assert
            result.Should().NotBeNull();
            result.Should().BeEquivalentTo(masterKey);
        }

        #endregion

        #region Clear Tests

        [Fact]
        public void Clear_RemovesSpecificEntry()
        {
            // Arrange
            var cache = new CapsaCache();
            var capsaId1 = TestHelpers.GenerateCapsaId();
            var capsaId2 = TestHelpers.GenerateCapsaId();
            var files = new[] { CreateTestFileMetadata() };

            cache.Set(capsaId1, TestHelpers.GenerateTestMasterKey(), files);
            cache.Set(capsaId2, TestHelpers.GenerateTestMasterKey(), files);

            // Act
            cache.Clear(capsaId1);

            // Assert
            cache.Count.Should().Be(1);
            cache.GetMasterKey(capsaId1).Should().BeNull();
            cache.GetMasterKey(capsaId2).Should().NotBeNull();
        }

        [Fact]
        public void ClearAll_RemovesEverything()
        {
            // Arrange
            var cache = new CapsaCache();
            var files = new[] { CreateTestFileMetadata() };

            cache.Set("capsa_1", TestHelpers.GenerateTestMasterKey(), files);
            cache.Set("capsa_2", TestHelpers.GenerateTestMasterKey(), files);
            cache.Set("capsa_3", TestHelpers.GenerateTestMasterKey(), files);

            // Act
            cache.ClearAll();

            // Assert
            cache.Count.Should().Be(0);
        }

        [Fact]
        public void Clear_NonExistentEntry_DoesNotThrow()
        {
            // Arrange
            var cache = new CapsaCache();

            // Act & Assert
            cache.Invoking(c => c.Clear("nonexistent"))
                .Should().NotThrow();
        }

        #endregion

        #region File Metadata Lookup Tests

        [Fact]
        public void GetFileMetadata_ReturnsCorrectFile()
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
        public void GetFileMetadata_WrongFileId_ReturnsNull()
        {
            // Arrange
            var cache = new CapsaCache();
            var capsaId = TestHelpers.GenerateCapsaId();
            var masterKey = TestHelpers.GenerateTestMasterKey();
            var files = new[] { CreateTestFileMetadata() };

            cache.Set(capsaId, masterKey, files);

            // Act
            var result = cache.GetFileMetadata(capsaId, "wrong_file_id");

            // Assert
            result.Should().BeNull();
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
