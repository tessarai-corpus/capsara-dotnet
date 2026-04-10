using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Capsara.SDK.Builder;
using Capsara.SDK.Internal.Crypto;
using Capsara.SDK.Models;
using Capsara.SDK.Tests.Helpers;
using FluentAssertions;
using Xunit;

namespace Capsara.SDK.Tests.Builder
{
    /// <summary>
    /// Tests for CapsaBuilder fluent envelope construction.
    /// Uses shared key fixture to avoid expensive RSA key generation per test class.
    /// </summary>
    [Collection("SharedKeys")]
    public class CapsaBuilderTests
    {
        private readonly GeneratedKeyPairResult _creatorKeyPair;
        private readonly GeneratedKeyPairResult _recipientKeyPair;
        private readonly GeneratedKeyPairResult _thirdKeyPair;
        private readonly string _creatorId;

        public CapsaBuilderTests(SharedKeyFixture fixture)
        {
            _creatorKeyPair = fixture.PrimaryKeyPair;
            _recipientKeyPair = fixture.SecondaryKeyPair;
            _thirdKeyPair = fixture.TertiaryKeyPair;
            _creatorId = TestHelpers.GeneratePartyId();
        }

        #region Constructor Tests

        [Fact]
        public void Constructor_WithValidParams_CreatesBuilder()
        {
            // Act
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);

            // Assert
            builder.Should().NotBeNull();
        }

        [Fact]
        public void Constructor_NullCreatorId_Throws()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() =>
                new CapsaBuilder(null!, _creatorKeyPair.PrivateKey));
        }

        [Fact]
        public void Constructor_NullPrivateKey_Throws()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() =>
                new CapsaBuilder(_creatorId, null!));
        }

        [Fact]
        public void Constructor_WithCustomLimits_UsesLimits()
        {
            // Arrange
            var limits = new SystemLimits
            {
                MaxFilesPerCapsa = 5,
                MaxFileSize = 1000,
                MaxTotalSize = 5000
            };

            // Act
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey, limits);

            // Assert - Add 5 files should work
            for (int i = 0; i < 5; i++)
            {
                builder.AddFile(new FileInput
                {
                    Filename = $"file{i}.txt",
                    Data = new byte[100]
                });
            }

            // Adding 6th file should throw
            Assert.Throws<InvalidOperationException>(() =>
                builder.AddFile(new FileInput
                {
                    Filename = "file6.txt",
                    Data = new byte[100]
                }));
        }

        #endregion

        #region AddRecipient Tests

        [Fact]
        public void AddRecipient_ReturnsBuilder()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            var recipientId = TestHelpers.GeneratePartyId();

            // Act
            var result = builder.AddRecipient(recipientId);

            // Assert
            result.Should().BeSameAs(builder);
        }

        [Fact]
        public void AddRecipient_MultipleRecipients_AddsAll()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            var recipientId1 = TestHelpers.GeneratePartyId();
            var recipientId2 = TestHelpers.GeneratePartyId();
            var recipientId3 = TestHelpers.GeneratePartyId();

            // Act
            builder.AddRecipient(recipientId1)
                   .AddRecipient(recipientId2)
                   .AddRecipient(recipientId3);

            // Assert
            builder.GetRecipientIds().Should().HaveCount(3);
            builder.GetRecipientIds().Should().Contain(recipientId1);
            builder.GetRecipientIds().Should().Contain(recipientId2);
            builder.GetRecipientIds().Should().Contain(recipientId3);
        }

        #endregion

        #region AddFile Tests

        [Fact]
        public void AddFile_WithByteArray_ReturnsBuilder()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            var fileInput = new FileInput
            {
                Filename = "test.txt",
                Data = Encoding.UTF8.GetBytes("Hello, World!")
            };

            // Act
            var result = builder.AddFile(fileInput);

            // Assert
            result.Should().BeSameAs(builder);
            builder.GetFileCount().Should().Be(1);
        }

        [Fact]
        public void AddFile_WithStream_AddsFile()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            using var stream = new MemoryStream(Encoding.UTF8.GetBytes("Stream content"));
            var fileInput = new FileInput
            {
                Filename = "stream.txt",
                Stream = stream
            };

            // Act
            builder.AddFile(fileInput);

            // Assert
            builder.GetFileCount().Should().Be(1);
        }

        [Fact]
        public void AddFile_ExceedsMaxFiles_Throws()
        {
            // Arrange - must set all limits, not just MaxFilesPerCapsa
            var limits = new SystemLimits
            {
                MaxFilesPerCapsa = 2,
                MaxFileSize = 1024 * 1024, // 1MB
                MaxTotalSize = 10L * 1024 * 1024 // 10MB
            };
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey, limits);

            builder.AddFile(new FileInput { Filename = "file1.txt", Data = new byte[10] });
            builder.AddFile(new FileInput { Filename = "file2.txt", Data = new byte[10] });

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() =>
                builder.AddFile(new FileInput { Filename = "file3.txt", Data = new byte[10] }));
        }

        [Fact]
        public void AddFile_ExceedsMaxFileSize_Throws()
        {
            // Arrange
            var limits = new SystemLimits { MaxFileSize = 100 };
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey, limits);

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() =>
                builder.AddFile(new FileInput { Filename = "big.txt", Data = new byte[200] }));
        }

        [Fact]
        public void AddFile_NoDataOrPathOrStream_Throws()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);

            // Act & Assert
            Assert.Throws<ArgumentException>(() =>
                builder.AddFile(new FileInput { Filename = "empty.txt" }));
        }

        [Fact]
        public void AddFile_MultipleFiles_AddsAll()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);

            // Act
            builder.AddFile(new FileInput { Filename = "file1.txt", Data = new byte[10] })
                   .AddFile(new FileInput { Filename = "file2.txt", Data = new byte[20] })
                   .AddFile(new FileInput { Filename = "file3.txt", Data = new byte[30] });

            // Assert
            builder.GetFileCount().Should().Be(3);
        }

        #endregion

        #region Subject/Body/Structured Tests

        [Fact]
        public void Subject_CanBeSet()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);

            // Act
            builder.Subject = "Test Subject";

            // Assert
            builder.Subject.Should().Be("Test Subject");
        }

        [Fact]
        public void Body_CanBeSet()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);

            // Act
            builder.Body = "Test body content";

            // Assert
            builder.Body.Should().Be("Test body content");
        }

        [Fact]
        public void Structured_CanAddData()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);

            // Act
            builder.Structured["key1"] = "value1";
            builder.Structured["key2"] = 123;

            // Assert
            builder.Structured.Should().HaveCount(2);
            builder.Structured["key1"].Should().Be("value1");
            builder.Structured["key2"].Should().Be(123);
        }

        #endregion

        #region Metadata Tests

        [Fact]
        public void Metadata_CanSetLabel()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);

            // Act
            builder.Metadata.Label = "Test Label";

            // Assert
            builder.Metadata.Label.Should().Be("Test Label");
        }

        [Fact]
        public void Metadata_CanSetTags()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);

            // Act
            builder.Metadata.Tags = new[] { "tag1", "tag2", "tag3" };

            // Assert
            builder.Metadata.Tags.Should().HaveCount(3);
        }

        [Fact]
        public void Metadata_CanSetNotes()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);

            // Act
            builder.Metadata.Notes = "Some notes about this capsa";

            // Assert
            builder.Metadata.Notes.Should().Be("Some notes about this capsa");
        }

        #endregion

        #region ExpiresAt Tests

        [Fact]
        public void ExpiresAt_CanBeSet()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            var expiresAt = DateTimeOffset.UtcNow.AddDays(30);

            // Act
            builder.ExpiresAt = expiresAt;

            // Assert
            builder.ExpiresAt.Should().NotBeNull();
        }

        [Fact]
        public void ExpiresAt_RoundsToMinute()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            var expiresAt = new DateTimeOffset(2024, 6, 15, 10, 30, 45, TimeSpan.Zero); // 10:30:45

            // Act
            builder.ExpiresAt = expiresAt;

            // Assert
            builder.ExpiresAt!.Value.Second.Should().Be(0);
            builder.ExpiresAt!.Value.Minute.Should().Be(30);
        }

        [Fact]
        public void ExpiresAt_NullClearsValue()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.ExpiresAt = DateTimeOffset.UtcNow.AddDays(30);

            // Act
            builder.ExpiresAt = null;

            // Assert
            builder.ExpiresAt.Should().BeNull();
        }

        #endregion

        #region BuildAsync Tests

        [Fact]
        public async Task BuildAsync_WithValidData_ReturnsBuiltCapsa()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            var recipientId = TestHelpers.GeneratePartyId();

            builder.AddRecipient(recipientId);
            builder.AddFile(new FileInput
            {
                Filename = "test.txt",
                Data = Encoding.UTF8.GetBytes("Hello, World!")
            });
            builder.Subject = "Test Subject";

            var partyKeys = new[]
            {
                TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair),
                TestHelpers.CreateMockPartyKey(recipientId, _recipientKeyPair)
            };

            // Act
            var result = await builder.BuildAsync(partyKeys);

            // Assert
            result.Should().NotBeNull();
            result.Capsa.Should().NotBeNull();
            result.Capsa.PackageId.Should().StartWith("capsa_");
            result.Files.Should().HaveCount(1);
        }

        [Fact]
        public async Task BuildAsync_EncryptsSubject()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddRecipient(TestHelpers.GeneratePartyId());
            builder.AddFile(new FileInput { Filename = "test.txt", Data = new byte[10] });
            builder.Subject = "Secret Subject";

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };

            // Act
            var result = await builder.BuildAsync(partyKeys);

            // Assert
            result.Capsa.EncryptedSubject.Should().NotBeNullOrEmpty();
            result.Capsa.SubjectIV.Should().NotBeNullOrEmpty();
            result.Capsa.SubjectAuthTag.Should().NotBeNullOrEmpty();
        }

        [Fact]
        public async Task BuildAsync_EncryptsBody()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddRecipient(TestHelpers.GeneratePartyId());
            builder.AddFile(new FileInput { Filename = "test.txt", Data = new byte[10] });
            builder.Body = "Secret body content";

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };

            // Act
            var result = await builder.BuildAsync(partyKeys);

            // Assert
            result.Capsa.EncryptedBody.Should().NotBeNullOrEmpty();
            result.Capsa.BodyIV.Should().NotBeNullOrEmpty();
            result.Capsa.BodyAuthTag.Should().NotBeNullOrEmpty();
        }

        [Fact]
        public async Task BuildAsync_EncryptsStructuredData()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddRecipient(TestHelpers.GeneratePartyId());
            builder.AddFile(new FileInput { Filename = "test.txt", Data = new byte[10] });
            builder.Structured["claimNumber"] = "CLM-12345";
            builder.Structured["amount"] = 1000.50;

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };

            // Act
            var result = await builder.BuildAsync(partyKeys);

            // Assert
            result.Capsa.EncryptedStructured.Should().NotBeNullOrEmpty();
            result.Capsa.StructuredIV.Should().NotBeNullOrEmpty();
            result.Capsa.StructuredAuthTag.Should().NotBeNullOrEmpty();
        }

        [Fact]
        public async Task BuildAsync_CreatesKeychainEntries()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            var recipientId = TestHelpers.GeneratePartyId();

            builder.AddRecipient(recipientId);
            builder.AddFile(new FileInput { Filename = "test.txt", Data = new byte[10] });

            var partyKeys = new[]
            {
                TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair),
                TestHelpers.CreateMockPartyKey(recipientId, _recipientKeyPair)
            };

            // Act
            var result = await builder.BuildAsync(partyKeys);

            // Assert
            result.Capsa.Keychain.Keys.Should().HaveCount(2);
            result.Capsa.Keychain.Keys.Should().Contain(k => k.Party == _creatorId);
            result.Capsa.Keychain.Keys.Should().Contain(k => k.Party == recipientId);
        }

        [Fact]
        public async Task BuildAsync_CreatesSignature()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput { Filename = "test.txt", Data = new byte[10] });

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };

            // Act
            var result = await builder.BuildAsync(partyKeys);

            // Assert
            result.Capsa.Signature.Should().NotBeNull();
            result.Capsa.Signature.Protected.Should().NotBeNullOrEmpty();
            result.Capsa.Signature.Payload.Should().NotBeNullOrEmpty();
            result.Capsa.Signature.Signature.Should().NotBeNullOrEmpty();
        }

        [Fact]
        public async Task BuildAsync_EncryptsFilenames()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput { Filename = "secret-document.pdf", Data = new byte[10] });

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };

            // Act
            var result = await builder.BuildAsync(partyKeys);

            // Assert
            var file = result.Capsa.Files[0];
            file.EncryptedFilename.Should().NotBeNullOrEmpty();
            file.FilenameIV.Should().NotBeNullOrEmpty();
            file.FilenameAuthTag.Should().NotBeNullOrEmpty();
        }

        [Fact]
        public async Task BuildAsync_HashesFileContent()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput { Filename = "test.txt", Data = Encoding.UTF8.GetBytes("Test content") });

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };

            // Act
            var result = await builder.BuildAsync(partyKeys);

            // Assert
            var file = result.Capsa.Files[0];
            file.Hash.Should().NotBeNullOrEmpty();
            file.HashAlgorithm.Should().Be("SHA-256");
        }

        [Fact]
        public async Task BuildAsync_ExceedsTotalSize_Throws()
        {
            // Arrange
            var limits = new SystemLimits { MaxTotalSize = 100, MaxFileSize = 1000, MaxFilesPerCapsa = 10 };
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey, limits);
            builder.AddFile(new FileInput { Filename = "file1.txt", Data = new byte[60] });
            builder.AddFile(new FileInput { Filename = "file2.txt", Data = new byte[60] });

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };

            // Act & Assert
            await Assert.ThrowsAsync<InvalidOperationException>(
                () => builder.BuildAsync(partyKeys));
        }

        [Fact]
        public async Task BuildAsync_DetectsMimeType()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput { Filename = "document.pdf", Data = new byte[10] });
            builder.AddFile(new FileInput { Filename = "image.jpg", Data = new byte[10] });

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };

            // Act
            var result = await builder.BuildAsync(partyKeys);

            // Assert
            result.Capsa.Files[0].Mimetype.Should().Be("application/pdf");
            result.Capsa.Files[1].Mimetype.Should().Be("image/jpeg");
        }

        [Fact]
        public async Task BuildAsync_WithExplicitMimeType_UsesExplicitType()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput
            {
                Filename = "unknown.xyz",
                Data = new byte[10],
                Mimetype = "application/custom"
            });

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };

            // Act
            var result = await builder.BuildAsync(partyKeys);

            // Assert
            result.Capsa.Files[0].Mimetype.Should().Be("application/custom");
        }

        #endregion

        #region Fluent API Tests

        [Fact]
        public async Task FluentApi_BuildsCompleteCapsaAsync()
        {
            // Arrange
            var recipientId = TestHelpers.GeneratePartyId();

            // Act
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey)
            {
                Subject = "Important Document",
                Body = "Please review the attached files.",
                ExpiresAt = DateTimeOffset.UtcNow.AddDays(7)
            };

            builder.AddRecipient(recipientId)
                   .AddFile(new FileInput { Filename = "report.pdf", Data = new byte[100] })
                   .AddFile(new FileInput { Filename = "appendix.xlsx", Data = new byte[50] });

            builder.Metadata.Label = "Q4 Report";
            builder.Metadata.Tags = new[] { "finance", "quarterly" };
            builder.Structured["quarter"] = "Q4";
            builder.Structured["year"] = 2024;

            var partyKeys = new[]
            {
                TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair),
                TestHelpers.CreateMockPartyKey(recipientId, _recipientKeyPair)
            };

            var result = await builder.BuildAsync(partyKeys);

            // Assert
            result.Capsa.PackageId.Should().StartWith("capsa_");
            result.Files.Should().HaveCount(2);
            result.Capsa.EncryptedSubject.Should().NotBeNullOrEmpty();
            result.Capsa.EncryptedBody.Should().NotBeNullOrEmpty();
            result.Capsa.EncryptedStructured.Should().NotBeNullOrEmpty();
            result.Capsa.AccessControl.ExpiresAt.Should().NotBeNullOrEmpty();
            result.Capsa.Metadata!.Label.Should().Be("Q4 Report");
        }

        #endregion
    }
}
