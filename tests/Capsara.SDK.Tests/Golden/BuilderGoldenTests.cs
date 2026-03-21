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

namespace Capsara.SDK.Tests.Golden
{
    /// <summary>
    /// Golden tests for CapsaBuilder with real cryptographic operations.
    /// Tests IV uniqueness, file size/count validation, expiration, signature, and delegation.
    /// </summary>
    [Collection("SharedKeys")]
    public class BuilderGoldenTests
    {
        private readonly GeneratedKeyPairResult _creatorKeyPair;
        private readonly GeneratedKeyPairResult _recipientKeyPair;
        private readonly GeneratedKeyPairResult _thirdKeyPair;
        private readonly string _creatorId;

        public BuilderGoldenTests(SharedKeyFixture fixture)
        {
            _creatorKeyPair = fixture.PrimaryKeyPair;
            _recipientKeyPair = fixture.SecondaryKeyPair;
            _thirdKeyPair = fixture.TertiaryKeyPair;
            _creatorId = TestHelpers.GeneratePartyId();
        }

        #region IV Uniqueness Tests

        [Fact]
        public async Task BuildAsync_GeneratesUniqueIVsPerFile()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput { Filename = "file1.txt", Data = new byte[100] });
            builder.AddFile(new FileInput { Filename = "file2.txt", Data = new byte[100] });
            builder.AddFile(new FileInput { Filename = "file3.txt", Data = new byte[100] });

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };

            // Act
            var result = await builder.BuildAsync(partyKeys);

            // Assert
            var ivs = result.Capsa.Files.Select(f => f.IV).ToList();
            ivs.Distinct().Count().Should().Be(3, "Each file should have a unique IV");
        }

        [Fact]
        public async Task BuildAsync_GeneratesUniqueFilenameIVsPerFile()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput { Filename = "file1.txt", Data = new byte[100] });
            builder.AddFile(new FileInput { Filename = "file2.txt", Data = new byte[100] });

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };

            // Act
            var result = await builder.BuildAsync(partyKeys);

            // Assert
            var filenameIVs = result.Capsa.Files.Select(f => f.FilenameIV).ToList();
            filenameIVs.Distinct().Count().Should().Be(2, "Each filename should have a unique IV");
        }

        [Fact]
        public async Task BuildAsync_SubjectAndBodyIVsAreDifferent()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.Subject = "Test Subject";
            builder.Body = "Test Body";
            builder.AddFile(new FileInput { Filename = "file.txt", Data = new byte[10] });

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };

            // Act
            var result = await builder.BuildAsync(partyKeys);

            // Assert
            result.Capsa.SubjectIV.Should().NotBe(result.Capsa.BodyIV);
        }

        [Fact]
        public async Task BuildAsync_TwoBuilds_ProduceDifferentIVs()
        {
            // Arrange
            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };

            var builder1 = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder1.AddFile(new FileInput { Filename = "file.txt", Data = new byte[10] });
            builder1.Subject = "Same subject";

            var builder2 = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder2.AddFile(new FileInput { Filename = "file.txt", Data = new byte[10] });
            builder2.Subject = "Same subject";

            // Act
            var result1 = await builder1.BuildAsync(partyKeys);
            var result2 = await builder2.BuildAsync(partyKeys);

            // Assert - IVs should differ even with identical input
            result1.Capsa.SubjectIV.Should().NotBe(result2.Capsa.SubjectIV);
        }

        #endregion

        #region File Size/Count Validation Tests

        [Fact]
        public void AddFile_ExceedsMaxFilesPerCapsa_Throws()
        {
            // Arrange
            var limits = new SystemLimits
            {
                MaxFilesPerCapsa = 3,
                MaxFileSize = 1024 * 1024,
                MaxTotalSize = 10L * 1024 * 1024
            };
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey, limits);

            builder.AddFile(new FileInput { Filename = "file1.txt", Data = new byte[10] });
            builder.AddFile(new FileInput { Filename = "file2.txt", Data = new byte[10] });
            builder.AddFile(new FileInput { Filename = "file3.txt", Data = new byte[10] });

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() =>
                builder.AddFile(new FileInput { Filename = "file4.txt", Data = new byte[10] }));
        }

        [Fact]
        public void AddFile_ExceedsMaxFileSize_Throws()
        {
            // Arrange
            var limits = new SystemLimits { MaxFileSize = 50 };
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey, limits);

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() =>
                builder.AddFile(new FileInput { Filename = "big.txt", Data = new byte[100] }));
        }

        [Fact]
        public async Task BuildAsync_ExceedsTotalSize_Throws()
        {
            // Arrange
            var limits = new SystemLimits { MaxTotalSize = 50, MaxFileSize = 1000, MaxFilesPerCapsa = 10 };
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey, limits);
            builder.AddFile(new FileInput { Filename = "file1.txt", Data = new byte[30] });
            builder.AddFile(new FileInput { Filename = "file2.txt", Data = new byte[30] });

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };

            // Act & Assert
            await Assert.ThrowsAsync<InvalidOperationException>(
                () => builder.BuildAsync(partyKeys));
        }

        [Fact]
        public void AddFile_NoDataNoStreamNoPath_Throws()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);

            // Act & Assert
            Assert.Throws<ArgumentException>(() =>
                builder.AddFile(new FileInput { Filename = "empty.txt" }));
        }

        [Fact]
        public void AddFile_WithStream_Succeeds()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            using var stream = new MemoryStream(Encoding.UTF8.GetBytes("Stream content"));

            // Act
            builder.AddFile(new FileInput { Filename = "stream.txt", Stream = stream });

            // Assert
            builder.GetFileCount().Should().Be(1);
        }

        [Fact]
        public void GetFileCount_InitiallyZero()
        {
            // Arrange & Act
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);

            // Assert
            builder.GetFileCount().Should().Be(0);
        }

        #endregion

        #region Expiration Tests

        [Fact]
        public void ExpiresAt_DefaultsToNull()
        {
            // Arrange & Act
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);

            // Assert
            builder.ExpiresAt.Should().BeNull();
        }

        [Fact]
        public void ExpiresAt_RoundsSecondsToZero()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            var expiresAt = new DateTimeOffset(2025, 6, 15, 10, 30, 59, TimeSpan.Zero);

            // Act
            builder.ExpiresAt = expiresAt;

            // Assert
            builder.ExpiresAt!.Value.Second.Should().Be(0);
        }

        [Fact]
        public async Task BuildAsync_WithExpiration_SetsAccessControl()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.ExpiresAt = DateTimeOffset.UtcNow.AddDays(30);
            builder.AddFile(new FileInput { Filename = "test.txt", Data = new byte[10] });

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };

            // Act
            var result = await builder.BuildAsync(partyKeys);

            // Assert
            result.Capsa.AccessControl.ExpiresAt.Should().NotBeNullOrEmpty();
        }

        #endregion

        #region Signature Tests

        [Fact]
        public async Task BuildAsync_ProducesValidSignature()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput { Filename = "test.txt", Data = Encoding.UTF8.GetBytes("content") });

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };

            // Act
            var result = await builder.BuildAsync(partyKeys);

            // Assert
            result.Capsa.Signature.Should().NotBeNull();
            result.Capsa.Signature.Protected.Should().NotBeNullOrEmpty();
            result.Capsa.Signature.Payload.Should().NotBeNullOrEmpty();
            result.Capsa.Signature.Signature.Should().NotBeNullOrEmpty();

            // Verify the signature is valid using the creator's public key
            var isValid = SignatureProvider.VerifyJws(
                result.Capsa.Signature.Protected,
                result.Capsa.Signature.Payload,
                result.Capsa.Signature.Signature,
                _creatorKeyPair.PublicKey);
            isValid.Should().BeTrue();
        }

        [Fact]
        public async Task BuildAsync_SignatureVerifiesWithCreatorPublicKey()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput { Filename = "doc.pdf", Data = new byte[50] });
            builder.Subject = "Signed subject";

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };

            // Act
            var result = await builder.BuildAsync(partyKeys);

            // Assert - should NOT verify with a different key
            var invalidVerify = SignatureProvider.VerifyJws(
                result.Capsa.Signature.Protected,
                result.Capsa.Signature.Payload,
                result.Capsa.Signature.Signature,
                _recipientKeyPair.PublicKey);
            invalidVerify.Should().BeFalse();
        }

        #endregion

        #region Delegation Tests

        [Fact]
        public async Task BuildAsync_WithDelegate_CreatesKeychainEntries()
        {
            // Arrange
            var recipientId = TestHelpers.GeneratePartyId();
            var delegateId = TestHelpers.GeneratePartyId();

            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddRecipient(recipientId);
            builder.AddFile(new FileInput { Filename = "test.txt", Data = new byte[10] });

            var partyKeys = new[]
            {
                TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair),
                new PartyKey
                {
                    Id = delegateId,
                    Email = "delegate@example.com",
                    PublicKey = _thirdKeyPair.PublicKey,
                    Fingerprint = _thirdKeyPair.Fingerprint,
                    IsDelegate = new[] { recipientId }
                }
            };

            // Act
            var result = await builder.BuildAsync(partyKeys);

            // Assert - keychain should contain entries
            result.Capsa.Keychain.Keys.Should().NotBeEmpty();
            result.Capsa.Keychain.Keys.Should().Contain(k => k.Party == _creatorId);
        }

        [Fact]
        public async Task BuildAsync_MultipleRecipients_EachGetsKeychainEntry()
        {
            // Arrange
            var recipientId1 = TestHelpers.GeneratePartyId();
            var recipientId2 = TestHelpers.GeneratePartyId();

            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddRecipient(recipientId1)
                   .AddRecipient(recipientId2);
            builder.AddFile(new FileInput { Filename = "test.txt", Data = new byte[10] });

            var partyKeys = new[]
            {
                TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair),
                TestHelpers.CreateMockPartyKey(recipientId1, _recipientKeyPair),
                TestHelpers.CreateMockPartyKey(recipientId2, _thirdKeyPair)
            };

            // Act
            var result = await builder.BuildAsync(partyKeys);

            // Assert
            result.Capsa.Keychain.Keys.Should().HaveCount(3);
            result.Capsa.Keychain.Keys.Should().Contain(k => k.Party == _creatorId);
            result.Capsa.Keychain.Keys.Should().Contain(k => k.Party == recipientId1);
            result.Capsa.Keychain.Keys.Should().Contain(k => k.Party == recipientId2);
        }

        #endregion

        #region Metadata and Content Tests

        [Fact]
        public async Task BuildAsync_EncryptsAllContentFields()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.Subject = "Test Subject";
            builder.Body = "Test Body";
            builder.Structured["key"] = "value";
            builder.AddFile(new FileInput { Filename = "test.txt", Data = new byte[10] });

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };

            // Act
            var result = await builder.BuildAsync(partyKeys);

            // Assert
            result.Capsa.EncryptedSubject.Should().NotBeNullOrEmpty();
            result.Capsa.SubjectIV.Should().NotBeNullOrEmpty();
            result.Capsa.SubjectAuthTag.Should().NotBeNullOrEmpty();

            result.Capsa.EncryptedBody.Should().NotBeNullOrEmpty();
            result.Capsa.BodyIV.Should().NotBeNullOrEmpty();
            result.Capsa.BodyAuthTag.Should().NotBeNullOrEmpty();

            result.Capsa.EncryptedStructured.Should().NotBeNullOrEmpty();
            result.Capsa.StructuredIV.Should().NotBeNullOrEmpty();
            result.Capsa.StructuredAuthTag.Should().NotBeNullOrEmpty();
        }

        [Fact]
        public async Task BuildAsync_PackageIdStartsWithCapsa()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput { Filename = "test.txt", Data = new byte[10] });

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };

            // Act
            var result = await builder.BuildAsync(partyKeys);

            // Assert
            result.Capsa.PackageId.Should().StartWith("capsa_");
        }

        [Fact]
        public async Task BuildAsync_FileHashUsesShA256()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput { Filename = "test.txt", Data = Encoding.UTF8.GetBytes("test content") });

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };

            // Act
            var result = await builder.BuildAsync(partyKeys);

            // Assert
            result.Capsa.Files[0].Hash.Should().NotBeNullOrEmpty();
            result.Capsa.Files[0].HashAlgorithm.Should().Be("SHA-256");
        }

        [Fact]
        public void Metadata_CanSetAndGetLabel()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);

            // Act
            builder.Metadata.Label = "Test Label";

            // Assert
            builder.Metadata.Label.Should().Be("Test Label");
        }

        [Fact]
        public void FluentApi_ChainsCorrectly()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            var recipientId = TestHelpers.GeneratePartyId();

            // Act
            var returned = builder
                .AddRecipient(recipientId)
                .AddFile(new FileInput { Filename = "file1.txt", Data = new byte[10] })
                .AddFile(new FileInput { Filename = "file2.txt", Data = new byte[10] });

            // Assert
            returned.Should().BeSameAs(builder);
            builder.GetFileCount().Should().Be(2);
            builder.GetRecipientIds().Should().Contain(recipientId);
        }

        #endregion

        #region Defense-in-Depth: Server-Aligned Pre-Flight Validations

        [Fact]
        public void AddRecipient_RejectsWhenKeychainWouldExceedLimit()
        {
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);

            // Add 99 recipients (+1 creator = 100 total, at limit, still valid)
            for (int i = 0; i < 99; i++)
            {
                builder.AddRecipient($"party_{i}");
            }

            // 100th recipient would make 101 (100 + creator) = over limit
            Assert.Throws<InvalidOperationException>(() => builder.AddRecipient("one_too_many"));
        }

        [Fact]
        public void AddRecipients_RejectsBatchThatWouldExceedLimit()
        {
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddRecipient("existing_1");

            var tooMany = Enumerable.Range(0, 100).Select(i => $"batch_{i}").ToArray();

            Assert.Throws<InvalidOperationException>(() => builder.AddRecipients(tooMany));
        }

        [Fact]
        public async Task BuildAsync_RejectsEncryptedSubjectExceeding64KB()
        {
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput { Filename = "f.txt", Data = new byte[10] });

            // 60KB of text + base64url overhead will exceed 65536 chars
            builder.Subject = new string('x', 60_000);

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => builder.BuildAsync(partyKeys));
            ex.Message.Should().Contain("subject").And.Contain("server limit");
        }

        [Fact]
        public async Task BuildAsync_AcceptsSubjectWithinLimit()
        {
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput { Filename = "f.txt", Data = new byte[10] });
            builder.Subject = "Normal subject line";

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };
            var result = await builder.BuildAsync(partyKeys);
            result.Capsa.EncryptedSubject.Should().NotBeNullOrEmpty();
        }

        [Fact]
        public async Task BuildAsync_RejectsEncryptedBodyExceeding1MB()
        {
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput { Filename = "f.txt", Data = new byte[10] });

            builder.Body = new string('x', 900_000);

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => builder.BuildAsync(partyKeys));
            ex.Message.Should().Contain("body").And.Contain("server limit");
        }

        [Fact]
        public async Task BuildAsync_RejectsEncryptedStructuredExceeding1MB()
        {
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput { Filename = "f.txt", Data = new byte[10] });

            builder.Structured["bigField"] = new string('x', 900_000);

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => builder.BuildAsync(partyKeys));
            ex.Message.Should().Contain("structured").And.Contain("server limit");
        }

        [Fact]
        public async Task BuildAsync_RejectsMetadataLabelExceeding512Chars()
        {
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput { Filename = "f.txt", Data = new byte[10] });
            builder.Metadata.Label = new string('x', 513);

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => builder.BuildAsync(partyKeys));
            ex.Message.Should().Contain("label").And.Contain("512");
        }

        [Fact]
        public async Task BuildAsync_RejectsMoreThan100Tags()
        {
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput { Filename = "f.txt", Data = new byte[10] });
            builder.Metadata.Tags = Enumerable.Range(0, 101).Select(i => $"tag_{i}").ToArray();

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => builder.BuildAsync(partyKeys));
            ex.Message.Should().Contain("tags count").And.Contain("100");
        }

        [Fact]
        public async Task BuildAsync_RejectsIndividualTagExceeding100Chars()
        {
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput { Filename = "f.txt", Data = new byte[10] });
            builder.Metadata.Tags = new[] { new string('x', 101) };

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => builder.BuildAsync(partyKeys));
            ex.Message.Should().Contain("tag").And.Contain("100 chars");
        }

        [Fact]
        public async Task BuildAsync_RejectsMetadataNotesExceeding10KB()
        {
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput { Filename = "f.txt", Data = new byte[10] });
            builder.Metadata.Notes = new string('x', 10_241);

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => builder.BuildAsync(partyKeys));
            ex.Message.Should().Contain("notes").And.Contain("10240");
        }

        [Fact]
        public async Task BuildAsync_RejectsMoreThan50RelatedPackages()
        {
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput { Filename = "f.txt", Data = new byte[10] });
            builder.Metadata.RelatedPackages = Enumerable.Range(0, 51).Select(i => $"pkg_{i}").ToArray();

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => builder.BuildAsync(partyKeys));
            ex.Message.Should().Contain("Related packages").And.Contain("50");
        }

        [Fact]
        public async Task BuildAsync_ProducesGloballyUniqueIVsAcrossAllFields()
        {
            var recipientId = TestHelpers.GeneratePartyId();
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.Subject = "test";
            builder.Body = "test body";
            builder.Structured["key"] = "val";
            builder.AddRecipient(recipientId);
            builder.AddFile(new FileInput { Filename = "a.txt", Data = new byte[10] });
            builder.AddFile(new FileInput { Filename = "b.txt", Data = new byte[10] });

            var partyKeys = new[]
            {
                TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair),
                TestHelpers.CreateMockPartyKey(recipientId, _recipientKeyPair),
            };
            var result = await builder.BuildAsync(partyKeys);

            // Collect ALL IVs from the built capsa
            var allIVs = new List<string>();
            if (result.Capsa.SubjectIV != null) allIVs.Add(result.Capsa.SubjectIV);
            if (result.Capsa.BodyIV != null) allIVs.Add(result.Capsa.BodyIV);
            if (result.Capsa.StructuredIV != null) allIVs.Add(result.Capsa.StructuredIV);
            foreach (var key in result.Capsa.Keychain.Keys)
            {
                if (key.IV != null) allIVs.Add(key.IV);
            }
            foreach (var file in result.Capsa.Files)
            {
                allIVs.Add(file.IV);
                allIVs.Add(file.FilenameIV);
            }

            // All IVs must be globally unique
            allIVs.Distinct().Count().Should().Be(allIVs.Count);
            // 2 files * 2 IVs (content + filename) + 3 metadata + 2 keychain = 9 IVs
            allIVs.Count.Should().BeGreaterThanOrEqualTo(9);
        }

        [Fact]
        public void ServerLimitsConstants_MatchZodSchema()
        {
            CapsaBuilder.MaxKeychainKeys.Should().Be(100);
            CapsaBuilder.MaxEncryptedSubject.Should().Be(65_536);
            CapsaBuilder.MaxEncryptedBody.Should().Be(1_048_576);
            CapsaBuilder.MaxEncryptedStructured.Should().Be(1_048_576);
            CapsaBuilder.MaxMetadataLabel.Should().Be(512);
            CapsaBuilder.MaxMetadataTags.Should().Be(100);
            CapsaBuilder.MaxTagLength.Should().Be(100);
            CapsaBuilder.MaxMetadataNotes.Should().Be(10_240);
            CapsaBuilder.MaxRelatedPackages.Should().Be(50);
        }

        #endregion

        #region Defense-in-Depth: Additional Pre-Flight Validations

        // Party ID Validation

        [Fact]
        public void AddRecipient_RejectsEmptyPartyId()
        {
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            Assert.Throws<ArgumentException>(() => builder.AddRecipient(""));
        }

        [Fact]
        public void AddRecipient_RejectsNullPartyId()
        {
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            Assert.Throws<ArgumentException>(() => builder.AddRecipient(null!));
        }

        [Fact]
        public void AddRecipient_RejectsPartyIdExceeding100Chars()
        {
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            var longId = new string('x', 101);
            var ex = Assert.Throws<ArgumentException>(() => builder.AddRecipient(longId));
            ex.Message.Should().Contain("100");
        }

        [Fact]
        public void AddRecipients_RejectsEmptyPartyIdInBatch()
        {
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            Assert.Throws<ArgumentException>(() => builder.AddRecipients("valid_id", ""));
        }

        // No-Content Guard

        [Fact]
        public async Task BuildAsync_RejectsEmptyCapsaWithNoFilesOrMessage()
        {
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            // Only structured data, no files or subject/body
            builder.WithStructured("key", "val");

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => builder.BuildAsync(partyKeys));
            ex.Message.Should().Contain("files").And.Contain("message");
        }

        [Fact]
        public async Task BuildAsync_AllowsSubjectOnlyWithNoFiles()
        {
            var recipientId = TestHelpers.GeneratePartyId();
            var recipientKeys = _recipientKeyPair;
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddRecipient(recipientId);
            builder.WithSubject("Just a message");

            var partyKeys = new[]
            {
                TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair),
                TestHelpers.CreateMockPartyKey(recipientId, recipientKeys)
            };
            var result = await builder.BuildAsync(partyKeys);
            result.Should().NotBeNull();
            result.Capsa.EncryptedSubject.Should().NotBeNullOrEmpty();
            result.Capsa.Files.Should().BeEmpty();
        }

        // Encrypted Filename Length Limit

        [Fact]
        public async Task BuildAsync_RejectsLongFilenameExceedingEncryptedLimit()
        {
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            // 1540 + 4 (.txt) = 1544 bytes → AES-GCM → 1544 bytes → base64url → 2059 chars > 2048
            var longFilename = new string('a', 1540) + ".txt";
            builder.AddFile(new FileInput { Filename = longFilename, Data = new byte[10] });

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => builder.BuildAsync(partyKeys));
            ex.Message.Should().Contain("Encrypted filename").And.Contain("2048");
        }

        // Constants Verification

        [Fact]
        public void ServerLimitsConstants_IncludeNewValidationLimits()
        {
            CapsaBuilder.MaxPartyIdLength.Should().Be(100);
            CapsaBuilder.MaxEncryptedFilename.Should().Be(2048);
            CapsaBuilder.MaxSignaturePayload.Should().Be(65536);
            CapsaBuilder.MaxActingFor.Should().Be(10);
        }

        #endregion
    }
}
