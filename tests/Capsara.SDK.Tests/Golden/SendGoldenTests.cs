using System;
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
    /// Golden tests for send/upload validation, batch splitting, and edge cases.
    /// </summary>
    [Collection("SharedKeys")]
    public class SendGoldenTests
    {
        private readonly GeneratedKeyPairResult _creatorKeyPair;
        private readonly string _creatorId;

        public SendGoldenTests(SharedKeyFixture fixture)
        {
            _creatorKeyPair = fixture.PrimaryKeyPair;
            _creatorId = TestHelpers.GeneratePartyId();
        }

        #region Validation Tests

        [Fact]
        public async Task SendCapsasAsync_WithoutIdentity_Throws()
        {
            // Arrange
            using var client = new CapsaraClient("https://api.test.com");
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput { Filename = "test.txt", Data = new byte[10] });

            // Act & Assert
            await Assert.ThrowsAsync<InvalidOperationException>(
                () => client.SendCapsasAsync(new[] { builder }));
        }

        [Fact]
        public void CapsaBuilder_NullCreatorId_Throws()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() =>
                new CapsaBuilder(null!, _creatorKeyPair.PrivateKey));
        }

        [Fact]
        public void CapsaBuilder_NullPrivateKey_Throws()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() =>
                new CapsaBuilder(_creatorId, null!));
        }

        [Fact]
        public void CapsaBuilder_EmptyCreatorId_DoesNotThrow()
        {
            // Arrange & Act - empty string is not null, constructor should accept it
            // (validation happens later during build)
            var builder = new CapsaBuilder("", _creatorKeyPair.PrivateKey);

            // Assert
            builder.Should().NotBeNull();
        }

        #endregion

        #region Batch Splitting Tests

        [Fact]
        public void MaxBatchSize_DefaultIs150()
        {
            // Arrange
            var options = new CapsaraClientOptions();

            // Assert
            options.MaxBatchSize.Should().Be(150);
        }

        [Fact]
        public void MaxBatchSize_CanBeCustomized()
        {
            // Arrange & Act
            var options = new CapsaraClientOptions { MaxBatchSize = 50 };

            // Assert
            options.MaxBatchSize.Should().Be(50);
        }

        [Fact]
        public async Task BuildAsync_MultipleBuildersProduceDistinctIds()
        {
            // Arrange
            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };

            var builder1 = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder1.AddFile(new FileInput { Filename = "file1.txt", Data = new byte[10] });

            var builder2 = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder2.AddFile(new FileInput { Filename = "file2.txt", Data = new byte[10] });

            // Act
            var result1 = await builder1.BuildAsync(partyKeys);
            var result2 = await builder2.BuildAsync(partyKeys);

            // Assert
            result1.Capsa.PackageId.Should().NotBe(result2.Capsa.PackageId);
        }

        #endregion

        #region Empty Array Tests

        [Fact]
        public async Task SendCapsasAsync_EmptyArray_Throws()
        {
            // Arrange
            using var client = new CapsaraClient("https://api.test.com");
            client.SetPrivateKey(_creatorKeyPair.PrivateKey);

            // Act & Assert - Sending zero capsas should throw or handle gracefully
            await Assert.ThrowsAnyAsync<Exception>(
                () => client.SendCapsasAsync(Array.Empty<CapsaBuilder>()));
        }

        #endregion

        #region BuiltCapsa Model Tests

        [Fact]
        public async Task BuildAsync_ReturnsEncryptedFileData()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput { Filename = "test.txt", Data = Encoding.UTF8.GetBytes("Hello content") });

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };

            // Act
            var result = await builder.BuildAsync(partyKeys);

            // Assert
            result.Files.Should().HaveCount(1);
            result.Files[0].Data.Should().NotBeEmpty();
            result.Files[0].Metadata.Should().NotBeNull();
            result.Files[0].Metadata.FileId.Should().NotBeNullOrEmpty();
        }

        [Fact]
        public async Task BuildAsync_EncryptedDataDiffersFromPlaintext()
        {
            // Arrange
            var plaintext = Encoding.UTF8.GetBytes("This is plaintext data");
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput { Filename = "test.txt", Data = plaintext });

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };

            // Act
            var result = await builder.BuildAsync(partyKeys);

            // Assert - encrypted data should not match plaintext
            result.Files[0].Data.Should().NotEqual(plaintext);
        }

        #endregion
    }
}
