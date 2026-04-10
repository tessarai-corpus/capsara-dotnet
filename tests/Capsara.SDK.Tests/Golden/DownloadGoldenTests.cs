using System;
using System.Text;
using System.Threading.Tasks;
using Capsara.SDK.Builder;
using Capsara.SDK.Internal.Crypto;
using Capsara.SDK.Internal.Decryptor;
using Capsara.SDK.Models;
using Capsara.SDK.Tests.Helpers;
using FluentAssertions;
using Xunit;

namespace Capsara.SDK.Tests.Golden
{
    /// <summary>
    /// Golden tests for file download: file metadata validation, decryption tests, missing authTag.
    /// </summary>
    [Collection("SharedKeys")]
    public class DownloadGoldenTests
    {
        private readonly GeneratedKeyPairResult _creatorKeyPair;
        private readonly string _creatorId;

        public DownloadGoldenTests(SharedKeyFixture fixture)
        {
            _creatorKeyPair = fixture.PrimaryKeyPair;
            _creatorId = TestHelpers.GeneratePartyId();
        }

        #region File Metadata Tests

        [Fact]
        public void EncryptedFile_DefaultValues_AreValid()
        {
            // Arrange & Act
            var file = new EncryptedFile();

            // Assert
            file.FileId.Should().Be(string.Empty);
            file.EncryptedFilename.Should().Be(string.Empty);
            file.IV.Should().Be(string.Empty);
            file.AuthTag.Should().Be(string.Empty);
            file.Mimetype.Should().Be(string.Empty);
            file.Hash.Should().Be(string.Empty);
            file.Size.Should().Be(0);
            file.Compressed.Should().BeNull();
        }

        [Fact]
        public async Task BuildAsync_FileMetadata_HasRequiredFields()
        {
            // Arrange
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput { Filename = "report.pdf", Data = new byte[500] });

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };

            // Act
            var built = await builder.BuildAsync(partyKeys);

            // Assert
            var file = built.Capsa.Files[0];
            file.FileId.Should().NotBeNullOrEmpty();
            file.EncryptedFilename.Should().NotBeNullOrEmpty();
            file.FilenameIV.Should().NotBeNullOrEmpty();
            file.FilenameAuthTag.Should().NotBeNullOrEmpty();
            file.IV.Should().NotBeNullOrEmpty();
            file.AuthTag.Should().NotBeNullOrEmpty();
            file.Hash.Should().NotBeNullOrEmpty();
            file.HashAlgorithm.Should().Be("SHA-256");
            file.Size.Should().BeGreaterThan(0);
            file.Mimetype.Should().Be("application/pdf");
        }

        [Fact]
        public async Task BuildAsync_FileMetadata_OriginalSizeTracked()
        {
            // Arrange
            var data = new byte[500];
            var builder = new CapsaBuilder(_creatorId, _creatorKeyPair.PrivateKey);
            builder.AddFile(new FileInput { Filename = "data.bin", Data = data });

            var partyKeys = new[] { TestHelpers.CreateMockPartyKey(_creatorId, _creatorKeyPair) };

            // Act
            var built = await builder.BuildAsync(partyKeys);

            // Assert
            var file = built.Capsa.Files[0];
            file.OriginalSize.Should().NotBeNull();
        }

        #endregion

        #region File Decryption Tests

        [Fact]
        public void DecryptFile_WithValidData_ReturnsOriginal()
        {
            // Arrange
            using var aes = AesGcmProviderFactory.Create();
            var masterKey = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);
            var originalData = Encoding.UTF8.GetBytes("Original file content");

            var encResult = aes.Encrypt(originalData, masterKey, iv);

            // Act
            var decrypted = CapsaDecryptor.DecryptFile(
                encResult.Ciphertext,
                masterKey,
                Base64Url.Encode(encResult.IvBytes),
                Base64Url.Encode(encResult.AuthTagBytes),
                compressed: false);

            // Assert
            decrypted.Should().Equal(originalData);
        }

        [Fact]
        public void DecryptFile_WithCompression_DecompressesAfterDecryption()
        {
            // Arrange
            using var aes = AesGcmProviderFactory.Create();
            var masterKey = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);

            // Compress then encrypt (matching the send workflow)
            var originalData = Encoding.UTF8.GetBytes(new string('A', 1000));
            var compressed = CompressionProvider.Compress(originalData);
            var encResult = aes.Encrypt(compressed.CompressedData, masterKey, iv);

            // Act
            var decrypted = CapsaDecryptor.DecryptFile(
                encResult.Ciphertext,
                masterKey,
                Base64Url.Encode(encResult.IvBytes),
                Base64Url.Encode(encResult.AuthTagBytes),
                compressed: true);

            // Assert
            decrypted.Should().Equal(originalData);
        }

        [Fact]
        public void DecryptFilename_WithValidData_ReturnsOriginalFilename()
        {
            // Arrange
            using var aes = AesGcmProviderFactory.Create();
            var masterKey = SecureMemory.GenerateRandomBytes(32);
            var iv = SecureMemory.GenerateRandomBytes(12);
            var filenameBytes = Encoding.UTF8.GetBytes("secret-document.pdf");

            var encResult = aes.Encrypt(filenameBytes, masterKey, iv);

            // Act
            var filename = CapsaDecryptor.DecryptFilename(
                Base64Url.Encode(encResult.Ciphertext),
                masterKey,
                Base64Url.Encode(encResult.IvBytes),
                Base64Url.Encode(encResult.AuthTagBytes));

            // Assert
            filename.Should().Be("secret-document.pdf");
        }

        #endregion

        #region Missing AuthTag Tests

        [Fact]
        public void DecryptFile_MissingAuthTag_ThrowsSecurityError()
        {
            // Arrange
            var masterKey = SecureMemory.GenerateRandomBytes(32);
            var encryptedData = new byte[100];
            var iv = Base64Url.Encode(SecureMemory.GenerateRandomBytes(12));

            // Act & Assert
            var ex = Assert.Throws<InvalidOperationException>(() =>
                CapsaDecryptor.DecryptFile(encryptedData, masterKey, iv, "", compressed: false));

            ex.Message.Should().Contain("SECURITY ERROR");
            ex.Message.Should().Contain("authTag");
        }

        [Fact]
        public void DecryptFile_NullAuthTag_ThrowsSecurityError()
        {
            // Arrange
            var masterKey = SecureMemory.GenerateRandomBytes(32);
            var encryptedData = new byte[100];
            var iv = Base64Url.Encode(SecureMemory.GenerateRandomBytes(12));

            // Act & Assert
            var ex = Assert.Throws<InvalidOperationException>(() =>
                CapsaDecryptor.DecryptFile(encryptedData, masterKey, iv, null!, compressed: false));

            ex.Message.Should().Contain("SECURITY ERROR");
        }

        [Fact]
        public void DecryptFilename_MissingAuthTag_ThrowsSecurityError()
        {
            // Arrange
            var masterKey = SecureMemory.GenerateRandomBytes(32);
            var encryptedFilename = Base64Url.Encode(new byte[32]);
            var iv = Base64Url.Encode(SecureMemory.GenerateRandomBytes(12));

            // Act & Assert
            var ex = Assert.Throws<InvalidOperationException>(() =>
                CapsaDecryptor.DecryptFilename(encryptedFilename, masterKey, iv, ""));

            ex.Message.Should().Contain("SECURITY ERROR");
        }

        #endregion
    }
}
