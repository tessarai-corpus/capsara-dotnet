using Capsara.SDK.Internal;
using FluentAssertions;
using Xunit;

namespace Capsara.SDK.Tests.Internal
{
    /// <summary>
    /// Tests for MimetypeLookup file extension to MIME type mapping.
    /// </summary>
    public class MimetypeLookupTests
    {
        #region Common Document Types

        [Theory]
        [InlineData("document.pdf", "application/pdf")]
        [InlineData("report.PDF", "application/pdf")]
        [InlineData("/path/to/file.pdf", "application/pdf")]
        public void Lookup_PdfFiles_ReturnsCorrectMimeType(string path, string expectedMime)
        {
            // Act
            var result = MimetypeLookup.Lookup(path);

            // Assert
            result.Should().Be(expectedMime);
        }

        [Theory]
        [InlineData("document.doc", "application/msword")]
        [InlineData("document.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")]
        [InlineData("spreadsheet.xls", "application/vnd.ms-excel")]
        [InlineData("spreadsheet.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")]
        [InlineData("presentation.ppt", "application/vnd.ms-powerpoint")]
        [InlineData("presentation.pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation")]
        public void Lookup_MicrosoftOfficeFiles_ReturnsCorrectMimeType(string path, string expectedMime)
        {
            // Act
            var result = MimetypeLookup.Lookup(path);

            // Assert
            result.Should().Be(expectedMime);
        }

        #endregion

        #region Image Types

        [Theory]
        [InlineData("photo.jpg", "image/jpeg")]
        [InlineData("photo.jpeg", "image/jpeg")]
        [InlineData("image.png", "image/png")]
        [InlineData("animation.gif", "image/gif")]
        [InlineData("bitmap.bmp", "image/bmp")]
        [InlineData("scan.tif", "image/tiff")]
        [InlineData("scan.tiff", "image/tiff")]
        [InlineData("modern.webp", "image/webp")]
        [InlineData("vector.svg", "image/svg+xml")]
        [InlineData("apple.heic", "image/heic")]
        [InlineData("apple.heif", "image/heif")]
        public void Lookup_ImageFiles_ReturnsCorrectMimeType(string path, string expectedMime)
        {
            // Act
            var result = MimetypeLookup.Lookup(path);

            // Assert
            result.Should().Be(expectedMime);
        }

        #endregion

        #region Audio Types

        [Theory]
        [InlineData("song.mp3", "audio/mpeg")]
        [InlineData("audio.wav", "audio/wav")]
        [InlineData("music.m4a", "audio/mp4")]
        [InlineData("sound.aac", "audio/aac")]
        [InlineData("track.ogg", "audio/ogg")]
        [InlineData("windows.wma", "audio/x-ms-wma")]
        [InlineData("lossless.flac", "audio/flac")]
        public void Lookup_AudioFiles_ReturnsCorrectMimeType(string path, string expectedMime)
        {
            // Act
            var result = MimetypeLookup.Lookup(path);

            // Assert
            result.Should().Be(expectedMime);
        }

        #endregion

        #region Video Types

        [Theory]
        [InlineData("video.mp4", "video/mp4")]
        [InlineData("movie.mov", "video/quicktime")]
        [InlineData("clip.avi", "video/x-msvideo")]
        [InlineData("windows.wmv", "video/x-ms-wmv")]
        [InlineData("container.mkv", "video/x-matroska")]
        [InlineData("web.webm", "video/webm")]
        [InlineData("itunes.m4v", "video/x-m4v")]
        [InlineData("mobile.3gp", "video/3gpp")]
        [InlineData("dashcam.ts", "video/mp2t")]
        public void Lookup_VideoFiles_ReturnsCorrectMimeType(string path, string expectedMime)
        {
            // Act
            var result = MimetypeLookup.Lookup(path);

            // Assert
            result.Should().Be(expectedMime);
        }

        #endregion

        #region Text and Data Types

        [Theory]
        [InlineData("readme.txt", "text/plain")]
        [InlineData("data.csv", "text/csv")]
        [InlineData("config.json", "application/json")]
        [InlineData("data.xml", "application/xml")]
        [InlineData("page.html", "text/html")]
        [InlineData("page.htm", "text/html")]
        [InlineData("document.rtf", "application/rtf")]
        public void Lookup_TextDataFiles_ReturnsCorrectMimeType(string path, string expectedMime)
        {
            // Act
            var result = MimetypeLookup.Lookup(path);

            // Assert
            result.Should().Be(expectedMime);
        }

        #endregion

        #region Archive Types

        [Theory]
        [InlineData("archive.zip", "application/zip")]
        [InlineData("compressed.gz", "application/gzip")]
        [InlineData("compressed.gzip", "application/gzip")]
        [InlineData("archive.tar", "application/x-tar")]
        [InlineData("archive.7z", "application/x-7z-compressed")]
        [InlineData("archive.rar", "application/vnd.rar")]
        public void Lookup_ArchiveFiles_ReturnsCorrectMimeType(string path, string expectedMime)
        {
            // Act
            var result = MimetypeLookup.Lookup(path);

            // Assert
            result.Should().Be(expectedMime);
        }

        #endregion

        #region Email Types

        [Theory]
        [InlineData("message.eml", "message/rfc822")]
        [InlineData("outlook.msg", "application/vnd.ms-outlook")]
        public void Lookup_EmailFiles_ReturnsCorrectMimeType(string path, string expectedMime)
        {
            // Act
            var result = MimetypeLookup.Lookup(path);

            // Assert
            result.Should().Be(expectedMime);
        }

        #endregion

        #region Insurance Industry Formats

        [Theory]
        [InlineData("data.al3", "application/x-al3")]
        [InlineData("index.tt2", "application/x-turbotag")]
        [InlineData("form.acord", "application/xml")]
        [InlineData("document.idx", "application/x-index")]
        public void Lookup_InsuranceFiles_ReturnsCorrectMimeType(string path, string expectedMime)
        {
            // Act
            var result = MimetypeLookup.Lookup(path);

            // Assert
            result.Should().Be(expectedMime);
        }

        #endregion

        #region EDI Formats

        [Theory]
        [InlineData("transaction.edi", "application/EDI-X12")]
        [InlineData("transaction.x12", "application/EDI-X12")]
        [InlineData("claim.837", "application/EDI-X12")]
        [InlineData("remittance.835", "application/EDI-X12")]
        [InlineData("enrollment.834", "application/EDI-X12")]
        [InlineData("inquiry.270", "application/EDI-X12")]
        [InlineData("response.271", "application/EDI-X12")]
        public void Lookup_EdiFiles_ReturnsCorrectMimeType(string path, string expectedMime)
        {
            // Act
            var result = MimetypeLookup.Lookup(path);

            // Assert
            result.Should().Be(expectedMime);
        }

        #endregion

        #region Financial Data Formats

        [Theory]
        [InlineData("bank.ofx", "application/x-ofx")]
        [InlineData("quicken.qfx", "application/x-qfx")]
        [InlineData("quickbooks.qbo", "application/x-qbo")]
        [InlineData("legacy.qif", "application/x-qif")]
        public void Lookup_FinancialFiles_ReturnsCorrectMimeType(string path, string expectedMime)
        {
            // Act
            var result = MimetypeLookup.Lookup(path);

            // Assert
            result.Should().Be(expectedMime);
        }

        #endregion

        #region Database Formats

        [Theory]
        [InlineData("database.mdb", "application/x-msaccess")]
        [InlineData("database.accdb", "application/x-msaccess")]
        [InlineData("legacy.dbf", "application/x-dbf")]
        public void Lookup_DatabaseFiles_ReturnsCorrectMimeType(string path, string expectedMime)
        {
            // Act
            var result = MimetypeLookup.Lookup(path);

            // Assert
            result.Should().Be(expectedMime);
        }

        #endregion

        #region Edge Cases

        [Fact]
        public void Lookup_NullPath_ReturnsNull()
        {
            // Act
            var result = MimetypeLookup.Lookup(null);

            // Assert
            result.Should().BeNull();
        }

        [Fact]
        public void Lookup_EmptyString_ReturnsNull()
        {
            // Act
            var result = MimetypeLookup.Lookup("");

            // Assert
            result.Should().BeNull();
        }

        [Fact]
        public void Lookup_UnknownExtension_ReturnsNull()
        {
            // Act
            var result = MimetypeLookup.Lookup("file.unknown123");

            // Assert
            result.Should().BeNull();
        }

        [Fact]
        public void Lookup_NoExtension_ReturnsNull()
        {
            // Act
            var result = MimetypeLookup.Lookup("filename");

            // Assert
            result.Should().BeNull();
        }

        [Fact]
        public void Lookup_BareExtension_ReturnsCorrectMimeType()
        {
            // Act
            var result = MimetypeLookup.Lookup(".pdf");

            // Assert
            result.Should().Be("application/pdf");
        }

        [Fact]
        public void Lookup_ExtensionWithoutDot_ReturnsCorrectMimeType()
        {
            // Act
            var result = MimetypeLookup.Lookup("pdf");

            // Assert
            result.Should().Be("application/pdf");
        }

        [Fact]
        public void Lookup_CaseInsensitive_ReturnsCorrectMimeType()
        {
            // Act
            var resultLower = MimetypeLookup.Lookup("file.pdf");
            var resultUpper = MimetypeLookup.Lookup("FILE.PDF");
            var resultMixed = MimetypeLookup.Lookup("File.PdF");

            // Assert
            resultLower.Should().Be("application/pdf");
            resultUpper.Should().Be("application/pdf");
            resultMixed.Should().Be("application/pdf");
        }

        [Fact]
        public void Lookup_PathWithSpaces_ReturnsCorrectMimeType()
        {
            // Act
            var result = MimetypeLookup.Lookup("/path/to/my file with spaces.pdf");

            // Assert
            result.Should().Be("application/pdf");
        }

        [Fact]
        public void Lookup_PathWithMultipleDots_ReturnsCorrectMimeType()
        {
            // Act
            var result = MimetypeLookup.Lookup("file.name.with.dots.pdf");

            // Assert
            result.Should().Be("application/pdf");
        }

        [Fact]
        public void Lookup_WindowsPath_ReturnsCorrectMimeType()
        {
            // Act
            var result = MimetypeLookup.Lookup(@"C:\Users\test\Documents\file.pdf");

            // Assert
            result.Should().Be("application/pdf");
        }

        [Fact]
        public void Lookup_UnixPath_ReturnsCorrectMimeType()
        {
            // Act
            var result = MimetypeLookup.Lookup("/home/user/documents/file.pdf");

            // Assert
            result.Should().Be("application/pdf");
        }

        #endregion
    }
}
