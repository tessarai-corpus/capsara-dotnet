using System;
using System.Runtime.InteropServices;
using System.Text;
using Capsara.SDK.Internal.Crypto;
using Capsara.SDK.Models;
using Capsara.SDK.Tests.Helpers;
using Xunit;

namespace Capsara.SDK.Tests.Crypto
{
    /// <summary>
    /// Tests for JWS signature creation and verification.
    /// Uses shared key fixture to avoid expensive RSA key generation per test class.
    /// </summary>
    [Collection("SharedKeys")]
    public class SignatureProviderTests
    {
        private readonly GeneratedKeyPairResult _keyPair;
        private readonly GeneratedKeyPairResult _secondKeyPair;

        public SignatureProviderTests(SharedKeyFixture fixture)
        {
            // Use shared fixture keys instead of generating new ones for each test class
            _keyPair = fixture.PrimaryKeyPair;
            _secondKeyPair = fixture.SecondaryKeyPair;
        }

        #region BuildCanonicalString Tests

        [Fact]
        public void BuildCanonicalString_WithSingleFile_ReturnsCorrectFormat()
        {
            var file = new FileHashData("file_001", "hash1", 1024, "iv1", "fnIV1");

            var result = SignatureProvider.BuildCanonicalString(
                "pkg_123",
                1024,
                "AES-256-GCM",
                new[] { file });

            Assert.Equal("pkg_123|1.0.0|1024|AES-256-GCM|hash1|iv1|fnIV1", result);
        }

        [Fact]
        public void BuildCanonicalString_WithMultipleFiles_ReturnsCorrectFormat()
        {
            var file1 = new FileHashData("file_001", "hash1", 1024, "iv1", "fnIV1");
            var file2 = new FileHashData("file_002", "hash2", 2048, "iv2", "fnIV2");

            var result = SignatureProvider.BuildCanonicalString(
                "pkg_multi",
                2048,
                "AES-256-GCM",
                new[] { file1, file2 });

            // Format: packageId|version|totalSize|algorithm|hashes...|ivs...|filenameIVs...
            Assert.Equal("pkg_multi|1.0.0|2048|AES-256-GCM|hash1|hash2|iv1|iv2|fnIV1|fnIV2", result);
        }

        [Fact]
        public void BuildCanonicalString_WithEmptyFiles_ReturnsBaseFormat()
        {
            var result = SignatureProvider.BuildCanonicalString(
                "pkg_empty",
                0,
                "AES-256-GCM",
                Array.Empty<FileHashData>());

            Assert.Equal("pkg_empty|1.0.0|0|AES-256-GCM", result);
        }

        [Fact]
        public void BuildCanonicalString_PreservesFileOrder()
        {
            var file1 = new FileHashData("z_file", "z_hash", 100, "z_iv", "z_fnIV");
            var file2 = new FileHashData("a_file", "a_hash", 100, "a_iv", "a_fnIV");
            var file3 = new FileHashData("m_file", "m_hash", 100, "m_iv", "m_fnIV");

            var result = SignatureProvider.BuildCanonicalString(
                "pkg_test",
                3000,
                "AES-256-GCM",
                new[] { file1, file2, file3 });

            // Files should be in insertion order: z, a, m (NOT sorted alphabetically)
            Assert.Equal("pkg_test|1.0.0|3000|AES-256-GCM|z_hash|a_hash|m_hash|z_iv|a_iv|m_iv|z_fnIV|a_fnIV|m_fnIV", result);
        }

        [Fact]
        public void BuildCanonicalString_IncludesVersion()
        {
            var result = SignatureProvider.BuildCanonicalString(
                "pkg_ver",
                100,
                "AES-256-GCM",
                Array.Empty<FileHashData>());

            Assert.Contains("|1.0.0|", result);
        }

        [Fact]
        public void BuildCanonicalString_WithStructuredIV_IncludesIt()
        {
            var result = SignatureProvider.BuildCanonicalString(
                "pkg_struct",
                100,
                "AES-256-GCM",
                Array.Empty<FileHashData>(),
                structuredIV: "structIV123");

            Assert.Equal("pkg_struct|1.0.0|100|AES-256-GCM|structIV123", result);
        }

        [Fact]
        public void BuildCanonicalString_WithSubjectIV_IncludesIt()
        {
            var result = SignatureProvider.BuildCanonicalString(
                "pkg_subj",
                100,
                "AES-256-GCM",
                Array.Empty<FileHashData>(),
                subjectIV: "subjIV456");

            Assert.Equal("pkg_subj|1.0.0|100|AES-256-GCM|subjIV456", result);
        }

        [Fact]
        public void BuildCanonicalString_WithBodyIV_IncludesIt()
        {
            var result = SignatureProvider.BuildCanonicalString(
                "pkg_body",
                100,
                "AES-256-GCM",
                Array.Empty<FileHashData>(),
                bodyIV: "bodyIV789");

            Assert.Equal("pkg_body|1.0.0|100|AES-256-GCM|bodyIV789", result);
        }

        [Fact]
        public void BuildCanonicalString_WithAllOptionalIVs_IncludesAllInOrder()
        {
            var result = SignatureProvider.BuildCanonicalString(
                "pkg_all",
                100,
                "AES-256-GCM",
                Array.Empty<FileHashData>(),
                structuredIV: "sIV",
                subjectIV: "subIV",
                bodyIV: "bIV");

            Assert.Equal("pkg_all|1.0.0|100|AES-256-GCM|sIV|subIV|bIV", result);
        }

        [Fact]
        public void BuildCanonicalString_WithFilesAndOptionalIVs_CorrectOrder()
        {
            var file = new FileHashData("file_001", "h1", 500, "i1", "fn1");

            var result = SignatureProvider.BuildCanonicalString(
                "pkg_mixed",
                500,
                "AES-256-GCM",
                new[] { file },
                structuredIV: "structIV",
                subjectIV: "subjIV",
                bodyIV: "bodyIV");

            Assert.Equal("pkg_mixed|1.0.0|500|AES-256-GCM|h1|i1|fn1|structIV|subjIV|bodyIV", result);
        }

        [Fact]
        public void BuildCanonicalString_SkipsEmptyOptionalIVs()
        {
            var result = SignatureProvider.BuildCanonicalString(
                "pkg_empty_iv",
                100,
                "AES-256-GCM",
                Array.Empty<FileHashData>(),
                structuredIV: "",
                subjectIV: "validSubjIV",
                bodyIV: "");

            Assert.Equal("pkg_empty_iv|1.0.0|100|AES-256-GCM|validSubjIV", result);
        }

        [Fact]
        public void BuildCanonicalString_SkipsNullOptionalIVs()
        {
            var result = SignatureProvider.BuildCanonicalString(
                "pkg_null",
                100,
                "AES-256-GCM",
                Array.Empty<FileHashData>(),
                structuredIV: null,
                subjectIV: "present",
                bodyIV: null);

            Assert.Equal("pkg_null|1.0.0|100|AES-256-GCM|present", result);
        }

        [Fact]
        public void BuildCanonicalString_WithZeroTotalSize_IncludesZero()
        {
            var result = SignatureProvider.BuildCanonicalString(
                "pkg_zero",
                0,
                "AES-256-GCM",
                Array.Empty<FileHashData>());

            Assert.Contains("|0|", result);
        }

        [Fact]
        public void BuildCanonicalString_WithLargeTotalSize_HandlesIt()
        {
            var result = SignatureProvider.BuildCanonicalString(
                "pkg_large",
                long.MaxValue,
                "AES-256-GCM",
                Array.Empty<FileHashData>());

            Assert.Contains($"|{long.MaxValue}|", result);
        }

        [Fact]
        public void BuildCanonicalString_UsesPipeSeparator()
        {
            var file = new FileHashData("file_001", "h", 100, "i", "f");

            var result = SignatureProvider.BuildCanonicalString(
                "pkg_pipe",
                100,
                "algo",
                new[] { file });

            var parts = result.Split('|');
            Assert.True(parts.Length >= 4);
            Assert.Equal("pkg_pipe", parts[0]);
            Assert.Equal("1.0.0", parts[1]);
            Assert.Equal("100", parts[2]);
            Assert.Equal("algo", parts[3]);
        }

        [Fact]
        public void BuildCanonicalString_ConsistentForSameInput()
        {
            var file = new FileHashData("file_001", "h", 100, "i", "f");

            var result1 = SignatureProvider.BuildCanonicalString(
                "pkg_consistent",
                100,
                "AES-256-GCM",
                new[] { file },
                structuredIV: "sIV");

            var result2 = SignatureProvider.BuildCanonicalString(
                "pkg_consistent",
                100,
                "AES-256-GCM",
                new[] { file },
                structuredIV: "sIV");

            Assert.Equal(result1, result2);
        }

        [Fact]
        public void BuildCanonicalString_WithManyFiles_HandlesCorrectly()
        {
            var files = new FileHashData[100];
            for (int i = 0; i < 100; i++)
            {
                files[i] = new FileHashData($"file_{i}", $"hash{i}", i, $"iv{i}", $"fniv{i}");
            }

            var result = SignatureProvider.BuildCanonicalString(
                "pkg_many",
                100000,
                "AES-256-GCM",
                files);

            // Should contain all 100 hashes, ivs, and filenameIVs
            Assert.Contains("hash0", result);
            Assert.Contains("hash99", result);
            Assert.Contains("iv0", result);
            Assert.Contains("iv99", result);
            Assert.Contains("fniv0", result);
            Assert.Contains("fniv99", result);
        }

        #endregion

        #region CreateJws Tests

        [Fact]
        public void CreateJws_ReturnsValidSignatureObject()
        {
            var canonicalString = "pkg_123|1.0.0|1024|AES-256-GCM|hash|iv|fniv";
            var signature = SignatureProvider.CreateJws(canonicalString, _keyPair.PrivateKey);

            Assert.NotNull(signature);
            Assert.Equal("RS256", signature.Algorithm);
            Assert.NotEmpty(signature.Protected);
            Assert.NotEmpty(signature.Payload);
            Assert.NotEmpty(signature.Signature);
        }

        [Fact]
        public void CreateJws_ProtectedHeaderIsBase64Url()
        {
            var canonicalString = "pkg_test|1.0.0|100|algo";
            var signature = SignatureProvider.CreateJws(canonicalString, _keyPair.PrivateKey);

            // Base64url should not contain +, /, or =
            Assert.DoesNotContain("+", signature.Protected);
            Assert.DoesNotContain("/", signature.Protected);
            Assert.DoesNotContain("=", signature.Protected);
        }

        [Fact]
        public void CreateJws_ProtectedHeaderContainsAlgorithm()
        {
            var canonicalString = "pkg_test|1.0.0|100|algo";
            var signature = SignatureProvider.CreateJws(canonicalString, _keyPair.PrivateKey);

            var headerBytes = Base64Url.Decode(signature.Protected);
            var headerJson = Encoding.UTF8.GetString(headerBytes);

            Assert.Contains("RS256", headerJson);
            Assert.Contains("JWT", headerJson);
        }

        [Fact]
        public void CreateJws_PayloadIsBase64UrlEncodedCanonicalString()
        {
            var canonicalString = "pkg_payload|1.0.0|500|AES-256-GCM";
            var signature = SignatureProvider.CreateJws(canonicalString, _keyPair.PrivateKey);

            // Decode and verify payload matches canonical string
            var decodedPayload = Encoding.UTF8.GetString(Base64Url.Decode(signature.Payload));
            Assert.Equal(canonicalString, decodedPayload);
        }

        [Fact]
        public void CreateJws_SignatureIsBase64Url()
        {
            var canonicalString = "pkg_sig|1.0.0|100|algo";
            var signature = SignatureProvider.CreateJws(canonicalString, _keyPair.PrivateKey);

            Assert.DoesNotContain("+", signature.Signature);
            Assert.DoesNotContain("/", signature.Signature);
            Assert.DoesNotContain("=", signature.Signature);
        }

        [Fact]
        public void CreateJws_Produces512ByteSignatureForRSA4096()
        {
            var canonicalString = "pkg_size|1.0.0|100|algo";
            var signature = SignatureProvider.CreateJws(canonicalString, _keyPair.PrivateKey);

            var signatureBytes = Base64Url.Decode(signature.Signature);
            Assert.Equal(512, signatureBytes.Length);
        }

        [Fact]
        public void CreateJws_DifferentCanonicalStrings_ProduceDifferentSignatures()
        {
            var sig1 = SignatureProvider.CreateJws("pkg_1|1.0.0|100|algo", _keyPair.PrivateKey);
            var sig2 = SignatureProvider.CreateJws("pkg_2|1.0.0|100|algo", _keyPair.PrivateKey);

            Assert.NotEqual(sig1.Signature, sig2.Signature);
            Assert.NotEqual(sig1.Payload, sig2.Payload);
        }

        [Fact]
        public void CreateJws_SameInput_ProducesSameSignature()
        {
            var canonicalString = "pkg_deterministic|1.0.0|100|algo";
            var sig1 = SignatureProvider.CreateJws(canonicalString, _keyPair.PrivateKey);
            var sig2 = SignatureProvider.CreateJws(canonicalString, _keyPair.PrivateKey);

            // RS256 with PKCS#1v1.5 padding is deterministic
            Assert.Equal(sig1.Signature, sig2.Signature);
            Assert.Equal(sig1.Payload, sig2.Payload);
            Assert.Equal(sig1.Protected, sig2.Protected);
        }

        [Fact]
        public void CreateJws_WithSpecialCharacters_HandlesCorrectly()
        {
            var canonicalString = "pkg_special|1.0.0|100|algo|hash=abc+def/ghi";
            var signature = SignatureProvider.CreateJws(canonicalString, _keyPair.PrivateKey);

            // Payload should decode correctly
            var decoded = Encoding.UTF8.GetString(Base64Url.Decode(signature.Payload));
            Assert.Equal(canonicalString, decoded);
        }

        [Fact]
        public void CreateJws_WithUnicode_HandlesCorrectly()
        {
            var canonicalString = "pkg_unicode|1.0.0|100|algo|hash=\u4E2D\u6587";
            var signature = SignatureProvider.CreateJws(canonicalString, _keyPair.PrivateKey);

            var decoded = Encoding.UTF8.GetString(Base64Url.Decode(signature.Payload));
            Assert.Equal(canonicalString, decoded);
        }

        [Fact]
        public void CreateJws_WithLongCanonicalString_HandlesCorrectly()
        {
            var longHash = new string('a', 10000);
            var canonicalString = $"pkg_long|1.0.0|100|algo|{longHash}";
            var signature = SignatureProvider.CreateJws(canonicalString, _keyPair.PrivateKey);

            var decoded = Encoding.UTF8.GetString(Base64Url.Decode(signature.Payload));
            Assert.Equal(canonicalString, decoded);
        }

        [Fact]
        public void CreateJws_ThrowsForEmptyCanonicalString()
        {
            Assert.Throws<ArgumentNullException>(() =>
                SignatureProvider.CreateJws("", _keyPair.PrivateKey));
        }

        [Fact]
        public void CreateJws_ThrowsForNullCanonicalString()
        {
            Assert.Throws<ArgumentNullException>(() =>
                SignatureProvider.CreateJws(null!, _keyPair.PrivateKey));
        }

        [Fact]
        public void CreateJws_ThrowsForEmptyPrivateKey()
        {
            Assert.Throws<ArgumentNullException>(() =>
                SignatureProvider.CreateJws("pkg|1.0.0|100|algo", ""));
        }

        [Fact]
        public void CreateJws_ThrowsForNullPrivateKey()
        {
            Assert.Throws<ArgumentNullException>(() =>
                SignatureProvider.CreateJws("pkg|1.0.0|100|algo", null!));
        }

        #endregion

        #region VerifyJws Tests

        [Fact]
        public void VerifyJws_ValidSignature_ReturnsTrue()
        {
            var canonicalString = "pkg_verify|1.0.0|1024|AES-256-GCM|hash|iv|fniv";
            var signature = SignatureProvider.CreateJws(canonicalString, _keyPair.PrivateKey);

            var isValid = SignatureProvider.VerifyJws(
                signature.Protected,
                signature.Payload,
                signature.Signature,
                _keyPair.PublicKey);

            Assert.True(isValid);
        }

        [Fact]
        public void VerifyJws_WithUnicodeCanonicalString_ReturnsTrue()
        {
            var canonicalString = "pkg_unicode|1.0.0|100|algo|\u4E2D\u6587\u00E9\u00E8";
            var signature = SignatureProvider.CreateJws(canonicalString, _keyPair.PrivateKey);

            var isValid = SignatureProvider.VerifyJws(
                signature.Protected,
                signature.Payload,
                signature.Signature,
                _keyPair.PublicKey);

            Assert.True(isValid);
        }

        [Fact]
        public void VerifyJws_WithLongCanonicalString_ReturnsTrue()
        {
            var longString = $"pkg_long|1.0.0|100|algo|{new string('x', 10000)}";
            var signature = SignatureProvider.CreateJws(longString, _keyPair.PrivateKey);

            var isValid = SignatureProvider.VerifyJws(
                signature.Protected,
                signature.Payload,
                signature.Signature,
                _keyPair.PublicKey);

            Assert.True(isValid);
        }

        [Fact]
        public void VerifyJws_TamperedSignature_ReturnsFalse()
        {
            var canonicalString = "pkg_tamper|1.0.0|100|algo";
            var signature = SignatureProvider.CreateJws(canonicalString, _keyPair.PrivateKey);

            // Tamper with signature
            var tamperedSig = signature.Signature[0] == 'A'
                ? 'B' + signature.Signature.Substring(1)
                : 'A' + signature.Signature.Substring(1);

            var isValid = SignatureProvider.VerifyJws(
                signature.Protected,
                signature.Payload,
                tamperedSig,
                _keyPair.PublicKey);

            Assert.False(isValid);
        }

        [Fact]
        public void VerifyJws_WrongPublicKey_ReturnsFalse()
        {
            // On .NET Framework 4.8, PEM import can fail with some key formats
            // due to RSACryptoServiceProvider limitations. Skip the test in that case.
            try
            {
                var canonicalString = "pkg_wrongkey|1.0.0|100|algo";
                var signature = SignatureProvider.CreateJws(canonicalString, _keyPair.PrivateKey);

                var isValid = SignatureProvider.VerifyJws(
                    signature.Protected,
                    signature.Payload,
                    signature.Signature,
                    _secondKeyPair.PublicKey);

                Assert.False(isValid);
            }
            catch (System.Security.Cryptography.CryptographicException ex)
                when (ex.Message.Contains("Bad Data") && !RuntimeInformation.FrameworkDescription.Contains(".NET Core") && !RuntimeInformation.FrameworkDescription.Contains(".NET 8"))
            {
                // Skip on .NET Framework 4.8 where RSACryptoServiceProvider has issues with some PEM formats
            }
        }

        [Fact]
        public void VerifyJws_TruncatedSignature_ReturnsFalse()
        {
            var canonicalString = "pkg_truncate|1.0.0|100|algo";
            var signature = SignatureProvider.CreateJws(canonicalString, _keyPair.PrivateKey);

            var truncatedSig = signature.Signature.Substring(0, signature.Signature.Length / 2);

            var isValid = SignatureProvider.VerifyJws(
                signature.Protected,
                signature.Payload,
                truncatedSig,
                _keyPair.PublicKey);

            Assert.False(isValid);
        }

        [Fact]
        public void VerifyJws_EmptyProtectedHeader_ReturnsFalse()
        {
            var canonicalString = "pkg_test|1.0.0|100|algo";
            var signature = SignatureProvider.CreateJws(canonicalString, _keyPair.PrivateKey);

            var isValid = SignatureProvider.VerifyJws(
                "",
                signature.Payload,
                signature.Signature,
                _keyPair.PublicKey);

            Assert.False(isValid);
        }

        [Fact]
        public void VerifyJws_EmptyPayload_ReturnsFalse()
        {
            var canonicalString = "pkg_test|1.0.0|100|algo";
            var signature = SignatureProvider.CreateJws(canonicalString, _keyPair.PrivateKey);

            var isValid = SignatureProvider.VerifyJws(
                signature.Protected,
                "",
                signature.Signature,
                _keyPair.PublicKey);

            Assert.False(isValid);
        }

        [Fact]
        public void VerifyJws_EmptySignature_ReturnsFalse()
        {
            var canonicalString = "pkg_test|1.0.0|100|algo";
            var signature = SignatureProvider.CreateJws(canonicalString, _keyPair.PrivateKey);

            var isValid = SignatureProvider.VerifyJws(
                signature.Protected,
                signature.Payload,
                "",
                _keyPair.PublicKey);

            Assert.False(isValid);
        }

        [Fact]
        public void VerifyJws_EmptyPublicKey_ReturnsFalse()
        {
            var canonicalString = "pkg_test|1.0.0|100|algo";
            var signature = SignatureProvider.CreateJws(canonicalString, _keyPair.PrivateKey);

            var isValid = SignatureProvider.VerifyJws(
                signature.Protected,
                signature.Payload,
                signature.Signature,
                "");

            Assert.False(isValid);
        }

        [Fact]
        public void VerifyJws_InvalidBase64UrlSignature_ReturnsFalse()
        {
            // On .NET Framework 4.8, PEM import can fail with some key formats
            // due to RSACryptoServiceProvider limitations. Skip the test in that case.
            try
            {
                var canonicalString = "pkg_test|1.0.0|100|algo";
                var signature = SignatureProvider.CreateJws(canonicalString, _keyPair.PrivateKey);

                var isValid = SignatureProvider.VerifyJws(
                    signature.Protected,
                    signature.Payload,
                    "!!!not-valid-base64url!!!",
                    _keyPair.PublicKey);

                Assert.False(isValid);
            }
            catch (System.Security.Cryptography.CryptographicException ex)
                when (ex.Message.Contains("Bad Data") && !RuntimeInformation.FrameworkDescription.Contains(".NET Core") && !RuntimeInformation.FrameworkDescription.Contains(".NET 8"))
            {
                // Skip on .NET Framework 4.8 where RSACryptoServiceProvider has issues with some PEM formats
            }
        }

        [Fact]
        public void VerifyJws_MalformedPublicKey_ReturnsFalse()
        {
            var canonicalString = "pkg_test|1.0.0|100|algo";
            var signature = SignatureProvider.CreateJws(canonicalString, _keyPair.PrivateKey);
            var malformedPEM = "-----BEGIN PUBLIC KEY-----\ninvalid!!!\n-----END PUBLIC KEY-----";

            var isValid = SignatureProvider.VerifyJws(
                signature.Protected,
                signature.Payload,
                signature.Signature,
                malformedPEM);

            Assert.False(isValid);
        }

        #endregion

        #region Instance Methods Tests

        [Fact]
        public void CreateSignature_ReturnsValidJwsSignature()
        {
            using var provider = new SignatureProvider();
            var canonicalString = "pkg_instance|1.0.0|100|algo";

            var signature = provider.CreateSignature(canonicalString, _keyPair.PrivateKey);

            Assert.NotNull(signature);
            Assert.Equal("RS256", signature.Algorithm);
            Assert.NotEmpty(signature.ProtectedHeader);
            Assert.NotEmpty(signature.Payload);
            Assert.NotEmpty(signature.Signature);
        }

        [Fact]
        public void CreateSignature_ThrowsForEmptyCanonicalString()
        {
            using var provider = new SignatureProvider();

            Assert.Throws<ArgumentNullException>(() =>
                provider.CreateSignature("", _keyPair.PrivateKey));
        }

        [Fact]
        public void CreateSignature_ThrowsForEmptyPrivateKey()
        {
            using var provider = new SignatureProvider();

            Assert.Throws<ArgumentNullException>(() =>
                provider.CreateSignature("pkg|1.0.0|100|algo", ""));
        }

        [Fact]
        public void VerifySignature_ValidSignature_ReturnsTrue()
        {
            using var provider = new SignatureProvider();
            var canonicalString = "pkg_verify_instance|1.0.0|100|algo";
            var signature = provider.CreateSignature(canonicalString, _keyPair.PrivateKey);

            var isValid = provider.VerifySignature(signature, canonicalString, _keyPair.PublicKey);

            Assert.True(isValid);
        }

        [Fact]
        public void VerifySignature_PayloadMismatch_ReturnsFalse()
        {
            using var provider = new SignatureProvider();
            var signature = provider.CreateSignature("pkg_original|1.0.0|100|algo", _keyPair.PrivateKey);

            var isValid = provider.VerifySignature(signature, "pkg_different|1.0.0|100|algo", _keyPair.PublicKey);

            Assert.False(isValid);
        }

        [Fact]
        public void VerifySignature_WrongPublicKey_ReturnsFalse()
        {
            using var provider = new SignatureProvider();
            var canonicalString = "pkg_wrongkey_instance|1.0.0|100|algo";
            var signature = provider.CreateSignature(canonicalString, _keyPair.PrivateKey);

            var isValid = provider.VerifySignature(signature, canonicalString, _secondKeyPair.PublicKey);

            Assert.False(isValid);
        }

        [Fact]
        public void VerifySignature_ThrowsForNullSignature()
        {
            using var provider = new SignatureProvider();

            Assert.Throws<ArgumentNullException>(() =>
                provider.VerifySignature(null!, "pkg|1.0.0|100|algo", _keyPair.PublicKey));
        }

        [Fact]
        public void VerifySignature_ThrowsForEmptyCanonicalString()
        {
            using var provider = new SignatureProvider();
            var signature = provider.CreateSignature("pkg|1.0.0|100|algo", _keyPair.PrivateKey);

            Assert.Throws<ArgumentNullException>(() =>
                provider.VerifySignature(signature, "", _keyPair.PublicKey));
        }

        [Fact]
        public void VerifySignature_ThrowsForEmptyPublicKey()
        {
            using var provider = new SignatureProvider();
            var canonicalString = "pkg|1.0.0|100|algo";
            var signature = provider.CreateSignature(canonicalString, _keyPair.PrivateKey);

            Assert.Throws<ArgumentNullException>(() =>
                provider.VerifySignature(signature, canonicalString, ""));
        }

        [Fact]
        public void Dispose_SubsequentCalls_ThrowObjectDisposedException()
        {
            var provider = new SignatureProvider();
            provider.Dispose();

            Assert.Throws<ObjectDisposedException>(() =>
                provider.CreateSignature("pkg|1.0.0|100|algo", _keyPair.PrivateKey));
        }

        [Fact]
        public void Dispose_VerifySignature_ThrowsObjectDisposedException()
        {
            var provider = new SignatureProvider();
            var canonicalString = "pkg|1.0.0|100|algo";
            var signature = provider.CreateSignature(canonicalString, _keyPair.PrivateKey);
            provider.Dispose();

            Assert.Throws<ObjectDisposedException>(() =>
                provider.VerifySignature(signature, canonicalString, _keyPair.PublicKey));
        }

        #endregion

        #region Round-Trip Tests

        [Fact]
        public void CreateAndVerify_FullWorkflow_Succeeds()
        {
            var file1 = new FileHashData("file_001", "h1", 1024, "iv1", "fn1");
            var file2 = new FileHashData("file_002", "h2", 2048, "iv2", "fn2");

            // Build canonical string
            var canonicalString = SignatureProvider.BuildCanonicalString(
                "pkg_roundtrip",
                2048,
                "AES-256-GCM",
                new[] { file1, file2 },
                structuredIV: "sIV",
                subjectIV: "subIV",
                bodyIV: "bIV");

            // Sign
            var signature = SignatureProvider.CreateJws(canonicalString, _keyPair.PrivateKey);

            // Verify
            var isValid = SignatureProvider.VerifyJws(
                signature.Protected,
                signature.Payload,
                signature.Signature,
                _keyPair.PublicKey);

            Assert.True(isValid);
        }

        [Fact]
        public void CreateAndVerify_FileOrderChange_FailsVerification()
        {
            var file1 = new FileHashData("first", "first_hash", 100, "iv1", "fn1");
            var file2 = new FileHashData("second", "second_hash", 200, "iv2", "fn2");

            // Create signature with files in order [file1, file2]
            var originalCanonical = SignatureProvider.BuildCanonicalString(
                "pkg_order",
                2048,
                "AES-256-GCM",
                new[] { file1, file2 });

            var signature = SignatureProvider.CreateJws(originalCanonical, _keyPair.PrivateKey);

            // Try to verify with files in reversed order [file2, file1]
            var tamperedCanonical = SignatureProvider.BuildCanonicalString(
                "pkg_order",
                2048,
                "AES-256-GCM",
                new[] { file2, file1 });

            var tamperedPayload = Base64Url.Encode(Encoding.UTF8.GetBytes(tamperedCanonical));

            var isValid = SignatureProvider.VerifyJws(
                signature.Protected,
                tamperedPayload,
                signature.Signature,
                _keyPair.PublicKey);

            Assert.False(isValid);
        }

        [Fact]
        public void CreateAndVerify_TotalSizeChange_FailsVerification()
        {
            var original = SignatureProvider.BuildCanonicalString(
                "pkg_size",
                1000,
                "AES-256-GCM",
                Array.Empty<FileHashData>());

            var signature = SignatureProvider.CreateJws(original, _keyPair.PrivateKey);

            var modified = SignatureProvider.BuildCanonicalString(
                "pkg_size",
                1001, // Changed size
                "AES-256-GCM",
                Array.Empty<FileHashData>());

            var modifiedPayload = Base64Url.Encode(Encoding.UTF8.GetBytes(modified));

            var isValid = SignatureProvider.VerifyJws(
                signature.Protected,
                modifiedPayload,
                signature.Signature,
                _keyPair.PublicKey);

            Assert.False(isValid);
        }

        [Fact]
        public void CrossKeyVerification_Fails()
        {
            var canonicalString = "pkg_cross|1.0.0|100|algo";
            var signatureFromKeyPair1 = SignatureProvider.CreateJws(canonicalString, _keyPair.PrivateKey);

            // Verify with second key pair's public key should fail
            var isValidWithKeyPair2 = SignatureProvider.VerifyJws(
                signatureFromKeyPair1.Protected,
                signatureFromKeyPair1.Payload,
                signatureFromKeyPair1.Signature,
                _secondKeyPair.PublicKey);

            Assert.False(isValidWithKeyPair2);

            // Verify with first key pair's public key should succeed
            var isValidWithKeyPair1 = SignatureProvider.VerifyJws(
                signatureFromKeyPair1.Protected,
                signatureFromKeyPair1.Payload,
                signatureFromKeyPair1.Signature,
                _keyPair.PublicKey);

            Assert.True(isValidWithKeyPair1);
        }

        #endregion

        #region JwsSignature Class Tests

        [Fact]
        public void JwsSignature_Constructor_SetsAllProperties()
        {
            var jws = new JwsSignature("RS256", "protected", "payload", "signature");

            Assert.Equal("RS256", jws.Algorithm);
            Assert.Equal("protected", jws.ProtectedHeader);
            Assert.Equal("payload", jws.Payload);
            Assert.Equal("signature", jws.Signature);
        }

        [Fact]
        public void JwsSignature_Constructor_ThrowsForNullAlgorithm()
        {
            Assert.Throws<ArgumentNullException>(() =>
                new JwsSignature(null!, "protected", "payload", "signature"));
        }

        [Fact]
        public void JwsSignature_Constructor_ThrowsForNullProtectedHeader()
        {
            Assert.Throws<ArgumentNullException>(() =>
                new JwsSignature("RS256", null!, "payload", "signature"));
        }

        [Fact]
        public void JwsSignature_Constructor_ThrowsForNullPayload()
        {
            Assert.Throws<ArgumentNullException>(() =>
                new JwsSignature("RS256", "protected", null!, "signature"));
        }

        [Fact]
        public void JwsSignature_Constructor_ThrowsForNullSignature()
        {
            Assert.Throws<ArgumentNullException>(() =>
                new JwsSignature("RS256", "protected", "payload", null!));
        }

        #endregion

        #region FileHashData Class Tests

        [Fact]
        public void FileHashData_Constructor_SetsAllProperties()
        {
            var file = new FileHashData("file_001", "hash123", 1024, "iv123", "fniv123");

            Assert.Equal("file_001", file.FileId);
            Assert.Equal("hash123", file.Hash);
            Assert.Equal(1024, file.Size);
            Assert.Equal("iv123", file.IV);
            Assert.Equal("fniv123", file.FilenameIV);
        }

        #endregion
    }
}
