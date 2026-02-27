using System;
using System.Text;
using Capsara.SDK.Internal.Crypto;
using Xunit;

namespace Capsara.SDK.Tests.Crypto
{
    public class Base64UrlTests
    {
        [Fact]
        public void Encode_EmptyArray_ReturnsEmptyString()
        {
            var result = Base64Url.Encode(Array.Empty<byte>());
            Assert.Equal(string.Empty, result);
        }

        [Fact]
        public void Encode_SimpleData_ReturnsValidBase64Url()
        {
            var data = Encoding.UTF8.GetBytes("Hello, World!");
            var result = Base64Url.Encode(data);

            // Base64url should not contain + or / or =
            Assert.DoesNotContain("+", result);
            Assert.DoesNotContain("/", result);
            Assert.DoesNotContain("=", result);
        }

        [Fact]
        public void Decode_EmptyString_ReturnsEmptyArray()
        {
            var result = Base64Url.Decode(string.Empty);
            Assert.Empty(result);
        }

        [Fact]
        public void RoundTrip_SimpleData_PreservesData()
        {
            var original = Encoding.UTF8.GetBytes("Test data for round-trip");
            var encoded = Base64Url.Encode(original);
            var decoded = Base64Url.Decode(encoded);

            Assert.Equal(original, decoded);
        }

        [Fact]
        public void RoundTrip_BinaryData_PreservesData()
        {
            var original = new byte[] { 0x00, 0x01, 0xFF, 0xFE, 0x80, 0x7F };
            var encoded = Base64Url.Encode(original);
            var decoded = Base64Url.Decode(encoded);

            Assert.Equal(original, decoded);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(16)]
        [InlineData(32)]
        [InlineData(100)]
        public void RoundTrip_VariousLengths_PreservesData(int length)
        {
            var original = new byte[length];
            new Random(42).NextBytes(original);

            var encoded = Base64Url.Encode(original);
            var decoded = Base64Url.Decode(encoded);

            Assert.Equal(original, decoded);
        }

        [Fact]
        public void Decode_WithPadding_HandlesCorrectly()
        {
            // Base64url without padding (URL-safe format)
            var base64Url = "SGVsbG8";

            var decoded = Base64Url.Decode(base64Url);
            Assert.Equal("Hello", Encoding.UTF8.GetString(decoded));
        }
    }
}
