using System;
using System.Text;
using Capsara.SDK.Internal.Crypto;
using Xunit;

namespace Capsara.SDK.Tests.Crypto
{
    public class HashProviderTests
    {
        [Fact]
        public void ComputeHash_EmptyData_ReturnsValidHash()
        {
            var hash = HashProvider.ComputeHash(Array.Empty<byte>());

            // SHA-256 of empty string is known
            Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash);
        }

        [Fact]
        public void ComputeHash_KnownInput_ReturnsExpectedHash()
        {
            var data = Encoding.UTF8.GetBytes("hello");
            var hash = HashProvider.ComputeHash(data);

            // Known SHA-256 of "hello"
            Assert.Equal("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", hash);
        }

        [Fact]
        public void ComputeHash_ReturnsLowercaseHex()
        {
            var hash = HashProvider.ComputeHash(new byte[] { 0x01, 0x02, 0x03 });

            Assert.DoesNotMatch("[A-F]", hash); // No uppercase hex
            Assert.Matches("^[a-f0-9]{64}$", hash); // 64 lowercase hex chars
        }

        [Fact]
        public void ComputeHash_DifferentInputs_ProduceDifferentHashes()
        {
            var hash1 = HashProvider.ComputeHash(Encoding.UTF8.GetBytes("input1"));
            var hash2 = HashProvider.ComputeHash(Encoding.UTF8.GetBytes("input2"));

            Assert.NotEqual(hash1, hash2);
        }

        [Fact]
        public void ComputeHash_SameInput_ProducesSameHash()
        {
            var data = Encoding.UTF8.GetBytes("test data");
            var hash1 = HashProvider.ComputeHash(data);
            var hash2 = HashProvider.ComputeHash(data);

            Assert.Equal(hash1, hash2);
        }

        [Fact]
        public void ConstantTimeEquals_SameData_ReturnsTrue()
        {
            var data1 = new byte[] { 1, 2, 3, 4, 5 };
            var data2 = new byte[] { 1, 2, 3, 4, 5 };

            Assert.True(HashProvider.ConstantTimeEquals(data1, data2));
        }

        [Fact]
        public void ConstantTimeEquals_DifferentData_ReturnsFalse()
        {
            var data1 = new byte[] { 1, 2, 3, 4, 5 };
            var data2 = new byte[] { 1, 2, 3, 4, 6 };

            Assert.False(HashProvider.ConstantTimeEquals(data1, data2));
        }

        [Fact]
        public void ConstantTimeEquals_DifferentLengths_ReturnsFalse()
        {
            var data1 = new byte[] { 1, 2, 3 };
            var data2 = new byte[] { 1, 2, 3, 4 };

            Assert.False(HashProvider.ConstantTimeEquals(data1, data2));
        }

        [Fact]
        public void ConstantTimeEquals_EmptyArrays_ReturnsTrue()
        {
            Assert.True(HashProvider.ConstantTimeEquals(Array.Empty<byte>(), Array.Empty<byte>()));
        }
    }
}
