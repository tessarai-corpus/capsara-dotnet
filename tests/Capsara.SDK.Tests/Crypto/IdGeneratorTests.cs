using System.Collections.Generic;
using System.Linq;
using Capsara.SDK.Internal.Crypto;
using Capsara.SDK.Internal.Utils;
using Xunit;

namespace Capsara.SDK.Tests.Crypto
{
    public class IdGeneratorTests
    {
        private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

        [Fact]
        public void Generate_DefaultLength_Returns21Characters()
        {
            var id = IdGenerator.Generate();
            Assert.Equal(21, id.Length);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(10)]
        [InlineData(21)]
        [InlineData(50)]
        [InlineData(100)]
        public void Generate_SpecifiedLength_ReturnsCorrectLength(int length)
        {
            var id = IdGenerator.Generate(length);
            Assert.Equal(length, id.Length);
        }

        [Fact]
        public void Generate_UsesOnlyValidAlphabetCharacters()
        {
            var id = IdGenerator.Generate(100);

            foreach (var c in id)
            {
                Assert.Contains(c, Alphabet);
            }
        }

        [Fact]
        public void Generate_ProducesUniqueIds()
        {
            const int count = 1000;
            var ids = new HashSet<string>();

            for (int i = 0; i < count; i++)
            {
                ids.Add(IdGenerator.Generate());
            }

            Assert.Equal(count, ids.Count);
        }

        [Fact]
        public void Generate_ProducesGoodDistribution()
        {
            // Generate many IDs and check character distribution
            const int sampleSize = 10000;
            var charCounts = new Dictionary<char, int>();

            for (int i = 0; i < sampleSize; i++)
            {
                var id = IdGenerator.Generate();
                foreach (var c in id)
                {
                    charCounts.TryGetValue(c, out var count);
                    charCounts[c] = count + 1;
                }
            }

            // All 64 alphabet characters should appear
            Assert.Equal(64, charCounts.Count);

            // Check that distribution is roughly uniform (within 50% of expected)
            var totalChars = sampleSize * 21;
            var expectedPerChar = totalChars / 64.0;

            foreach (var kvp in charCounts)
            {
                Assert.InRange(kvp.Value, expectedPerChar * 0.5, expectedPerChar * 1.5);
            }
        }

        [Fact]
        public void Generate_IsUrlSafe()
        {
            var id = IdGenerator.Generate(100);

            // URL-safe characters only
            Assert.DoesNotContain("+", id);
            Assert.DoesNotContain("/", id);
            Assert.DoesNotContain("=", id);
            Assert.DoesNotContain(" ", id);
            Assert.DoesNotContain("\n", id);
        }
    }
}
