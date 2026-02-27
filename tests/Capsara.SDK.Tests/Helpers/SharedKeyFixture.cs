using System;
using Capsara.SDK.Internal.Crypto;
using Xunit;

namespace Capsara.SDK.Tests.Helpers
{
    /// <summary>
    /// Shared RSA key pair fixture for test classes that need RSA keys.
    /// RSA-4096 key generation is expensive (~800ms per key), so we share
    /// pre-generated keys across multiple test classes to reduce test runtime.
    /// </summary>
    public class SharedKeyFixture : IDisposable
    {
        /// <summary>
        /// Primary key pair available for most tests.
        /// </summary>
        public GeneratedKeyPairResult PrimaryKeyPair { get; }

        /// <summary>
        /// Secondary key pair for tests that need multiple parties.
        /// </summary>
        public GeneratedKeyPairResult SecondaryKeyPair { get; }

        /// <summary>
        /// Third key pair for multi-party tests.
        /// </summary>
        public GeneratedKeyPairResult TertiaryKeyPair { get; }

        public SharedKeyFixture()
        {
            // Generate keys once per test collection (not per test class)
            PrimaryKeyPair = TestHelpers.GenerateTestKeyPair();
            SecondaryKeyPair = TestHelpers.GenerateTestKeyPair();
            TertiaryKeyPair = TestHelpers.GenerateTestKeyPair();
        }

        public void Dispose()
        {
            // No unmanaged resources to clean up
            GC.SuppressFinalize(this);
        }
    }

    /// <summary>
    /// Collection definition for tests that share RSA key pairs.
    /// All test classes in this collection will receive the same SharedKeyFixture instance.
    /// </summary>
    [CollectionDefinition("SharedKeys")]
    public class SharedKeyCollection : ICollectionFixture<SharedKeyFixture>
    {
        // This class has no code, and is never created. Its purpose is simply
        // to be the place to apply [CollectionDefinition] and all the
        // ICollectionFixture<> interfaces.
    }
}
