using System;

namespace Capsara.SDK.Internal.Crypto
{
    /// <summary>
    /// Creates platform-appropriate AES-GCM provider: native on .NET 6+, BouncyCastle on .NET Framework 4.8.
    /// </summary>
    internal static class AesGcmProviderFactory
    {
        /// <summary>
        /// Create a new AES-GCM provider for the current platform.
        /// </summary>
        public static IAesGcmProvider Create()
        {
#if NET6_0_OR_GREATER
            return new NativeAesGcmProvider();
#elif NETFRAMEWORK
            return new BouncyCastleAesGcmProvider();
#else
            throw new PlatformNotSupportedException(
                "AES-GCM is only supported on .NET 6+ or .NET Framework 4.8");
#endif
        }
    }
}
