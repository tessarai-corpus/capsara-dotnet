using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace Capsara.SDK.Internal.Crypto
{
    /// <summary>
    /// Secure memory clearing and CSPRNG random byte generation.
    /// </summary>
    internal static class SecureMemory
    {
        /// <summary>
        /// Securely clear a byte array by zeroing its contents.
        /// Uses volatile writes to prevent JIT dead store elimination.
        /// </summary>
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static void Clear(byte[]? buffer)
        {
            if (buffer == null || buffer.Length == 0) return;

#if NET6_0_OR_GREATER
            CryptographicOperations.ZeroMemory(buffer);
#else
            // Volatile writes prevent JIT dead store elimination from skipping the clear
            for (int i = 0; i < buffer.Length; i++)
            {
                VolatileWrite(ref buffer[i], 0);
            }
#endif
        }

#if !NET6_0_OR_GREATER
        /// <summary>Volatile write to prevent JIT dead store elimination.</summary>
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static void VolatileWrite(ref byte location, byte value)
        {
            System.Threading.Volatile.Write(ref location, value);
        }
#endif

        /// <summary>Alias for Clear(byte[]).</summary>
        public static void ClearBuffer(byte[]? buffer) => Clear(buffer);

#if NET6_0_OR_GREATER
        /// <summary>Securely clear a span by zeroing its contents.</summary>
        public static void Clear(Span<byte> buffer)
        {
            if (buffer.IsEmpty) return;
            CryptographicOperations.ZeroMemory(buffer);
        }
#endif

        /// <summary>
        /// Securely clear a char array. Uses volatile writes to prevent JIT dead store elimination.
        /// </summary>
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static void Clear(char[]? buffer)
        {
            if (buffer == null || buffer.Length == 0) return;
#if NET6_0_OR_GREATER
            Array.Clear(buffer);
#else
            // Volatile writes prevent JIT dead store elimination
            for (int i = 0; i < buffer.Length; i++)
            {
                VolatileWriteChar(ref buffer[i], '\0');
            }
#endif
        }

#if !NET6_0_OR_GREATER
        /// <summary>
        /// Volatile write for char. Uses Thread.MemoryBarrier because Volatile.Write
        /// requires reference types in .NET Framework 4.x.
        /// </summary>
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static void VolatileWriteChar(ref char location, char value)
        {
            location = value;
            System.Threading.Thread.MemoryBarrier();
        }
#endif

        /// <summary>Generate cryptographically secure random bytes.</summary>
        public static byte[] GenerateRandomBytes(int length)
        {
            if (length <= 0)
                throw new ArgumentOutOfRangeException(nameof(length), "Length must be positive");

            byte[] bytes = new byte[length];

#if NET6_0_OR_GREATER
            RandomNumberGenerator.Fill(bytes);
#else
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }
#endif

            return bytes;
        }

        /// <summary>Generate a random AES-256 master key (32 bytes).</summary>
        public static byte[] GenerateMasterKey()
        {
            return GenerateRandomBytes(32);
        }

        /// <summary>Generate a random AES-GCM IV (12 bytes / 96 bits).</summary>
        public static byte[] GenerateIv()
        {
            return GenerateRandomBytes(12);
        }
    }

    /// <summary>
    /// Disposable wrapper that automatically zeroes sensitive byte arrays on dispose.
    /// </summary>
    internal sealed class SecureBuffer : IDisposable
    {
        private byte[] _buffer;
        private bool _disposed;

        /// <summary>Create a new secure buffer of specified size.</summary>
        public SecureBuffer(int size)
        {
            if (size <= 0)
                throw new ArgumentOutOfRangeException(nameof(size), "Size must be positive");
            _buffer = new byte[size];
        }

        /// <summary>
        /// Wrap existing data. Takes ownership -- caller should not modify after this.
        /// </summary>
        public SecureBuffer(byte[] data)
        {
            _buffer = data ?? throw new ArgumentNullException(nameof(data));
        }

        public byte[] Buffer
        {
            get
            {
                ThrowIfDisposed();
                return _buffer;
            }
        }

        public int Length
        {
            get
            {
                ThrowIfDisposed();
                return _buffer.Length;
            }
        }

        /// <summary>Copy the buffer. The copy is not secure -- caller must clear it.</summary>
        public byte[] ToArray()
        {
            ThrowIfDisposed();
            byte[] copy = new byte[_buffer.Length];
            Array.Copy(_buffer, copy, _buffer.Length);
            return copy;
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(SecureBuffer));
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                SecureMemory.Clear(_buffer);
                _buffer = Array.Empty<byte>();
                _disposed = true;
            }
        }
    }
}
