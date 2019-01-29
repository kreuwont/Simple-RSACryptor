using System;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace RSACryptor
{
    [SecuritySafeCritical]
    public unsafe sealed class ManagedSafeBuffer : IDisposable
    {
        private const int DefaultBufferSize = 64;

        [SecuritySafeCritical] private byte[] _safeBuffer = null;

        public ManagedSafeBuffer(byte* ptr)
        {
            CreateSafeBuffer(ptr);
        }

        public void Dispose()
        {
            ClearBuffer(_safeBuffer);
            _safeBuffer = null;
        }

        [SecuritySafeCritical]
        public byte[] GetBuffer() => _safeBuffer;

        [SecuritySafeCritical]
        private void CreateSafeBuffer(byte* ptr)
        {
            var curPos = 0;
            byte* p = ptr;

            var encodeBuffer = AllocateBuffer();
            while (*p != 0)
            {
                if (curPos >= encodeBuffer.Length) ReallocateBuffer(ref encodeBuffer);
                encodeBuffer[curPos++] = *(p++);
            }

            var encodeString = Encoding.ASCII.GetString(encodeBuffer, 0, (int)(p - ptr));
            ClearBuffer(encodeBuffer);
            _safeBuffer = Convert.FromBase64String(encodeString);
            DeleteString(ref encodeString);
        }

        [SecuritySafeCritical]
        private byte[] AllocateBuffer() => new byte[DefaultBufferSize];

        [SecuritySafeCritical]
        private void ReallocateBuffer(ref byte[] buffer)
        {
            try
            {
                int newSize = checked(buffer.Length * 2);
                var oldBuff = buffer;

                buffer = new byte[newSize];
                Buffer.BlockCopy(oldBuff, 0, buffer, 0, oldBuff.Length);

                ClearBuffer(oldBuff);
            }
            catch (OverflowException)
            {
                ClearBuffer(buffer);
                throw new InternalBufferOverflowException();
            }
        }

        [SecuritySafeCritical]
        private void ClearBuffer(byte[] buff) => buff.Memset(0, buff.Length, 0);

        [SecuritySafeCritical]
        private void DeleteString(ref string str)
        {
            fixed (char* p = str)
            {
                char* ch = p;
                while (*ch != Char.MinValue) *(ch++) = Char.MinValue;
            }

            str = null;
        }
    }
}
