using System;

namespace RSACryptor
{
    public static class Util
    {
        public static unsafe void Memset(this byte[] buffer, int position, int length, byte val)
        {
            if (position >= length)
                throw new ArgumentException($"{nameof(position)} must be lower {nameof(length)}");

            fixed (byte* pBuffer = buffer)
            {
                byte* p = pBuffer + position;
                while (p < pBuffer + length)
                    *(p++) = val;
            }
        }
    }
}
