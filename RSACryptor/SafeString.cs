using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace RSACryptor
{
    [SecuritySafeCritical]
    public unsafe sealed class SafeString : IDisposable
    {
        [SecuritySafeCritical] private SecureString _secureString;

        public SafeString(string text) : this() => SetString(text);

        public SafeString(byte[] buffer) : this()
        {
            var text = Convert.ToBase64String(buffer);
            buffer.Memset(0, buffer.Length, 0);
            SetString(text);
        }

        public SafeString() => _secureString = new SecureString();

        [SecuritySafeCritical]
        public void SetString(string text)
        {
            _secureString.Clear();

            fixed (char* ch = text)
            {
                char* curCh = ch;
                while (*curCh != Char.MinValue)
                {
                    _secureString.AppendChar(*curCh);
                    *(curCh++) = Char.MinValue;
                }
            }
        }

        [SecuritySafeCritical]
        public ManagedSafeBuffer GetSafeBuffer()
        {
            ManagedSafeBuffer sb = null;
            byte* p = null;

            try
            {
                p = (byte*) Marshal.SecureStringToCoTaskMemAnsi(_secureString);
                sb = new ManagedSafeBuffer(p);
                return sb;
            }
            catch
            {
                sb.Dispose();
                sb = null;
                throw;
            }
            finally
            {
                if(p != null) Marshal.ZeroFreeCoTaskMemAnsi((IntPtr)p);
            }
        }

        public void Dispose()
        {
            _secureString.Dispose();
            _secureString = null;
        }
    }
}
