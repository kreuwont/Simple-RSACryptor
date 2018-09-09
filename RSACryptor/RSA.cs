using System;
using System.Collections.Generic;
using System.Security;
using System.Security.Cryptography;

namespace RSACryptor
{
    using Buff = System.Byte;
    using Length = System.Int32;
    [SecuritySafeCritical]
    public class RSACrypt : IDisposable
    {
        private const Length RecommendKeyLength = 2048;

        private int _keyLength;
        private byte[] _publicKey;
        private byte[] _privateKey;

        [SecuritySafeCritical]
        public RSACrypt() : this(RecommendKeyLength)
        {
        }

        [SecuritySafeCritical]
        public RSACrypt(Length keyLength)
        {
            _keyLength = keyLength;
            GenerateKey();
        }

        /// <summary>
        /// Генерирует новые приватный и публичный ключи
        /// </summary>
        [SecuritySafeCritical]
        public void GenerateKey()
        {
            ClearKey();
            using (var provider = new RSACryptoServiceProvider(_keyLength))
            {
                _publicKey = provider.ExportCspBlob(false);
                _privateKey = provider.ExportCspBlob(true);
            }
        }

        [SecuritySafeCritical]
        public Buff[] Encrypt(Buff[] buffer)
        {
            List<byte> retnBuff = new List<byte>();

            using (var rsaProvider = new RSACryptoServiceProvider(_keyLength))
            {
                rsaProvider.ImportCspBlob(_publicKey);

                int maxLength = (_keyLength - 384) / 8 + 37;
                int dataLength = buffer.Length;
                int iterations = dataLength == maxLength ? 0 : dataLength / maxLength;
                for (int i = 0; i <= iterations; i++)
                {
                    byte[] tempBytes = new byte[
                            (dataLength - maxLength * i > maxLength) ? maxLength :
                                                          dataLength - maxLength * i];
                    Buffer.BlockCopy(buffer, maxLength * i, tempBytes, 0,
                                      tempBytes.Length);

                    byte[] encryptBuffer = rsaProvider.Encrypt(tempBytes, false);

                    retnBuff.AddRange(encryptBuffer);
                }
            }

            return retnBuff.ToArray();
        }

        [SecuritySafeCritical]
        public Buff[] Decrypt(Buff[] buffer)
        {
            List<byte> retnBuff = new List<byte>();
            using (var rsaProvider = new RSACryptoServiceProvider(_keyLength))
            {
                try
                {
                    rsaProvider.ImportCspBlob(_privateKey);

                    int maxLength = _keyLength / 8;
                    int dataLength = buffer.Length;
                    int iterations = dataLength == maxLength ? 1 : dataLength / maxLength;
                    for (int i = 0; i < iterations; i++)
                    {
                        byte[] tempBytes = new byte[
                                (dataLength - maxLength * i > maxLength) ? maxLength :
                                                              dataLength - maxLength * i];
                        Buffer.BlockCopy(buffer, maxLength * i, tempBytes, 0,
                                          tempBytes.Length);

                        byte[] decryptedBuffer = rsaProvider.Decrypt(tempBytes, false);

                        retnBuff.AddRange(decryptedBuffer);
                    }
                }
                catch (CryptographicException)
                {
                    throw;
                }
            }

            return retnBuff.ToArray();
        }

        [SecuritySafeCritical]
        public Buff[] ExportKey(bool isPrivate)
        {
            if (isPrivate)
                return _privateKey;
            else
                return _publicKey;
        }

        [SecuritySafeCritical]
        public void ImportKey(Length keyLength, Buff[] key, bool isPrivate)
        {
            if (keyLength == 0 || keyLength % 2 != 0)
                throw new ArgumentException("Некорректный размер ключа");

            if (key == null)
                throw new ArgumentNullException($"{nameof(key)} не может быть равно null");

            _keyLength = keyLength;

            ClearKey();

            if (isPrivate)
            {
                _privateKey = new byte[key.Length];
                Array.Copy(key, 0, _privateKey, 0, key.Length);
            }
            else
            {
                _publicKey = new byte[key.Length];
                Array.Copy(key, 0, _publicKey, 0, key.Length);
            }
        }

        [SecuritySafeCritical]
        public Length ExportKeyLenght()
        {
            return _keyLength;
        }

        [SecuritySafeCritical]
        private void ClearKey()
        {
            if (_privateKey != null)
            {
                Array.Clear(_privateKey, 0, _privateKey.Length);
                _privateKey = null;
            }

            if (_publicKey != null)
            {
                Array.Clear(_publicKey, 0, _publicKey.Length);
                _publicKey = null;
            }
        }

        public void Dispose()
        {
            ClearKey();
        }
    }
}
