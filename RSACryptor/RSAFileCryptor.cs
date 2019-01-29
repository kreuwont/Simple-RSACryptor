using System;
using System.IO;
using System.Threading.Tasks;

namespace RSACryptor
{
    public enum Opcode : byte
    {
        KeyLength = 0,
        PublicKey = 1,
        PrivateKey = 2
    }

    [Flags]
    public enum DataTypeFlag
    {
        PublicKey = 1,
        PrivateKey = 2
    }

    public static class RSAFileCryptor
    {
        public static async Task EncryptFileAsync(string filePath, string saveKeyDataPath, DataTypeFlag saveInfoFlag)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException("File not found");

            using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.ReadWrite, FileShare.Read))
            {
                using (var provider = new RSACrypt())
                {
                    byte[] fileBuffer = new byte[stream.Length];
                    await stream.ReadAsync(fileBuffer, 0, fileBuffer.Length);

                    var encryptBuffer = provider.Encrypt(fileBuffer);
                    stream.Seek(0, SeekOrigin.Begin);
                    stream.SetLength(encryptBuffer.Length);
                    await stream.WriteAsync(encryptBuffer, 0, encryptBuffer.Length);

                    Array.Clear(fileBuffer, 0, fileBuffer.Length);
                    SaveKeyData(provider, saveKeyDataPath, saveInfoFlag);
                }
            }
        }

        public static async Task DecryptFileAsync(string filePath, string keyDataPath)
        {
            using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                using (var provider = new RSACrypt())
                {
                    (int keyLenght, byte[] publicKey, byte[] privateKey) = ReadKeyData(provider, keyDataPath, DataTypeFlag.PrivateKey);
                    provider.ImportKey(keyLenght, privateKey, true);

                    byte[] fileBuffer = new byte[stream.Length];
                    await stream.ReadAsync(fileBuffer, 0, fileBuffer.Length);

                    var decryptBuffer = provider.Decrypt(fileBuffer);
                    stream.Seek(0, SeekOrigin.Begin);
                    stream.SetLength(decryptBuffer.Length);
                    await stream.WriteAsync(decryptBuffer, 0, decryptBuffer.Length);

                    Array.Clear(fileBuffer, 0, fileBuffer.Length);
                }
            }
        }

        private static void SaveKeyData(RSACrypt provider, string path, DataTypeFlag saveInfoFlag)
        {
            using (var bw = new BinaryWriter(File.Create(path)))
            {
                bw.Write((byte)Opcode.KeyLength);
                bw.Write(provider.ExportKeyLenght());

                if (Convert.ToBoolean(saveInfoFlag & DataTypeFlag.PublicKey))
                {
                    using (var key = provider.ExportKey(false))
                    {
                        var keyBuffer = key.GetBuffer();
                        bw.Write((byte)Opcode.PublicKey);
                        bw.Write(keyBuffer.Length);
                        bw.Write(keyBuffer);
                    }
                }

                if (Convert.ToBoolean(saveInfoFlag & DataTypeFlag.PrivateKey))
                {
                    using (var key = provider.ExportKey(true))
                    {
                        var keyBuffer = key.GetBuffer();
                        bw.Write((byte)Opcode.PrivateKey);
                        bw.Write(keyBuffer.Length);
                        bw.Write(keyBuffer);
                    }
                }
            }
        }

        private static (int, byte[], byte[]) ReadKeyData(RSACrypt provider, string path, DataTypeFlag saveTypeFlag)
        {
            int? keyLenght = null;
            byte[] publicKey = null;
            byte[] privateKey = null;

            if (!File.Exists(path))
                throw new FileNotFoundException("Key file not found");

            using (var br = new BinaryReader(File.Open(path, FileMode.Open)))
            {
                while (br.BaseStream.Position < br.BaseStream.Length)
                {
                    Opcode opcode = (Opcode)br.ReadByte();
                    switch (opcode)
                    {
                        case Opcode.KeyLength:
                            if (keyLenght == null) keyLenght = br.ReadInt32();
                            break;

                        case Opcode.PublicKey:
                            if (publicKey == null)
                                publicKey = br.ReadBytes(br.ReadInt32());
                            break;

                        case Opcode.PrivateKey:
                            if (privateKey == null)
                                privateKey = br.ReadBytes(br.ReadInt32());
                            break;

                        default:
                            throw new Exception("Detected unknown opcode");
                    }
                }
            }

            if (keyLenght == null)
                throw new Exception("Key lenght fault");

            return (keyLenght.Value, publicKey, privateKey);
        }
    }
}
