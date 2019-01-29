using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace RSACryptor.Tests
{
    [TestClass]
    public class RSAFileCryptorTest
    {
        [DataTestMethod]
        [DataRow("a")]
        [DataRow("Hello, world")]
        [DataRow("Random message for test RSA crypto system")]
        public async Task FileCryptor_File_CryptDecrypt(string text)
        {
            var fileName = "text.txt";
            File.WriteAllText(fileName, text);

            await RSAFileCryptor.EncryptFileAsync(fileName, "keys.key", DataTypeFlag.PublicKey | DataTypeFlag.PrivateKey);
            await RSAFileCryptor.DecryptFileAsync(fileName, "keys.key");

            var textContent = File.ReadAllText(fileName);
            File.Delete(fileName);

            Assert.AreEqual(textContent, text);
        }

        [DataTestMethod]
        [DataRow("512kb.txt")]
        public async Task FileCryptor_BigFile_CryptDecrypt(string fileName)
        {
            var text = File.ReadAllText(fileName);

            await RSAFileCryptor.EncryptFileAsync(fileName, "keys.key", DataTypeFlag.PublicKey | DataTypeFlag.PrivateKey);
            await RSAFileCryptor.DecryptFileAsync(fileName, "keys.key");

            var textContent = File.ReadAllText(fileName);

            Assert.AreEqual(textContent, text);
        }
    }
}
