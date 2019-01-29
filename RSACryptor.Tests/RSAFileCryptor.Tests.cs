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
            var keysFileName = "keys.key";
            File.WriteAllText(fileName, text);

            await RSAFileCryptor.EncryptFileAsync(fileName, keysFileName, DataTypeFlag.PublicKey | DataTypeFlag.PrivateKey);
            await RSAFileCryptor.DecryptFileAsync(fileName, keysFileName);

            var textContent = File.ReadAllText(fileName);
            File.Delete(fileName);
            File.Delete(keysFileName);

            Assert.AreEqual(textContent, text);
        }

        [DataTestMethod]
        [DataRow("512kb.txt")]
        public async Task FileCryptor_BigFile_CryptDecrypt(string fileName)
        {
            var keysFileName = "keys.key";
            var newFileName = "test_data.txt";
            File.Copy(fileName, newFileName);
            var text = File.ReadAllText(newFileName);
            
            await RSAFileCryptor.EncryptFileAsync(newFileName, keysFileName, DataTypeFlag.PublicKey | DataTypeFlag.PrivateKey);
            await RSAFileCryptor.DecryptFileAsync(newFileName, keysFileName);

            var textContent = File.ReadAllText(newFileName);
            File.Delete(newFileName);
            File.Delete(keysFileName);

            Assert.AreEqual(textContent, text);
        }
    }
}
