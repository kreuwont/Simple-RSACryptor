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
        [TestMethod]
        public async Task FileCryptor_HelloWorldFile_CryptDecrypt()
        {
            var text = "Hello, World";
            var fileName = "text.txt";
            File.WriteAllText(fileName, text);

            await RSAFileCryptor.EncryptFileAsync(fileName, "keys.key", DataTypeFlag.PublicKey | DataTypeFlag.PrivateKey);
            await RSAFileCryptor.DecryptFileAsync(fileName, "keys.key");

            var textContent = File.ReadAllText(fileName);
            Assert.AreEqual(textContent, text);
        }
    }
}
