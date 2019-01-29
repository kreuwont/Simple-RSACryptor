using System.IO;
using System.Text;
using RSACryptor;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace RSACryptor.Tests
{
    [TestClass]
    public class RSACryptTest
    {
        [DataTestMethod]
        [DataRow("a")]
        [DataRow("Hello, world")]
        [DataRow("Random message for test RSA crypto system")]
        public void RSATests_String_EncryptDecrypt(string text)
        {
            RSACrypt cryptor = new RSACrypt();

            var cryptBuffer = Encoding.UTF8.GetBytes(text);
            var encryptBuffer = cryptor.Encrypt(cryptBuffer);
            var decryptBuffer = cryptor.Decrypt(encryptBuffer);
            var resultString = Encoding.UTF8.GetString(decryptBuffer);

            cryptor.Dispose();

            Assert.AreEqual(resultString, text);
        }

        [DataTestMethod]
        [DataRow("512kb.txt")]
        public void RSATests_BigString_EncryptDecrypt(string fileName)
        {
            string text = File.ReadAllText(fileName);
            RSACrypt cryptor = new RSACrypt();

            var cryptBuffer = Encoding.UTF8.GetBytes(text);
            var encryptBuffer = cryptor.Encrypt(cryptBuffer);
            var decryptBuffer = cryptor.Decrypt(encryptBuffer);
            var resultString = Encoding.UTF8.GetString(decryptBuffer);

            cryptor.Dispose();

            Assert.AreEqual(resultString, text);
        }
    }
}
