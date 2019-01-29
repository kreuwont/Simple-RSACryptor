using System.Text;
using RSACryptor;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace RSACryptor.Tests
{
    [TestClass]
    public class RSACryptTest
    {
        [TestMethod]
        public void RSATests_HelloWorld_EncryptDecrypt()
        {
            string text = "Hello, World";
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
