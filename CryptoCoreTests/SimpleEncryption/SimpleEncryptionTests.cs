using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Xeres.CryptoCore;

namespace CryptoCoreTests
{
    [TestClass]
    public class SimpleEncryptionTests
    {
        [TestMethod]
        public void EncryptingAndDecryptingMessageResultsInSameMessage()
        {
            string message = "This is a test string to be encrypted and decrypted.";
            string key = SimpleEncryption.GenerateKey();

            string encryptedData = SimpleEncryption.Encrypt(key, message);

            string decryptedMessage = SimpleEncryption.Decrypt(key, encryptedData);

            Assert.AreEqual(message, decryptedMessage);
        }
    }
}
