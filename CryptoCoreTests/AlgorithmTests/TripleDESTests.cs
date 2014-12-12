using System;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Xeres.CryptoCore;
using Xeres.CryptoCore.Algorithms;
using Xeres.CryptoCore.StringTransformers;

namespace CryptoCoreTests.AlgorithmTests
{
    [TestClass]
    public class TripleDESTests
    {
        private string testClearText = "This is a string to be used for testing.";
        private SymmetricEncryption encryptor = null;
        private SymmetricEncryption decryptor = null;
        private ISymmetricEncryptionAlgorithm eAlgorithm = null;
        private ISymmetricEncryptionAlgorithm dAlgorithm = null;
        private AsciiTransformer transformer = null;
        private byte[] key = null;
        private byte[] iv = null;

        [TestInitialize]
        public void TripleDESTestSetup()
        {
            encryptor = new SymmetricEncryption();
            decryptor = new SymmetricEncryption();
            eAlgorithm = new TripleDESAlgorithm();
            dAlgorithm = new TripleDESAlgorithm();
            transformer = new AsciiTransformer();
            key = SecureRandom.GetRandomBytes(24);
            iv = SecureRandom.GetRandomBytes(8);
        }

        [TestMethod]
        public void TDES_Encrypting_And_Decrypting_Results_In_Same_String()
        {

            eAlgorithm.Key = key;
            eAlgorithm.IV = iv;

            byte[] ciphertext = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testClearText));


            dAlgorithm.Key = key;
            dAlgorithm.IV = iv;

            byte[] decryptedPlainText = decryptor.Decrypt(dAlgorithm, ciphertext);
            Assert.AreEqual(testClearText, transformer.GetString(decryptedPlainText));
        }
        [TestMethod]
        public void TDES_Decrypting_With_Incorrect_Key_Fails()
        {
            eAlgorithm.Key = key;
            eAlgorithm.IV = iv;

            byte[] ciphertext = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testClearText));


            dAlgorithm.Key = SecureRandom.GetRandomBytes(24);
            dAlgorithm.IV = iv;

            Exception ex = null;
            byte[] decryptedPlainText = new byte[1];
            try
            {
                decryptedPlainText = decryptor.Decrypt(dAlgorithm, ciphertext);
            }
            catch (Exception caughtEx)
            {
                ex = caughtEx;
            }

            Assert.AreNotEqual(testClearText, transformer.GetString(decryptedPlainText));
        }

        [TestMethod]
        public void TDES_Decrypting_With_Incorrect_IV_Fails()
        {
            eAlgorithm.Key = key;
            eAlgorithm.IV = iv;

            byte[] ciphertext = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testClearText));


            dAlgorithm.Key = key;
            dAlgorithm.IV = SecureRandom.GetRandomBytes(8);

            Exception ex = null;
            byte[] decryptedPlainText = new byte[1];
            try
            {
                decryptedPlainText = decryptor.Decrypt(dAlgorithm, ciphertext);
            }
            catch (Exception caughtEx)
            {
                ex = caughtEx;
            }

            Assert.AreNotEqual(testClearText, transformer.GetString(decryptedPlainText));
        }
    }
}
