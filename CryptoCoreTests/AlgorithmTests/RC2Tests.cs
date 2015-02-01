using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Xeres.CryptoCore;
using Xeres.CryptoCore.Algorithms;
using Xeres.CryptoCore.StringTransformers;

namespace CryptoCoreTests.AlgorithmTests
{
    [TestClass]
    public class RC2Tests
    {
        private string testClearText = "This is a string to be used for testing.";
        private SymmetricEncryption encryptor = null;
        private SymmetricEncryption decryptor = null;
        private ISymmetricEncryptionAlgorithm eAlgorithm = null;
        private ISymmetricEncryptionAlgorithm dAlgorithm = null;
        private AsciiTransformer transformer = null;
        private byte[] key = null;


        [TestInitialize]
        public void RC2TestSetup()
        {
            encryptor = new SymmetricEncryption();
            decryptor = new SymmetricEncryption();
            eAlgorithm = new RC2Algorithm();
            dAlgorithm = new RC2Algorithm();
            transformer = new AsciiTransformer();
            key = SecureRandom.GetRandomBytes(5);

        }

        [TestMethod]
        public void RC2_Encrypting_And_Decrypting_Results_In_Same_String()
        {

            eAlgorithm.Key = key;


            byte[] ciphertext = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testClearText));


            dAlgorithm.Key = key;
            dAlgorithm.IV = eAlgorithm.IV;

            byte[] decryptedPlainText = decryptor.Decrypt(dAlgorithm, ciphertext);
            Assert.AreEqual(testClearText, transformer.GetString(decryptedPlainText));
        }
        [TestMethod]
        public void RC2_Decrypting_With_Incorrect_Key_Fails()
        {
            eAlgorithm.Key = key;


            byte[] ciphertext = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testClearText));


            dAlgorithm.Key = SecureRandom.GetRandomBytes(5);
            dAlgorithm.IV = eAlgorithm.IV;

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
        public void RC2_Decrypting_With_Incorrect_IV_Fails()
        {
            eAlgorithm.Key = key;


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
