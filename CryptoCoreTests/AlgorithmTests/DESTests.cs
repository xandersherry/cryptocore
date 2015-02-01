using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Xeres.CryptoCore;
using Xeres.CryptoCore.Algorithms;
using Xeres.CryptoCore.StringTransformers;

namespace CryptoCoreTests.AlgorithmTests
{
    [TestClass]
    public class DESTests
    {
        private string testPlaintext = "This is a string to be used for testing.";
        private SymmetricEncryption encryptor = null;
        private SymmetricEncryption decryptor = null;
        private ISymmetricEncryptionAlgorithm eAlgorithm = null;
        private ISymmetricEncryptionAlgorithm dAlgorithm = null;
        private AsciiTransformer transformer = null;
        private byte[] key = null;


        [TestInitialize]
        public void DESTestSetup()
        {
            key = SecureRandom.GetRandomBytes(8);
            encryptor = new SymmetricEncryption();
            decryptor = new SymmetricEncryption();
            eAlgorithm = new DESAlgorithm(){ Key = key};
            dAlgorithm = new DESAlgorithm(){Key = key};
            transformer = new AsciiTransformer();
        }

        [TestMethod]
        public void DES_Encrypting_And_Decrypting_Results_In_Same_String()
        {
            EncryptedData encryptedData = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testPlaintext));

            dAlgorithm.IV = encryptedData.IV;

            byte[] decryptedPlaintext = decryptor.Decrypt(dAlgorithm, encryptedData.Ciphertext);

            Assert.AreEqual(testPlaintext, transformer.GetString(decryptedPlaintext));
        }
        [TestMethod]
        public void DES_Decrypting_With_Incorrect_Key_Fails()
        {
            EncryptedData encryptedData = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testPlaintext));

            dAlgorithm.Key = SecureRandom.GetRandomBytes(8);
            dAlgorithm.IV = encryptedData.IV;

            Exception ex = null;
            byte[] decryptedPlaintext = new byte[1];
            try
            {
                decryptedPlaintext = decryptor.Decrypt(dAlgorithm, encryptedData.Ciphertext);
            }
            catch (Exception caughtEx)
            {
                ex = caughtEx;
            }

            Assert.AreNotEqual(testPlaintext, transformer.GetString(decryptedPlaintext));
        }

        [TestMethod]
        public void DES_Decrypting_With_Incorrect_IV_Fails()
        {
            EncryptedData encryptedData = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testPlaintext));

            dAlgorithm.IV = SecureRandom.GetRandomBytes(8);

            Exception ex = null;
            byte[] decryptedPlaintext = new byte[1];
            try
            {
                decryptedPlaintext = decryptor.Decrypt(dAlgorithm, encryptedData.Ciphertext);
            }
            catch (Exception caughtEx)
            {
                ex = caughtEx;
            }

            Assert.AreNotEqual(testPlaintext, transformer.GetString(decryptedPlaintext));
        }
    }
}
