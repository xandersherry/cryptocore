using System;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.Cryptography;
using Xeres.CryptoCore;
using Xeres.CryptoCore.Algorithms;
using Xeres.CryptoCore.StringTransformers;

namespace CryptoCoreTests.AlgorithmTests
{
    [TestClass]
    public class AuthenticatedAesTests
    {
        private string testClearText = "This is a string to be used for testing.";
        private AuthenticatedSymmetricEncryption encryptor;
        private AuthenticatedSymmetricEncryption decryptor;
        private ICngSymmetricEncryptionAlgorithm eAlgorithm;
        private ICngSymmetricEncryptionAlgorithm dAlgorithm;
        private AsciiTransformer transformer;
        private byte[] key;
        private byte[] additonalAuthenticatedData;

        [TestInitialize]
        public void AuthenticatedAesTestSetup()
        {
            encryptor = new AuthenticatedSymmetricEncryption();
            decryptor = new AuthenticatedSymmetricEncryption();
            eAlgorithm = new AuthenticatedAesAlgorithm();
            dAlgorithm = new AuthenticatedAesAlgorithm();
            transformer = new AsciiTransformer();
            key = SecureRandom.GetRandomBytes(32);
            additonalAuthenticatedData = transformer.GetBytes("Additional Authenticated Data");
        }

        [TestMethod]
        public void AEAD_Encrypting_And_Decrypting_Results_In_Same_String()
        {
            eAlgorithm.Key = key;
          

            byte[] ciphertext = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testClearText));
            byte[] tag = encryptor.GetTag();

            dAlgorithm.Key = key;
            dAlgorithm.IV = eAlgorithm.IV;
            dAlgorithm.Tag = tag;

            byte[] decryptedPlainText = decryptor.Decrypt(dAlgorithm, ciphertext);
            Assert.AreEqual(testClearText, transformer.GetString(decryptedPlainText));
        }

        [TestMethod]
        public void AEAD_CCM_Mode_Encrypting_And_Decrypting_Results_In_Same_String()
        {
            eAlgorithm.Key = key;

            eAlgorithm.ChainingMode = CngChainingMode.Ccm;

            byte[] ciphertext = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testClearText));
            byte[] tag = encryptor.GetTag();

            dAlgorithm.Key = key;
            dAlgorithm.IV = eAlgorithm.IV;
            dAlgorithm.ChainingMode = CngChainingMode.Ccm;
            dAlgorithm.Tag = tag;

            byte[] decryptedPlainText = decryptor.Decrypt(dAlgorithm, ciphertext);
            Assert.AreEqual(testClearText, transformer.GetString(decryptedPlainText));

        }


        [TestMethod]
        public void AEAD_Decrypting_With_Incorrect_Tag_Fails()
        {
            eAlgorithm.Key = key;


            byte[] ciphertext = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testClearText));

            dAlgorithm.Key = key;
            dAlgorithm.IV = eAlgorithm.IV;
            dAlgorithm.Tag = SecureRandom.GetRandomBytes(16);

            Exception exception = null;
            try
            {
                decryptor.Decrypt(dAlgorithm, ciphertext);
            }
            catch (Exception ex)
            {
                exception = ex;
            }
            Assert.IsNotNull(exception);
        }

        [TestMethod]
        public void AEAD_Decrypting_With_Incorrect_Key_Fails()
        {
            eAlgorithm.Key = key;

            byte[] ciphertext = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testClearText));
            byte[] tag = encryptor.GetTag();

            dAlgorithm.Key = SecureRandom.GetRandomBytes(32);
            dAlgorithm.IV = eAlgorithm.IV;
            dAlgorithm.Tag = tag;

            Exception exception = null;
            try
            {
                decryptor.Decrypt(dAlgorithm, ciphertext);
            }
            catch (Exception ex)
            {
                exception = ex;
            }
            Assert.IsNotNull(exception);
        }

        [TestMethod]
        public void AEAD_Decrypting_With_Mismatched_Chaining_Mode_Fails()
        {
            eAlgorithm.Key = key;
            eAlgorithm.ChainingMode = CngChainingMode.Ccm;
            
            byte[] ciphertext = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testClearText));
            byte[] tag = encryptor.GetTag();

            dAlgorithm.Key = key;
            dAlgorithm.IV = eAlgorithm.IV;
            dAlgorithm.Tag = tag;

            Exception exception = null;
            try
            {
                decryptor.Decrypt(dAlgorithm, ciphertext);
            }
            catch (Exception ex)
            {
                exception = ex;
            }
            Assert.IsNotNull(exception);
        }


        [TestMethod]
        public void AEAD_Decrypting_With_Incorrect_IV_Fails()
        {
            eAlgorithm.Key = key;

            byte[] ciphertext = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testClearText));
            byte[] tag = encryptor.GetTag();

            dAlgorithm.Key = key;
            dAlgorithm.IV = SecureRandom.GetRandomBytes(12);
            dAlgorithm.Tag = tag;

            Exception exception = null;
            try
            {
                decryptor.Decrypt(dAlgorithm, ciphertext);
            }
            catch (Exception ex)
            {
                exception = ex;
            }
            Assert.IsNotNull(exception);
        }

        public void AEAD_Encrypting_And_Decrypting_With_AAD_Results_In_Same_String()
        {
            eAlgorithm.Key = key;
            eAlgorithm.AdditionalAuthenticatedData = additonalAuthenticatedData;

            byte[] ciphertext = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testClearText));
            byte[] tag = encryptor.GetTag();

            dAlgorithm.Key = key;
            dAlgorithm.IV = eAlgorithm.IV;
            dAlgorithm.Tag = tag;
            dAlgorithm.AdditionalAuthenticatedData = additonalAuthenticatedData;

            byte[] decryptedPlainText = decryptor.Decrypt(dAlgorithm, ciphertext);
            Assert.AreEqual(testClearText, transformer.GetString(decryptedPlainText));
        }

        [TestMethod]
        public void AEAD_Decrypting_With_Incorrect_AAD_Fails()
        {
            eAlgorithm.Key = key;
            eAlgorithm.AdditionalAuthenticatedData = additonalAuthenticatedData;

            byte[] ciphertext = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testClearText));
            byte[] tag = encryptor.GetTag();

            dAlgorithm.Key = key;
            dAlgorithm.IV = eAlgorithm.IV;
            dAlgorithm.Tag = tag;
            dAlgorithm.AdditionalAuthenticatedData = SecureRandom.GetRandomBytes(29);

            Exception exception = null;
            try
            {
                decryptor.Decrypt(dAlgorithm, ciphertext);
            }
            catch (Exception ex)
            {
                exception = ex;
            }
            Assert.IsNotNull(exception);
        }
    }
}
