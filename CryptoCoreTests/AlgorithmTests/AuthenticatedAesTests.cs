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
        private string testPlaintext = "This is a string to be used for testing.";
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
            key = SecureRandom.GetRandomBytes(32);
            encryptor = new AuthenticatedSymmetricEncryption();
            decryptor = new AuthenticatedSymmetricEncryption();
            eAlgorithm = new AuthenticatedAesAlgorithm(){Key = key};
            dAlgorithm = new AuthenticatedAesAlgorithm(){Key = key};
            transformer = new AsciiTransformer();
            additonalAuthenticatedData = transformer.GetBytes("Additional Authenticated Data");
        }

        [TestMethod]
        public void AEAD_Encrypting_And_Decrypting_Results_In_Same_String()
        {
            EncryptedData encryptedData = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testPlaintext));

            dAlgorithm.IV = encryptedData.IV;
            dAlgorithm.Tag = encryptedData.Tag;

            byte[] decryptedPlaintext = decryptor.Decrypt(dAlgorithm, encryptedData.Ciphertext);

            Assert.AreEqual(testPlaintext, transformer.GetString(decryptedPlaintext));
        }

        [TestMethod]
        public void AEAD_CCM_Mode_Encrypting_And_Decrypting_Results_In_Same_String()
        {
            eAlgorithm.ChainingMode = CngChainingMode.Ccm;

            EncryptedData encryptedData = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testPlaintext));

            dAlgorithm.IV = encryptedData.IV;
            dAlgorithm.ChainingMode = CngChainingMode.Ccm;
            dAlgorithm.Tag = encryptedData.Tag;

            byte[] decryptedPlaintext = decryptor.Decrypt(dAlgorithm, encryptedData.Ciphertext);

            Assert.AreEqual(testPlaintext, transformer.GetString(decryptedPlaintext));
        }


        [TestMethod]
        public void AEAD_Decrypting_With_Incorrect_Tag_Fails()
        {
            EncryptedData encryptedData = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testPlaintext));

            dAlgorithm.IV = encryptedData.IV;
            dAlgorithm.Tag = SecureRandom.GetRandomBytes(16);

            Exception exception = null;
            try
            {
                decryptor.Decrypt(dAlgorithm, encryptedData.Ciphertext);
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
            EncryptedData encryptedData = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testPlaintext));

            dAlgorithm.Key = SecureRandom.GetRandomBytes(32);
            dAlgorithm.IV = encryptedData.IV;
            dAlgorithm.Tag = encryptedData.Tag;

            Exception exception = null;
            try
            {
                decryptor.Decrypt(dAlgorithm, encryptedData.Ciphertext);
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
            eAlgorithm.ChainingMode = CngChainingMode.Ccm;
            
            EncryptedData encryptedData = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testPlaintext));

            dAlgorithm.IV = encryptedData.IV;
            dAlgorithm.Tag = encryptedData.Tag;

            Exception exception = null;
            try
            {
                decryptor.Decrypt(dAlgorithm, encryptedData.Ciphertext);
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
            EncryptedData encryptedData = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testPlaintext));
   
            dAlgorithm.IV = SecureRandom.GetRandomBytes(12);
            dAlgorithm.Tag = encryptedData.Tag;

            Exception exception = null;
            try
            {
                decryptor.Decrypt(dAlgorithm, encryptedData.Ciphertext);
            }
            catch (Exception ex)
            {
                exception = ex;
            }

            Assert.IsNotNull(exception);
        }

        public void AEAD_Encrypting_And_Decrypting_With_AAD_Results_In_Same_String()
        {
            eAlgorithm.AdditionalAuthenticatedData = additonalAuthenticatedData;

            EncryptedData encryptedData = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testPlaintext));
        
            dAlgorithm.IV = encryptedData.IV;
            dAlgorithm.Tag = encryptedData.Tag;
            dAlgorithm.AdditionalAuthenticatedData = encryptedData.AdditionalAuthenticatedData;

            byte[] decryptedPlaintext = decryptor.Decrypt(dAlgorithm, encryptedData.Ciphertext);

            Assert.AreEqual(testPlaintext, transformer.GetString(decryptedPlaintext));
        }

        [TestMethod]
        public void AEAD_Decrypting_With_Incorrect_AAD_Fails()
        {
            eAlgorithm.AdditionalAuthenticatedData = additonalAuthenticatedData;

            EncryptedData encryptedData = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testPlaintext));

            dAlgorithm.IV = encryptedData.IV;
            dAlgorithm.Tag = encryptedData.Tag;
            dAlgorithm.AdditionalAuthenticatedData = SecureRandom.GetRandomBytes(29);

            Exception exception = null;
            try
            {
                decryptor.Decrypt(dAlgorithm, encryptedData.Ciphertext);
            }
            catch (Exception ex)
            {
                exception = ex;
            }

            Assert.IsNotNull(exception);
        }
    }
}
