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
        private byte[] iv;
        private byte[] additonalAuthenticatedData;
        private AuthenticatedSymmetricEncryption nonCNGencryptor;
        private AuthenticatedSymmetricEncryption nonCNGdecryptor;
        private ISymmetricEncryptionAlgorithm nonCNGeAlgorithm;
        private ISymmetricEncryptionAlgorithm nonCNGdAlgorithm;
        private byte[] nonCNGiv;
        private HMAC eValidationAlgorithm;
        private HMAC dValidationAlgorithm;
        private byte[] validationKey;

        [TestInitialize]
        public void AuthenticatedAesTestSetup()
        {
            encryptor = new AuthenticatedSymmetricEncryption();
            decryptor = new AuthenticatedSymmetricEncryption();
            eAlgorithm = new AuthenticatedAesAlgorithm();
            dAlgorithm = new AuthenticatedAesAlgorithm();
            transformer = new AsciiTransformer();
            key = SecureRandom.GetRandomBytes(32);
            iv = SecureRandom.GetRandomBytes(12);
            additonalAuthenticatedData = transformer.GetBytes("Additional Authenticated Data");
            nonCNGencryptor = new AuthenticatedSymmetricEncryption();
            nonCNGdecryptor = new AuthenticatedSymmetricEncryption();
            nonCNGeAlgorithm = new AesAlgorithm();
            nonCNGdAlgorithm = new AesAlgorithm();
            validationKey = SecureRandom.GetRandomBytes(32);
            nonCNGiv = SecureRandom.GetRandomBytes(16);
        }

        [TestMethod]
        public void AEAD_Encrypting_And_Decrypting_Results_In_Same_String()
        {
            eAlgorithm.Key = key;
            eAlgorithm.IV = iv;

            byte[] ciphertext = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testClearText));
            byte[] tag = encryptor.GetTag();

            dAlgorithm.Key = key;
            dAlgorithm.IV = iv;
            dAlgorithm.Tag = tag;

            byte[] decryptedPlainText = decryptor.Decrypt(dAlgorithm, ciphertext);
            Assert.AreEqual(testClearText, transformer.GetString(decryptedPlainText));
        }

        [TestMethod]
        public void AEAD_CCM_Mode_Encrypting_And_Decrypting_Results_In_Same_String()
        {
            eAlgorithm.Key = key;
            eAlgorithm.IV = iv;
            eAlgorithm.ChainingMode = CngChainingMode.Ccm;

            byte[] ciphertext = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testClearText));
            byte[] tag = encryptor.GetTag();

            dAlgorithm.Key = key;
            dAlgorithm.IV = iv;
            dAlgorithm.ChainingMode = CngChainingMode.Ccm;
            dAlgorithm.Tag = tag;

            byte[] decryptedPlainText = decryptor.Decrypt(dAlgorithm, ciphertext);
            Assert.AreEqual(testClearText, transformer.GetString(decryptedPlainText));

        }


        [TestMethod]
        public void AEAD_Decrypting_With_Incorrect_Tag_Fails()
        {
            eAlgorithm.Key = key;
            eAlgorithm.IV = iv;

            byte[] ciphertext = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testClearText));

            dAlgorithm.Key = key;
            dAlgorithm.IV = iv;
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
            eAlgorithm.IV = iv;

            byte[] ciphertext = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testClearText));
            byte[] tag = encryptor.GetTag();

            dAlgorithm.Key = SecureRandom.GetRandomBytes(32);
            dAlgorithm.IV = iv;
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
            eAlgorithm.IV = iv;
            eAlgorithm.ChainingMode = CngChainingMode.Ccm;
            
            byte[] ciphertext = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testClearText));
            byte[] tag = encryptor.GetTag();

            dAlgorithm.Key = key;
            dAlgorithm.IV = iv;
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
            eAlgorithm.IV = iv;

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
            eAlgorithm.IV = iv;
            eAlgorithm.AdditionalAuthenticatedData = additonalAuthenticatedData;

            byte[] ciphertext = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testClearText));
            byte[] tag = encryptor.GetTag();

            dAlgorithm.Key = key;
            dAlgorithm.IV = iv;
            dAlgorithm.Tag = tag;
            dAlgorithm.AdditionalAuthenticatedData = additonalAuthenticatedData;

            byte[] decryptedPlainText = decryptor.Decrypt(dAlgorithm, ciphertext);
            Assert.AreEqual(testClearText, transformer.GetString(decryptedPlainText));
        }

        [TestMethod]
        public void AEAD_Decrypting_With_Incorrect_AAD_Fails()
        {
            eAlgorithm.Key = key;
            eAlgorithm.IV = iv;
            eAlgorithm.AdditionalAuthenticatedData = additonalAuthenticatedData;

            byte[] ciphertext = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testClearText));
            byte[] tag = encryptor.GetTag();

            dAlgorithm.Key = key;
            dAlgorithm.IV = iv;
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

        [TestMethod]
        public void AE_Encrypting_and_Decrypting_With_HMACSHA256_Succeeds_and_Results_in_Same_String()
        {
            nonCNGeAlgorithm.Key = key;
            nonCNGeAlgorithm.IV = nonCNGiv;

            eValidationAlgorithm = new HMACSHA256();
            eValidationAlgorithm.Key = validationKey;
            nonCNGencryptor.HMACAlgorithm = eValidationAlgorithm;

            byte[] ciphertext = nonCNGencryptor.Encrypt(nonCNGeAlgorithm, transformer.GetBytes(testClearText));
            byte[] hmac = nonCNGencryptor.GetTag();

            nonCNGdAlgorithm.Key = key;
            nonCNGdAlgorithm.IV = nonCNGiv;

            dValidationAlgorithm = new HMACSHA256();
            dValidationAlgorithm.Key = validationKey;
            nonCNGdecryptor.HMACAlgorithm = dValidationAlgorithm;
            nonCNGdecryptor.Tag = hmac;

            byte[] decryptedPlainText = nonCNGdecryptor.Decrypt(nonCNGdAlgorithm, ciphertext);
            Assert.AreEqual(testClearText, transformer.GetString(decryptedPlainText));
        }

        [TestMethod]
        public void AE_Encrypting_and_Decrypting_With_HMACSHA512_Succeeds_and_Results_in_Same_String()
        {
            validationKey = SecureRandom.GetRandomBytes(64);

            nonCNGeAlgorithm.Key = key;
            nonCNGeAlgorithm.IV = nonCNGiv;

            eValidationAlgorithm = new HMACSHA512();
            eValidationAlgorithm.Key = validationKey;
            nonCNGencryptor.HMACAlgorithm = eValidationAlgorithm;

            byte[] ciphertext = nonCNGencryptor.Encrypt(nonCNGeAlgorithm, transformer.GetBytes(testClearText));
            byte[] hmac = nonCNGencryptor.GetTag();

            nonCNGdAlgorithm.Key = key;
            nonCNGdAlgorithm.IV = nonCNGiv;

            dValidationAlgorithm = new HMACSHA512();
            dValidationAlgorithm.Key = validationKey;
            nonCNGdecryptor.HMACAlgorithm = dValidationAlgorithm;
            nonCNGdecryptor.Tag = hmac;

            byte[] decryptedPlainText = nonCNGdecryptor.Decrypt(nonCNGdAlgorithm, ciphertext);
            Assert.AreEqual(testClearText, transformer.GetString(decryptedPlainText));
        }

        [TestMethod]
        public void AE_Encrypting_and_Decrypting_With_HMACSHA1_Succeeds_and_Results_in_Same_String()
        {
            validationKey = SecureRandom.GetRandomBytes(20);

            nonCNGeAlgorithm.Key = key;
            nonCNGeAlgorithm.IV = nonCNGiv;

            eValidationAlgorithm = new HMACSHA1();
            eValidationAlgorithm.Key = validationKey;
            nonCNGencryptor.HMACAlgorithm = eValidationAlgorithm;

            byte[] ciphertext = nonCNGencryptor.Encrypt(nonCNGeAlgorithm, transformer.GetBytes(testClearText));
            byte[] hmac = nonCNGencryptor.GetTag();

            nonCNGdAlgorithm.Key = key;
            nonCNGdAlgorithm.IV = nonCNGiv;

            dValidationAlgorithm = new HMACSHA1();
            dValidationAlgorithm.Key = validationKey;
            nonCNGdecryptor.HMACAlgorithm = dValidationAlgorithm;
            nonCNGdecryptor.Tag = hmac;

            byte[] decryptedPlainText = nonCNGdecryptor.Decrypt(nonCNGdAlgorithm, ciphertext);
            Assert.AreEqual(testClearText, transformer.GetString(decryptedPlainText));
        }

        [TestMethod]
        public void AE_Encrypting_and_Decrypting_With_HMACSHA256_With_Invalid_MAC_Fails()
        {
            nonCNGeAlgorithm.Key = key;
            nonCNGeAlgorithm.IV = nonCNGiv;

            eValidationAlgorithm = new HMACSHA256();
            eValidationAlgorithm.Key = validationKey;
            nonCNGencryptor.HMACAlgorithm = eValidationAlgorithm;

            byte[] ciphertext = nonCNGencryptor.Encrypt(nonCNGeAlgorithm, transformer.GetBytes(testClearText));

            nonCNGdAlgorithm.Key = key;
            nonCNGdAlgorithm.IV = nonCNGiv;

            dValidationAlgorithm = new HMACSHA256();
            dValidationAlgorithm.Key = validationKey;
            nonCNGdecryptor.HMACAlgorithm = dValidationAlgorithm;
            nonCNGdecryptor.Tag = SecureRandom.GetRandomBytes(32);

            Exception exception = null;
            try
            {
                nonCNGdecryptor.Decrypt(nonCNGdAlgorithm, ciphertext);
            }
            catch (Exception ex)
            {
                exception = ex;
            }
            Assert.IsNotNull(exception);
        }

        [TestMethod]
        public void AE_Encrypting_and_Decrypting_With_HMACSHA256_With_Invalid_MAC_Key_Fails()
        {
            nonCNGeAlgorithm.Key = key;
            nonCNGeAlgorithm.IV = nonCNGiv;

            eValidationAlgorithm = new HMACSHA256();
            eValidationAlgorithm.Key = validationKey;
            nonCNGencryptor.HMACAlgorithm = eValidationAlgorithm;

            byte[] ciphertext = nonCNGencryptor.Encrypt(nonCNGeAlgorithm, transformer.GetBytes(testClearText));
            byte[] hmac = nonCNGencryptor.GetTag();

            nonCNGdAlgorithm.Key = key;
            nonCNGdAlgorithm.IV = nonCNGiv;

            dValidationAlgorithm = new HMACSHA256();
            dValidationAlgorithm.Key = SecureRandom.GetRandomBytes(32);
            nonCNGdecryptor.HMACAlgorithm = dValidationAlgorithm;
            nonCNGdecryptor.Tag = hmac;

            Exception exception = null;
            try
            {
                nonCNGdecryptor.Decrypt(nonCNGdAlgorithm, ciphertext);
            }
            catch (Exception ex)
            {
                exception = ex;
            }
            Assert.IsNotNull(exception);
        }

        [TestMethod]
        public void AE_Encrypting_and_Decrypting_With_HMACSHA256_With_Incorrect_MAC_Algorithm_Fails()
        {
            nonCNGeAlgorithm.Key = key;
            nonCNGeAlgorithm.IV = nonCNGiv;

            eValidationAlgorithm = new HMACSHA256();
            eValidationAlgorithm.Key = validationKey;
            nonCNGencryptor.HMACAlgorithm = eValidationAlgorithm;

            byte[] ciphertext = nonCNGencryptor.Encrypt(nonCNGeAlgorithm, transformer.GetBytes(testClearText));
            byte[] hmac = nonCNGencryptor.GetTag();

            nonCNGdAlgorithm.Key = key;
            nonCNGdAlgorithm.IV = nonCNGiv;

            dValidationAlgorithm = new HMACSHA1();
            dValidationAlgorithm.Key = validationKey;
            nonCNGdecryptor.HMACAlgorithm = dValidationAlgorithm;
            nonCNGdecryptor.Tag = hmac;

            Exception exception = null;
            try
            {
                nonCNGdecryptor.Decrypt(nonCNGdAlgorithm, ciphertext);
            }
            catch (Exception ex)
            {
                exception = ex;
            }
            Assert.IsNotNull(exception);
        }

        [TestMethod]
        public void AE_Encrypting_and_Decrypting_With_HMACSHA256_With_Incorrect_Ciphertext_Fails()
        {
            nonCNGeAlgorithm.Key = key;
            nonCNGeAlgorithm.IV = nonCNGiv;

            eValidationAlgorithm = new HMACSHA256();
            eValidationAlgorithm.Key = validationKey;
            nonCNGencryptor.HMACAlgorithm = eValidationAlgorithm;

            byte[] ciphertext = nonCNGencryptor.Encrypt(nonCNGeAlgorithm, transformer.GetBytes(testClearText));
            byte[] hmac = nonCNGencryptor.GetTag();

            nonCNGdAlgorithm.Key = key;
            nonCNGdAlgorithm.IV = nonCNGiv;

            dValidationAlgorithm = new HMACSHA256();
            dValidationAlgorithm.Key = validationKey;
            nonCNGdecryptor.HMACAlgorithm = dValidationAlgorithm;
            nonCNGdecryptor.Tag = hmac;

            Exception exception = null;
            try
            {
                nonCNGdecryptor.Decrypt(nonCNGdAlgorithm, SecureRandom.GetRandomBytes(ciphertext.Length));
            }
            catch (Exception ex)
            {
                exception = ex;
            }
            Assert.IsNotNull(exception);
        }
    }
}
