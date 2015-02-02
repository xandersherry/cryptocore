using System;
using System.Security.Cryptography;
using CryptoCoreTests.StringTransformerTests;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Xeres.CryptoCore;
using Xeres.CryptoCore.Algorithms;
using Xeres.CryptoCore.StringTransformers;

namespace CryptoCoreTests.AlgorithmTests
{
    [TestClass]
    public class AesTests
    {
        private string testPlaintext = "This is a string to be used for testing.";
        private string testPlaintextWithExtendedCharacters = "This is å test string with ëxteñded charactérs.";
        private string testPlaintextWithChineseCharacters = "这是额外的扩展字符集的测试字符串中国人。";
        private SymmetricEncryption encryptor = null;
        private SymmetricEncryption decryptor = null;
        private AuthenticatedSymmetricEncryption authenticatedEncryptor;
        private AuthenticatedSymmetricEncryption authenticatedDecrytor;
        private ISymmetricEncryptionAlgorithm eAlgorithm = null;
        private ISymmetricEncryptionAlgorithm dAlgorithm = null;
        private IStringTransformer transformer = null;
        private byte[] key = null;
        private byte[] validationKey = null;
         

        [TestInitialize]
        public void AesTestSetup()
        {
            key = SecureRandom.GetRandomBytes(32);
            encryptor = new SymmetricEncryption();
            decryptor = new SymmetricEncryption();
            authenticatedEncryptor = new AuthenticatedSymmetricEncryption();
            authenticatedDecrytor = new AuthenticatedSymmetricEncryption();
            eAlgorithm = new AesAlgorithm(){Key = key};
            dAlgorithm = new AesAlgorithm(){ Key = key};
            transformer = new UTF8Transformer();
        }

        [TestMethod]
        public void AES_Encrypting_And_Decrypting_Results_In_Same_String()
        {
            EncryptedData encryptedData = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testPlaintext));
            
            dAlgorithm.IV = encryptedData.IV;

            byte[] decryptedPlaintext = decryptor.Decrypt(dAlgorithm, encryptedData.Ciphertext);
            
            Assert.AreEqual(testPlaintext, transformer.GetString(decryptedPlaintext));
        }


        [TestMethod]
        public void AES_CFB_Mode_Encrypting_And_Decrypting_Results_In_Same_String()
        {
            eAlgorithm.Mode = CipherMode.CFB;

            EncryptedData encryptedData = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testPlaintext));

            dAlgorithm.Mode = CipherMode.CFB;
            dAlgorithm.IV = encryptedData.IV;

            byte[] decryptedPlaintext = decryptor.Decrypt(dAlgorithm, encryptedData.Ciphertext);

            Assert.AreEqual(testPlaintext, transformer.GetString(decryptedPlaintext));
        }

        [TestMethod]
        public void AES_Encrypting_And_Decrypting_String_With_ExtendedCharacters_Results_In_Same_String()
        {
            EncryptedData encryptedData = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testPlaintextWithExtendedCharacters));

            dAlgorithm.IV = encryptedData.IV;

            byte[] decryptedPlaintext = decryptor.Decrypt(dAlgorithm, encryptedData.Ciphertext);

            Assert.AreEqual(testPlaintextWithExtendedCharacters, transformer.GetString(decryptedPlaintext));
        }

        [TestMethod]
        public void AES_Encrypting_And_Decrypting_String_With_Chinese_Characters_Results_In_Same_String()
        {
            EncryptedData encryptedData = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testPlaintextWithChineseCharacters));

            dAlgorithm.IV = encryptedData.IV;

            byte[] decryptedPlaintext = decryptor.Decrypt(dAlgorithm, encryptedData.Ciphertext);

            Assert.AreEqual(testPlaintextWithChineseCharacters, transformer.GetString(decryptedPlaintext));
        }


        [TestMethod]
        public void AES_Decrypting_With_Incorrect_Key_Fails()
        {
            EncryptedData encryptedData = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testPlaintext));

            dAlgorithm.Key = SecureRandom.GetRandomBytes(32);
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
        public void AES_Decrypting_With_Incorrect_IV_Fails()
        {
            EncryptedData encryptedData = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testPlaintext));

            dAlgorithm.IV = SecureRandom.GetRandomBytes(16);

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
        public void AE_Encrypting_and_Decrypting_With_HMACSHA256_Succeeds_and_Results_in_Same_String()
        {
            validationKey = SecureRandom.GetRandomBytes(32);
            authenticatedEncryptor.HMACAlgorithm = new HMACSHA256(){ Key = validationKey};

            EncryptedData encryptedData = authenticatedEncryptor.Encrypt(eAlgorithm, transformer.GetBytes(testPlaintext));
  
            authenticatedDecrytor.HMACAlgorithm = new HMACSHA256(){Key = validationKey};
            authenticatedDecrytor.Tag = encryptedData.Tag;
            dAlgorithm.IV = encryptedData.IV;

            byte[] decryptedPlaintext = authenticatedDecrytor.Decrypt(dAlgorithm, encryptedData.Ciphertext);

            Assert.AreEqual(testPlaintext, transformer.GetString(decryptedPlaintext));
        }

        [TestMethod]
        public void AE_CFB_Mode_Encrypting_and_Decrypting_With_HMACSHA256_Succeeds_and_Results_in_Same_String()
        {
            validationKey = SecureRandom.GetRandomBytes(32);
            authenticatedEncryptor.HMACAlgorithm = new HMACSHA256() { Key = validationKey };
            eAlgorithm.Mode = CipherMode.CFB;
            
            EncryptedData encryptedData = authenticatedEncryptor.Encrypt(eAlgorithm, transformer.GetBytes(testPlaintext));

            authenticatedDecrytor.HMACAlgorithm = new HMACSHA256() { Key = validationKey };
            authenticatedDecrytor.Tag = encryptedData.Tag;
            dAlgorithm.IV = encryptedData.IV;
            dAlgorithm.Mode = CipherMode.CFB;

            byte[] decryptedPlaintext = authenticatedDecrytor.Decrypt(dAlgorithm, encryptedData.Ciphertext);

            Assert.AreEqual(testPlaintext, transformer.GetString(decryptedPlaintext));
        }

        [TestMethod]
        public void AE_Encrypting_and_Decrypting_With_HMACSHA512_Succeeds_and_Results_in_Same_String()
        {
            validationKey = SecureRandom.GetRandomBytes(64);
            authenticatedEncryptor.HMACAlgorithm = new HMACSHA512(){Key = validationKey};

            EncryptedData encryptedData = authenticatedEncryptor.Encrypt(eAlgorithm, transformer.GetBytes(testPlaintext));
     
            authenticatedDecrytor.HMACAlgorithm = new HMACSHA512(){Key = validationKey};
            authenticatedDecrytor.Tag = encryptedData.Tag;
            dAlgorithm.IV = encryptedData.IV;

            byte[] decryptedPlaintext = authenticatedDecrytor.Decrypt(dAlgorithm, encryptedData.Ciphertext);

            Assert.AreEqual(testPlaintext, transformer.GetString(decryptedPlaintext));
        }

        [TestMethod]
        public void AE_Encrypting_and_Decrypting_With_HMACSHA1_Succeeds_and_Results_in_Same_String()
        {
            validationKey = SecureRandom.GetRandomBytes(20);
            authenticatedEncryptor.HMACAlgorithm = new HMACSHA1(){Key = validationKey};

            EncryptedData encryptedData = authenticatedEncryptor.Encrypt(eAlgorithm, transformer.GetBytes(testPlaintext));

            authenticatedDecrytor.HMACAlgorithm = new HMACSHA1(){Key = validationKey};
            authenticatedDecrytor.Tag = encryptedData.Tag;
            dAlgorithm.IV = encryptedData.IV;

            byte[] decryptedPlaintext = authenticatedDecrytor.Decrypt(dAlgorithm, encryptedData.Ciphertext);

            Assert.AreEqual(testPlaintext, transformer.GetString(decryptedPlaintext));
        }

        [TestMethod]
        public void AE_Encrypting_and_Decrypting_With_HMACSHA256_With_Invalid_MAC_Fails()
        {
           validationKey = SecureRandom.GetRandomBytes(32);
            authenticatedEncryptor.HMACAlgorithm = new HMACSHA256(){ Key = validationKey};

            EncryptedData encryptedData = authenticatedEncryptor.Encrypt(eAlgorithm, transformer.GetBytes(testPlaintext));
  
            authenticatedDecrytor.HMACAlgorithm = new HMACSHA256(){Key = validationKey};
            authenticatedDecrytor.Tag = SecureRandom.GetRandomBytes(32);
            dAlgorithm.IV = encryptedData.IV;
  
            Exception exception = null;
            try
            {
                authenticatedDecrytor.Decrypt(dAlgorithm, encryptedData.Ciphertext);
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
            validationKey = SecureRandom.GetRandomBytes(32);
            authenticatedEncryptor.HMACAlgorithm = new HMACSHA256(){ Key = validationKey};

            EncryptedData encryptedData = authenticatedEncryptor.Encrypt(eAlgorithm, transformer.GetBytes(testPlaintext));
  
            authenticatedDecrytor.HMACAlgorithm = new HMACSHA256(){Key = SecureRandom.GetRandomBytes(32)};
            authenticatedDecrytor.Tag = encryptedData.Tag;
            dAlgorithm.IV = encryptedData.IV;

            Exception exception = null;
            try
            {
                authenticatedDecrytor.Decrypt(dAlgorithm, encryptedData.Ciphertext);
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
            validationKey = SecureRandom.GetRandomBytes(32);
            authenticatedEncryptor.HMACAlgorithm = new HMACSHA256(){ Key = validationKey};

            EncryptedData encryptedData = authenticatedEncryptor.Encrypt(eAlgorithm, transformer.GetBytes(testPlaintext));
  
            authenticatedDecrytor.HMACAlgorithm = new HMACSHA1(){Key = validationKey};
            authenticatedDecrytor.Tag = encryptedData.Tag;
            dAlgorithm.IV = encryptedData.IV;

            Exception exception = null;
            try
            {
                authenticatedDecrytor.Decrypt(dAlgorithm, encryptedData.Ciphertext);
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
            validationKey = SecureRandom.GetRandomBytes(32);
            authenticatedEncryptor.HMACAlgorithm = new HMACSHA256(){ Key = validationKey};

            EncryptedData encryptedData = authenticatedEncryptor.Encrypt(eAlgorithm, transformer.GetBytes(testPlaintext));
  
            authenticatedDecrytor.HMACAlgorithm = new HMACSHA256(){Key = validationKey};
            authenticatedDecrytor.Tag = encryptedData.Tag;
            dAlgorithm.IV = encryptedData.IV;

            Exception exception = null;
            try
            {
                authenticatedDecrytor.Decrypt(dAlgorithm, SecureRandom.GetRandomBytes(encryptedData.Ciphertext.Length));
            }
            catch (Exception ex)
            {
                exception = ex;
            }
            Assert.IsNotNull(exception);
        }
    }
}
