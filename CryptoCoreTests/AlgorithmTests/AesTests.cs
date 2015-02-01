using System;
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
        private string testClearText = "This is a string to be used for testing.";
        private string testClearTextWithExtendedCharacters = "This is å test string with ëxteñded charactérs.";
        private string testClearTextWithChineseCharacters = "这是额外的扩展字符集的测试字符串中国人。";
        private SymmetricEncryption encryptor = null;
        private SymmetricEncryption decryptor = null;
        private ISymmetricEncryptionAlgorithm eAlgorithm = null;
        private ISymmetricEncryptionAlgorithm dAlgorithm = null;
        private IStringTransformer transformer = null;
        private byte[] key = null;


        [TestInitialize]
        public void AesTestSetup()
        {
            encryptor = new SymmetricEncryption();
            decryptor = new SymmetricEncryption();
            eAlgorithm = new AesAlgorithm();
            dAlgorithm = new AesAlgorithm();
            transformer = new UTF8Transformer();
            key = SecureRandom.GetRandomBytes(32);
        }

        [TestMethod]
        public void AES_Encrypting_And_Decrypting_Results_In_Same_String()
        {

            eAlgorithm.Key = key;

            byte[] ciphertext = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testClearText));
   

            dAlgorithm.Key = key;
            dAlgorithm.IV = eAlgorithm.IV;

            byte[] decryptedPlainText = decryptor.Decrypt(dAlgorithm, ciphertext);
            Assert.AreEqual(testClearText, transformer.GetString(decryptedPlainText));
        }

        [TestMethod]
        public void AES_Encrypting_And_Decrypting_String_With_ExtendedCharacters_Results_In_Same_String()
        {

            eAlgorithm.Key = key;


            byte[] ciphertext = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testClearTextWithExtendedCharacters));


            dAlgorithm.Key = key;
            dAlgorithm.IV = eAlgorithm.IV;

            byte[] decryptedPlainText = decryptor.Decrypt(dAlgorithm, ciphertext);
            Assert.AreEqual(testClearTextWithExtendedCharacters, transformer.GetString(decryptedPlainText));
        }

        [TestMethod]
        public void AES_Encrypting_And_Decrypting_String_With_Chinese_Characters_Results_In_Same_String()
        {

            eAlgorithm.Key = key;


            byte[] ciphertext = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testClearTextWithChineseCharacters));


            dAlgorithm.Key = key;
            dAlgorithm.IV = eAlgorithm.IV;

            byte[] decryptedPlainText = decryptor.Decrypt(dAlgorithm, ciphertext);
            Assert.AreEqual(testClearTextWithChineseCharacters, transformer.GetString(decryptedPlainText));
        }


        [TestMethod]
        public void AES_Decrypting_With_Incorrect_Key_Fails()
        {
            eAlgorithm.Key = key;

            byte[] ciphertext = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testClearText));


            dAlgorithm.Key = SecureRandom.GetRandomBytes(32);
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
        public void AES_Decrypting_With_Incorrect_IV_Fails()
        {
            eAlgorithm.Key = key;


            byte[] ciphertext = encryptor.Encrypt(eAlgorithm, transformer.GetBytes(testClearText));


            dAlgorithm.Key = key;
            dAlgorithm.IV = SecureRandom.GetRandomBytes(16);

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
