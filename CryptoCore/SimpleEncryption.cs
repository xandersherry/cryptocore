using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xeres.CryptoCore.Algorithms;
using Xeres.CryptoCore.StringTransformers;

namespace Xeres.CryptoCore
{
    /// <summary>
    /// The SimpleEncryption API provides the simplest way to securely encrypt
    /// and decrypt data for use in a .NET application.  It provides 
    /// authenticated encryption to ensure both the confidentially and integrity
    /// of messages protected by this API.  
    /// </summary>
    public static class SimpleEncryption
    {
        private const ushort CURRENT_VERSION = 1;
        private const int VERSION_LENGTH = 2;  
        private const int IV_LENGTH = 12;
        private const int TAG_LENGTH = 16;
        private const int KEY_LENGTH = 16;

        /// <summary>
        /// Generates a new random, Base-64 encoded, 128-bit key
        /// </summary>
        /// <returns>Base-64 encoded string</returns>
        public static string GenerateKey()
        {
            return Convert.ToBase64String(SecureRandom.GetRandomBytes(KEY_LENGTH));
        }

        /// <summary>
        /// Encrypts textual data. Submit any UTF-8 (or ASCII) plaintext string and a strong random key for encryption. 
        /// </summary>
        /// <param name="key">A Base-64 encoded, 128-bit key</param>
        /// <param name="plaintext">A UTF-8 string that is the plaintext message to be encrypted</param>
        /// <returns>Base-64 encoded string that includes a version, an IV, a tag, and the ciphertext of the data encrypted with the key</returns>
        public static string Encrypt(string key, string plaintext)
        {
            return Encrypy(key, new UTF8Transformer().GetBytes(plaintext));
        }

        /// <summary>
        /// Encrypts binary data. Submit any data as a byte array, and a strong random key to encrypt it. 
        /// </summary>
        /// <param name="key">A Base-64 encoded, 128-bit key</param>
        /// <param name="dataToEncrypt">Base-64 encoded string that includes a version, an IV, a tag, and the ciphertext of the data encrypted with the key</param>
        /// <returns></returns>
        public static string Encrypy(string key, byte[] dataToEncrypt)
        {
            AuthenticatedAesAlgorithm algorithm = new AuthenticatedAesAlgorithm();
            AuthenticatedSymmetricEncryption encryptor = new AuthenticatedSymmetricEncryption();
            
            algorithm.Key = Convert.FromBase64String(key);
            algorithm.AdditionalAuthenticatedData = BitConverter.GetBytes(CURRENT_VERSION);

            EncryptedData encryptedData = encryptor.Encrypt(algorithm, dataToEncrypt); 

            byte[] output = new byte[VERSION_LENGTH + IV_LENGTH + TAG_LENGTH + encryptedData.Ciphertext.Length];
            Buffer.BlockCopy(BitConverter.GetBytes(CURRENT_VERSION), 0, output, 0, VERSION_LENGTH);
            Buffer.BlockCopy(encryptedData.IV, 0, output, VERSION_LENGTH, IV_LENGTH);
            Buffer.BlockCopy(encryptedData.Tag, 0, output, VERSION_LENGTH + IV_LENGTH, TAG_LENGTH);
            Buffer.BlockCopy(encryptedData.Ciphertext, 0, output, VERSION_LENGTH + IV_LENGTH + TAG_LENGTH, encryptedData.Ciphertext.Length);

            return Convert.ToBase64String(output);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="key">A Base-64 encoded, 128-bit key</param>
        /// <param name="encryptedData">The Base-64 encoded string containing the IV, tag, and ciphertext</param>
        /// <returns>A UTF-8 string containing the plaintext message</returns>
        public static string Decrypt(string key, string encryptedData)
        {
            byte[] input = Convert.FromBase64String(encryptedData);
            byte[] versionBytes = new byte[VERSION_LENGTH];
            byte[] iv = new byte[IV_LENGTH];
            byte[] tag = new byte[TAG_LENGTH];
            byte[] ciphertext = new byte[input.Length - (VERSION_LENGTH + IV_LENGTH + TAG_LENGTH)];

            Buffer.BlockCopy(input, 0, versionBytes, 0, VERSION_LENGTH);
            Buffer.BlockCopy(input, VERSION_LENGTH, iv, 0, IV_LENGTH);
            Buffer.BlockCopy(input, VERSION_LENGTH + IV_LENGTH, tag, 0, TAG_LENGTH);
            Buffer.BlockCopy(input, VERSION_LENGTH + IV_LENGTH + TAG_LENGTH, ciphertext, 0, ciphertext.Length);

            AuthenticatedAesAlgorithm algorithm = new AuthenticatedAesAlgorithm();
            AuthenticatedSymmetricEncryption decryptor = new AuthenticatedSymmetricEncryption();
            UTF8Transformer transformer = new UTF8Transformer();

            algorithm.Key = Convert.FromBase64String(key);
            algorithm.IV = iv;
            algorithm.Tag = tag;
            algorithm.AdditionalAuthenticatedData = versionBytes;

            return transformer.GetString(decryptor.Decrypt(algorithm, ciphertext));   
        }
    }
}
