using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xeres.CryptoCore.Algorithms;
using Xeres.CryptoCore.StringTransformers;

namespace Xeres.CryptoCore
{
    public static class SimpleEncryption
    {
        private const int IV_LENGTH = 12;
        private const int TAG_LENGTH = 16;
        private const int KEY_LENGTH = 32;

        /// <summary>
        /// Generates a new random, Base-64 encoded, 256-bit key
        /// </summary>
        /// <returns>Base-64 encoded string</returns>
        public static string GenerateKey()
        {
            return Convert.ToBase64String(SecureRandom.GetRandomBytes(KEY_LENGTH));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="key">A Base-64 encoded, 256-bit key</param>
        /// <param name="plaintext">A UTF-8 string that is the plaintext message to be encrypted</param>
        /// <returns>Base-64 encoded string that includes an IV, a tag, and the ciphertext of the data encrypted with the key</returns>
        public static string Encrypt(string key, string plaintext)
        {
            AuthenticatedAesAlgorithm algorithm = new AuthenticatedAesAlgorithm();
            AuthenticatedSymmetricEncryption encryptor = new AuthenticatedSymmetricEncryption();
            UTF8Transformer transformer = new UTF8Transformer();
            
            algorithm.Key = Convert.FromBase64String(key);
            algorithm.IV = SecureRandom.GetRandomBytes(IV_LENGTH);

            byte[] encryptedMessage = encryptor.Encrypt(algorithm, transformer.GetBytes(plaintext));
            byte[] tag = encryptor.GetTag();

            byte[] output = new byte[algorithm.IV.Length + tag.Length + encryptedMessage.Length];
            Buffer.BlockCopy(algorithm.IV, 0, output, 0, algorithm.IV.Length);
            Buffer.BlockCopy(tag, 0, output, algorithm.IV.Length, tag.Length);
            Buffer.BlockCopy(encryptedMessage, 0, output, algorithm.IV.Length + tag.Length, encryptedMessage.Length);

            return Convert.ToBase64String(output);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="key">A Base-64 encoded, 256-bit key</param>
        /// <param name="encryptedData">The Base-64 encoded string containing the IV, tag, and ciphertext</param>
        /// <returns>A UTF-8 string containing the plaintext message</returns>
        public static string Decrypt(string key, string encryptedData)
        {
            byte[] input = Convert.FromBase64String(encryptedData);

            byte[] iv = new byte[IV_LENGTH];
            byte[] tag = new byte[TAG_LENGTH];
            byte[] ciphertext = new byte[input.Length - (IV_LENGTH + TAG_LENGTH)];

            Buffer.BlockCopy(input, 0, iv, 0, IV_LENGTH);
            Buffer.BlockCopy(input, IV_LENGTH, tag, 0, TAG_LENGTH);
            Buffer.BlockCopy(input, (IV_LENGTH + TAG_LENGTH), ciphertext, 0, ciphertext.Length);

            AuthenticatedAesAlgorithm algorithm = new AuthenticatedAesAlgorithm();
            AuthenticatedSymmetricEncryption decryptor = new AuthenticatedSymmetricEncryption();
            UTF8Transformer transformer = new UTF8Transformer();

            algorithm.Key = Convert.FromBase64String(key);
            algorithm.IV = iv;
            algorithm.Tag = tag;

            return transformer.GetString(decryptor.Decrypt(algorithm, ciphertext));
            
        }


    }
}
