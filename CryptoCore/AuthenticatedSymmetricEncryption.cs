using System;
using System.IO;
using System.Security.Cryptography;
using Security.Cryptography;

namespace Xeres.CryptoCore
{
    /// <summary>
    /// AuthenticatedSymmetricEncryption is the API for authenticated 
    /// symmetric encrpytion, and is the preferred API when you require
    /// more flexibility than is provided by the SimpleEncryption API. 
    /// </summary>
    public class AuthenticatedSymmetricEncryption : SymmetricEncryption
    {

        public AuthenticatedSymmetricEncryption()
        {
            HMACAlgorithm = new HMACSHA256();
        }

        public override byte[] Encrypt(ISymmetricEncryptionAlgorithm algorithm, byte[] plaintext)
        {
            byte[] encryptedData;
            if (algorithm.IsCngAlgorithm)
            {
                ICngSymmetricEncryptionAlgorithm internalAlgorithm = (ICngSymmetricEncryptionAlgorithm) algorithm;
                using (MemoryStream memStreamEncryptedData = new MemoryStream())
                {
                    using (IAuthenticatedCryptoTransform transform = internalAlgorithm.AuthenticatedEncryptor)
                    {
                        using (CryptoStream encStream = new CryptoStream(memStreamEncryptedData,
                            transform, CryptoStreamMode.Write))
                        {
                            try
                            {
                                encStream.Write(plaintext, 0, plaintext.Length);
                            }
                            catch (Exception ex)
                            {
                                throw new Exception("Error while writing encrypted data to the stream: \n"
                                                    + ex.Message);
                            }
                            encStream.FlushFinalBlock();
                            encStream.Close();
                            encryptedData = memStreamEncryptedData.ToArray();
                        }
                        _tag = transform.GetTag();
                    }
                }
            }
            else
            {
                encryptedData = base.Encrypt(algorithm, plaintext);

                using (HMACAlgorithm)
                {
                    byte[] messageToMac = new byte[algorithm.IV.Length + encryptedData.Length];
                    Buffer.BlockCopy(algorithm.IV, 0, messageToMac, 0, algorithm.IV.Length);
                    Buffer.BlockCopy(encryptedData, 0, messageToMac, algorithm.IV.Length, encryptedData.Length);
                    _tag = HMACAlgorithm.ComputeHash(messageToMac);
                }
            }

            return encryptedData;
        }

        public override byte[] Decrypt(ISymmetricEncryptionAlgorithm algorithm, byte[] ciphertext)
        {
            if (algorithm.IsCngAlgorithm)
            {
                ICngSymmetricEncryptionAlgorithm internalAlgorithm = (ICngSymmetricEncryptionAlgorithm) algorithm;
                using (MemoryStream memStreamDecryptedData = new MemoryStream())
                {
                    using (ICryptoTransform transform = internalAlgorithm.Decryptor)
                    {
                        using (CryptoStream decStream = new CryptoStream(memStreamDecryptedData,
                            transform, CryptoStreamMode.Write))
                        {
                            try
                            {
                                decStream.Write(ciphertext, 0, ciphertext.Length);
                            }
                            catch (Exception ex)
                            {
                                throw new Exception("Error while writing decrypted data to the 	stream: \n"
                                                    + ex.Message);
                            }
                            decStream.FlushFinalBlock();
                            decStream.Close();
                            return memStreamDecryptedData.ToArray();
                        }
                    }
                }
            }
            else
            {
                using (HMACAlgorithm)
                {
                    byte[] iv = algorithm.IV;
                    byte[] messageToMac = new byte[iv.Length + ciphertext.Length];
                    Buffer.BlockCopy(iv, 0, messageToMac, 0, iv.Length);
                    Buffer.BlockCopy(ciphertext, 0, messageToMac, iv.Length, ciphertext.Length);

                    byte[] calculatedHMAC = HMACAlgorithm.ComputeHash(messageToMac);

                    // Constant time comparison.  Very important.  Do not short-circuit to speed up. -XS
                    bool match = true;
                    for (int i = 0; i < _tag.Length; i++)
                        match = match & _tag[i] == calculatedHMAC[i]; //uses non-shortcircuit and (&)
                    //    if message doesn't authenticate throw an error
                    if (!match)
                        throw new CryptographicException("The HMAC did not validate. Decryption cannot continue.");

                }
                return base.Decrypt(algorithm, ciphertext);
            }

            return null;
        }

        private byte[] _tag;
        public byte[] Tag { set { _tag = value; }}
        public byte[] GetTag()
        {
            return _tag;
        }

        public HMAC HMACAlgorithm { get; set; }

    }
}
