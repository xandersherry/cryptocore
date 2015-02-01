using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Xeres.CryptoCore
{
    /// <summary>
    /// The SymmetricEncryption API is generally for backwards compatibility
    /// purposes only.  It is an API for un-authenticated symmetric encryption
    /// which means that in order to implemented it securely an authentication
    /// mechananism to ensure message integrity must also be implemented and 
    /// used.
    /// You should generally prefer to use the AuthenticatedSymmetricEncryption
    /// API instead, which integrates message authentication automatically.
    /// </summary>
    public class SymmetricEncryption
    {
        public virtual EncryptedData Encrypt(ISymmetricEncryptionAlgorithm algorithm, byte[] plaintext)
        {
            algorithm.Instance.GenerateIV();
            EncryptedData encryptedData = new EncryptedData(){ IV = algorithm.IV};

            using (MemoryStream memStreamEncryptedData = new MemoryStream())
            {

                using (ICryptoTransform transform = algorithm.Encryptor)
                {
                   using( CryptoStream encStream = new CryptoStream(memStreamEncryptedData,
                        transform, CryptoStreamMode.Write)) { 
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
                            encryptedData.Ciphertext = memStreamEncryptedData.ToArray();
                            return encryptedData;
                        }
                }
            }
        }

        public virtual byte[] Decrypt(ISymmetricEncryptionAlgorithm algorithm, byte[] ciphertext)
        {
            using (MemoryStream memStreamDecryptedData = new MemoryStream())
            {
                using (ICryptoTransform transform = algorithm.Decryptor)
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
    }
}
