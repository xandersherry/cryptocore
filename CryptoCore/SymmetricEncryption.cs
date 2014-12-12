using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Xeres.CryptoCore
{
    public class SymmetricEncryption
    {
        public virtual byte[] Encrypt(ISymmetricEncryptionAlgorithm algorithm, byte[] plaintext)
        {
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
                        return memStreamEncryptedData.ToArray();
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
