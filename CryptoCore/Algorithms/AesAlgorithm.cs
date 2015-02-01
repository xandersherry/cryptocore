using System.Security.Cryptography;

namespace Xeres.CryptoCore.Algorithms
{
    /// <summary>
    /// AES is an authenticated algorithm, protecting message integrity through
    /// the use of encrypt-then-MAC using a configurable HMAC variant.  The 
    /// default configuration uses HMAC-SHA256.  
    /// </summary>
    public class AesAlgorithm : ISymmetricEncryptionAlgorithm
    {
        private AesCryptoServiceProvider algorithmInstance = new AesCryptoServiceProvider();
        public string AlgorithmName
        {
            get { return "AES"; }
        }

        public ICryptoTransform Encryptor
        {
            get { return algorithmInstance.CreateEncryptor(); }
        }

        public ICryptoTransform Decryptor
        {
            get { return algorithmInstance.CreateDecryptor(); }
        }

        public byte[] Key
        {
            get { return algorithmInstance.Key; }
            set { algorithmInstance.Key = value; }
        }

        
        public byte[] IV
        {
            get { return algorithmInstance.IV; }
            set { algorithmInstance.IV = value; }
        }

        public CipherMode Mode
        {
            get { return algorithmInstance.Mode; }
            set { algorithmInstance.Mode = value; }
        }

        public bool IsCngAlgorithm
        {
            get { return false; }
        }
        public SymmetricAlgorithm Instance
        {
            get { return algorithmInstance; }
        }
    }
}
