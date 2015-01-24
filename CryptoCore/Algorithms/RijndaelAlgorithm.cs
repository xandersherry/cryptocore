using System.Security.Cryptography;

namespace Xeres.CryptoCore.Algorithms
{
    /// <summary>
    /// Rijndeal is a symmetric encryption algorithm, and this un-authenticated
    /// form is included for backwards compatibility purposes only.  It should 
    /// not be used for new systems unless a suitable  authentication mechanism 
    /// is also implemented and used to ensure message integrity.  Generally 
    /// the AuthenticatedSymmetricEncryption API and the algorithms it supports
    /// should be used instead.
    /// </summary>
    public class RijndaelAlgorithm : ISymmetricEncryptionAlgorithm
    {
        private RijndaelManaged algorithmInstance = new RijndaelManaged();
        
        public string AlgorithmName
        {
            get { return "Rijndael"; }
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
            get
            {
                return algorithmInstance.Key;
            }
            set
            {
                algorithmInstance.Key = value;
            }
        }

        public byte[] IV
        {
            get
            {
                return algorithmInstance.IV;
            }
            set
            {
                algorithmInstance.IV = value;
            }
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
