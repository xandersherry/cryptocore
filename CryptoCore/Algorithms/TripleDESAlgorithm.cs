using System;
using System.Security.Cryptography;

namespace Xeres.CryptoCore.Algorithms
{
    /// <summary>
    /// Triple-DES is a symmetric encryption algorithm included for backwards
    /// compatibility purposes only.  It should not be used for new systems 
    /// for any reason;  the AuthenticatedSymmetricEncryption API and the 
    /// algorithms it supports should be used instead.
    /// </summary>
    [Obsolete("This algorithm is obsolete. Use AuthenticatedSymmetricEncryption and one of the algorithms it supports instead.", false)]
    public class TripleDESAlgorithm : ISymmetricEncryptionAlgorithm
    {
        private TripleDESCryptoServiceProvider algorithmInstance = new TripleDESCryptoServiceProvider();

        public string AlgorithmName
        {
            get { return "TripleDES"; }
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
