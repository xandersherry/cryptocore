using System;
using System.Security.Cryptography;

namespace Xeres.CryptoCore.Algorithms
{
    /// <summary>
    /// RC2 is a symmetric encryption algorithm included for backwards
    /// compatibility purposes and only for existing systems that already use 
    /// it and cannot be updated to support a secure algorithm. It should not 
    /// be used for new systems for any reason; 
    /// the AuthenticatedSymmetricEncryption API and the algorithms it supports 
    /// should be used instead.
    /// </summary>
    [Obsolete("This algorithm is obsolete and unsafe. Use AuthenticatedSymmetricEncryption and one of the algorithms it supports instead.", false)]
    public class RC2Algorithm : ISymmetricEncryptionAlgorithm
    {
        private RC2CryptoServiceProvider algorithmInstance = new RC2CryptoServiceProvider();

        public string AlgorithmName
        {
            get { return "RC2"; }
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
