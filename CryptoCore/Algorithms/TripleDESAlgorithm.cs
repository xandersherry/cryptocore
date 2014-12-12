﻿using System.Security.Cryptography;

namespace Xeres.CryptoCore.Algorithms
{
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
