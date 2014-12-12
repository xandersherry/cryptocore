using System;
using System.Security.Cryptography;
using ClrSecurity = Security.Cryptography;

namespace Xeres.CryptoCore.Algorithms
{
    public class AuthenticatedAesAlgorithm : ICngSymmetricEncryptionAlgorithm
    {
        private ClrSecurity.AuthenticatedAesCng algorithmInstance = new ClrSecurity.AuthenticatedAesCng();
        public string AlgorithmName
        {
            get { return "AuthenticatedAES"; }
        }

        public ClrSecurity.CngChainingMode ChainingMode
        {
            get { return algorithmInstance.CngMode; }
            set { algorithmInstance.CngMode = value; }
        }
        public ClrSecurity.IAuthenticatedCryptoTransform AuthenticatedEncryptor
        {
            get { return algorithmInstance.CreateAuthenticatedEncryptor(); }
        }

        public byte[] AdditionalAuthenticatedData
        {
            get { return algorithmInstance.AuthenticatedData; }
            set { algorithmInstance.AuthenticatedData = value; }
        }

        public ICryptoTransform Encryptor
        {
            get { throw new MethodAccessException("The default encryptor is not used for Authenticated AES.  Use the AuthenticatedEncryptor instead."); }
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

        public bool IsCngAlgorithm
        {
            get { return true; }
        }

        public byte[] Tag
        {
            set { algorithmInstance.Tag = value; }
        }

        public SymmetricAlgorithm Instance
        {
            get { return algorithmInstance; }
        }
    }
}
