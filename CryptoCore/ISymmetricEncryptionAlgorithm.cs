using System.Security.Cryptography;

namespace Xeres.CryptoCore
{
    public interface ISymmetricEncryptionAlgorithm
    {
        string AlgorithmName { get; }
        ICryptoTransform Encryptor { get; }
        ICryptoTransform Decryptor { get; }

        byte[] Key { get; set; }
        byte[] IV { get; set; }

        bool IsCngAlgorithm { get;  }
        SymmetricAlgorithm Instance { get; }
    }
}
