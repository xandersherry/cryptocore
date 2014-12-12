using Security.Cryptography;

namespace Xeres.CryptoCore
{
    public interface ICngSymmetricEncryptionAlgorithm : ISymmetricEncryptionAlgorithm
    {
        CngChainingMode ChainingMode { get; set; }

        byte[] AdditionalAuthenticatedData { get; set; }

        IAuthenticatedCryptoTransform AuthenticatedEncryptor { get; }
        
        byte[] Tag { set; }
    }
}
