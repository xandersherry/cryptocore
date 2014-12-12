using System.Security.Cryptography;

namespace Xeres.CryptoCore
{
    public static class SecureRandom
    {
        public static byte[] GetRandomBytes(int length)
        {
            byte[] randomBytes = new byte[length];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(randomBytes);
            }
            return randomBytes;
        }
    }
}
