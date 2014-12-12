using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Xeres.CryptoCore.StringTransformers
{
    public class Base64Transformer : IStringTransformer
    {
        public string EncodingName
        {
            get { return "Base-64"; }
        }

        public byte[] GetBytes(string input)
        {
            if (input.Length % 4 != 0)
                throw new ArgumentException("The input value is not a valid Base-64 encoded string.");

            return Convert.FromBase64String(input);
        }

        public string GetString(byte[] input)
        {
            return Convert.ToBase64String(input);
        }
    }
}
