using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Xeres.CryptoCore.StringTransformers
{
    public class UTF8Transformer : IStringTransformer
    {
        public string EncodingName
        {
            get { return "UTF-8"; }
        }

        public byte[] GetBytes(string input)
        {
            return Encoding.UTF8.GetBytes(input);
        }

        public string GetString(byte[] input)
        {
            return Encoding.UTF8.GetString(input);
        }
    }
}
