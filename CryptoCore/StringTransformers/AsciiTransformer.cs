using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Xeres.CryptoCore.StringTransformers
{
    public class AsciiTransformer : IStringTransformer
    {
        public string EncodingName
        {
            get { return "ASCII"; }
        }

        public byte[] GetBytes(string input)
        {
            return Encoding.ASCII.GetBytes(input);
        }

        public string GetString(byte[] input)
        {
            return System.Text.Encoding.ASCII.GetString(input);
        }
    }
}
