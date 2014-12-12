using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Xeres.CryptoCore.StringTransformers
{
    public class HexTransformer : IStringTransformer   
    {
        public string EncodingName
        {
            get { return "Hex"; }
        }

        public byte[] GetBytes(string input)
        {
            byte[] output = new byte[(input.Length / 2)];
            int currChar = 0;
            for (int i = 0; i < output.Length; i++)
            {
                output[i] = byte.Parse(input.Substring(currChar, 2), System.Globalization.NumberStyles.HexNumber);
                currChar += 2;
            }

            return output;
        }

        public string GetString(byte[] input)
        {
            StringBuilder output = new StringBuilder();
            for (int i = 0; i < input.Length; i++)
            {
                output.Append(input[i].ToString("X2"));
            }
            return output.ToString();
        }
    }
}
