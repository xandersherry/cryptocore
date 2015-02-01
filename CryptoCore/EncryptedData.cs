using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xeres.CryptoCore.StringTransformers;

namespace Xeres.CryptoCore
{
    public class EncryptedData
    {
        public byte[] Ciphertext { get; set; }
        public byte[] IV { get; set; }
        public byte[] Tag { get; set; }

        public string ToString(IStringTransformer outputFormat = null, string delimiter = "")
        {
            if (outputFormat == null)
                outputFormat = new Base64Transformer();

            StringBuilder output = new StringBuilder();
            output.Append(outputFormat.GetString(IV));
            output.Append(delimiter);
            output.Append(outputFormat.GetString(Tag));
            output.Append(delimiter);
            output.Append(outputFormat.GetString(Ciphertext));

            return output.ToString();
        }
    }
}
