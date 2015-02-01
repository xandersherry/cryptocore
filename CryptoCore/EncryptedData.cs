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
        public byte[] AdditionalAuthenticatedData { get; set; }
        public byte[] Ciphertext { get; set; }
        public byte[] IV { get; set; }
        public byte[] Tag { get; set; }

        public string ToString(IStringTransformer outputFormat = null, string delimiter = "", bool includeAAD = true)
        {
            if (outputFormat == null)
                outputFormat = new Base64Transformer();

            StringBuilder output = new StringBuilder();
            bool requireDelimiter = false;
            if (IV != null && IV.Length > 0)
            {
                output.Append(outputFormat.GetString(IV));
                requireDelimiter = true;
            }
            if (Tag != null && Tag.Length > 0)
            {
                if (requireDelimiter)
                    output.Append(delimiter);

                output.Append(outputFormat.GetString(Tag));
                requireDelimiter = true;
            }
            
            if (requireDelimiter)
                output.Append(delimiter);

            output.Append(outputFormat.GetString(Ciphertext));
            
            if (includeAAD && AdditionalAuthenticatedData != null && AdditionalAuthenticatedData.Length > 0)
            {
                output.Append(delimiter);
                output.Append(outputFormat.GetString(AdditionalAuthenticatedData));
            }

            return output.ToString();
        }
    }
}
