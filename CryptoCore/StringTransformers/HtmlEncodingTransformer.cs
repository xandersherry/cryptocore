using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace Xeres.CryptoCore.StringTransformers
{
    public class HtmlEncodingTransformer : IStringTransformer
    {
        public string EncodingName
        {
            get { return "HtmlEncoding"; }
        }

        public byte[] GetBytes(string input)
        {
            return Encoding.UTF8.GetBytes(HttpUtility.HtmlDecode(input));
        }

        public string GetString(byte[] input)
        {
            return HttpUtility.HtmlEncode(Encoding.UTF8.GetString(input));
        }

    }
}
