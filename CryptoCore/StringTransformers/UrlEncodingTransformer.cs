using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace Xeres.CryptoCore.StringTransformers
{
    public class UrlEncodingTransformer : IStringTransformer
    {

        public string EncodingName
        {
            get { return "UrlEncode"; }
        }

        public byte[] GetBytes(string input)
        {
            return Encoding.ASCII.GetBytes(HttpUtility.UrlDecode(input));
        }

        public string GetString(byte[] input)
        {
            return HttpUtility.UrlEncode(Encoding.ASCII.GetString(input));
        }



    }
}
