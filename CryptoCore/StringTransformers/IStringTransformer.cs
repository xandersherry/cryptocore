using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Xeres.CryptoCore.StringTransformers
{
    public interface IStringTransformer
    {
        string EncodingName { get; }
        byte[] GetBytes(string input);
        string GetString(byte[] input);
    }
}
