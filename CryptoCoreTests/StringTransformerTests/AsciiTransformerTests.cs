using System;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Xeres.CryptoCore.StringTransformers;

namespace CryptoCoreTests.StringTransformerTests
{
    [TestClass]
    public class AsciiTransformerTests
    {   private byte[] testBytes = new byte[12]{84, 101, 115, 116, 32, 115, 116, 114, 105, 110, 103, 46};
        private string testString = "Test string.";


        [TestMethod]
        public void Ascii_baseline_ensure_testBytes_equals_testString()
        {
            string result = string.Empty;
            for (int i = 0; i < testBytes.Length; i++)
            {
                char currentCharacter = (char)testBytes[i];
                result += currentCharacter.ToString();
            }

            Assert.AreEqual(testString, result);
        }

        [TestMethod]
        public void Ascii_transform_bytes_results_in_correct_string()
        {
            AsciiTransformer transformer = new AsciiTransformer();
            string result = transformer.GetString(testBytes);

            Assert.AreEqual(testString, result);
        }

        [TestMethod]
        public void Ascii_transform_string_results_in_correct_bytearray()
        {
            AsciiTransformer transformer = new AsciiTransformer();
            byte[] result = transformer.GetBytes(testString);

            Assert.AreEqual(testString.Length, result.Length);
            Assert.IsTrue(result.SequenceEqual(testBytes));
        }

    }
}

