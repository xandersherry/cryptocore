using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Xeres.CryptoCore.StringTransformers;

namespace CryptoCoreTests.StringTransformerTests
{
    [TestClass]
    public class Utf8TransformerTests
    {
        [TestMethod]
        public void Utf8_transform_a_simple_string_to_bytearray_and_back_results_in_same_string()
        {
            string testString = "This is a test string without extended characters.";
            UTF8Transformer transformer = new UTF8Transformer();

            byte[] intermediateBytes = transformer.GetBytes(testString);
            string result = transformer.GetString(intermediateBytes);

            Assert.AreEqual(testString, result);
        }

        [TestMethod]
        public void Utf8_transform_a_string_with_extended_characters_to_bytearray_and_back_results_in_same_string()
        {
            string testString = "This is å test string with ëxteñded charactérs.";
            UTF8Transformer transformer = new UTF8Transformer();

            byte[] intermediateBytes = transformer.GetBytes(testString);
            string result = transformer.GetString(intermediateBytes);

            Assert.AreEqual(testString, result);
        }

        [TestMethod]
        public void Utf8_transform_a_string_with_Chinese_characters_to_bytearray_and_back_results_in_same_string()
        {
            string testString = "这是额外的扩展字符集的测试字符串中国人。";
            UTF8Transformer transformer = new UTF8Transformer();

            byte[] intermediateBytes = transformer.GetBytes(testString);
            string result = transformer.GetString(intermediateBytes);

            Assert.AreEqual(testString, result);
        }
    }


}
