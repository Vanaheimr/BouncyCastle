using System;
using System.Linq;
using System.Text;

namespace Org.BouncyCastle.Utilities
{

    /// <summary>
    /// General string utilities.
    /// </summary>
    public abstract class Strings
    {

        internal static Boolean IsOneOf(String StringValue, params String[] Candidates)
        {
            return Candidates.Any(v => v == StringValue);
        }

        public static String FromByteArray(Byte[] ByteArray)
        {
            return new String(ByteArray.Select(v => Convert.ToChar(v)).ToArray());
        }

        public static Byte[] ToByteArray(Char[] CharArray)
        {
            return CharArray.Select(v => Convert.ToByte(v)).ToArray();
        }

        public static Byte[] ToByteArray(String StringValue)
        {
            return StringValue.Select(v => Convert.ToByte(v)).ToArray();
        }

        public static String FromAsciiByteArray(Byte[] ByteArray)
        {
            return Encoding.ASCII.GetString(ByteArray, 0, ByteArray.Length);
        }

        public static Byte[] ToAsciiByteArray(Char[] CharArray)
        {
            return Encoding.ASCII.GetBytes(CharArray);
        }

        public static Byte[] ToAsciiByteArray(String StringValue)
        {
            return Encoding.ASCII.GetBytes(StringValue);
        }

    }

}
