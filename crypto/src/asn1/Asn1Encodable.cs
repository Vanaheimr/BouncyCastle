using System;
using System.IO;

namespace Org.BouncyCastle.Asn1
{

    public abstract class Asn1Encodable : IAsn1Convertible
    {

        public const String Der = "DER";
        public const String Ber = "BER";

        public Byte[] GetEncoded()
        {

            var bOut = new MemoryStream();
            var aOut = new Asn1OutputStream(bOut);

            aOut.WriteObject(this);

            return bOut.ToArray();

        }

        public Byte[] GetEncoded(String encoding)
        {

            if (encoding.Equals(Der))
            {

                var bOut = new MemoryStream();
                var dOut = new DerOutputStream(bOut);

                dOut.WriteObject(this);

                return bOut.ToArray();

            }

            return GetEncoded();

        }

        /// <summary>
        /// Return the DER encoding of the object, null if the DER encoding can not be made.
        /// </summary>
        /// <returns>A DER byte array, null otherwise.</returns>
        public Byte[] GetDerEncoded()
        {
            try
            {
                return GetEncoded(Der);
            }
            catch (IOException)
            {
                return null;
            }
        }

        public sealed override Int32 GetHashCode()
        {
            return ToAsn1Object().CallAsn1GetHashCode();
        }

        public sealed override Boolean Equals(Object obj)
        {

            if (obj == this)
                return true;

            if (!(obj is IAsn1Convertible other))
                return false;

            var o1 = ToAsn1Object();
            var o2 = other.ToAsn1Object();

            return o1 == o2 || o1.CallAsn1Equals(o2);

        }

        public abstract Asn1Object ToAsn1Object();

    }

}
