using System;

namespace Org.BouncyCastle.Asn1.X9
{

    public class DHPublicKey : Asn1Encodable
    {

        public DerInteger Y   { get; }

        public DHPublicKey(DerInteger y)
        {
            this.Y = y ?? throw new ArgumentNullException(nameof(y), "The given parameter 'y' must not be null!");
        }


        public static DHPublicKey GetInstance(Asn1TaggedObject obj, Boolean IsExplicit)
        {
            return GetInstance(DerInteger.GetInstance(obj, IsExplicit));
        }

        public static DHPublicKey GetInstance(object obj)
        {

            if (obj == null || obj is DHPublicKey)
                return (DHPublicKey) obj;

            if (obj is DerInteger)
                return new DHPublicKey((DerInteger)obj);

            throw new ArgumentException("Invalid DHPublicKey: " + obj.GetType().FullName, "obj");

        }

        public override Asn1Object ToAsn1Object()
            => Y;

    }

}
