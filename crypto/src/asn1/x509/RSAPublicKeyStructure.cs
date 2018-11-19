using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.X509
{

    public class RsaPublicKeyStructure : Asn1Encodable
    {

        public BigInteger Modulus          { get; }

        public BigInteger PublicExponent   { get; }



        public static RsaPublicKeyStructure GetInstance(Asn1TaggedObject  obj,
                                                        Boolean           explicitly)
        {
            return GetInstance(Asn1Sequence.GetInstance(obj, explicitly));
        }

        public static RsaPublicKeyStructure GetInstance(Object  obj)
        {

            if (obj == null || obj is RsaPublicKeyStructure)
            {
                return (RsaPublicKeyStructure) obj;
            }

            if (obj is Asn1Sequence)
            {
                return new RsaPublicKeyStructure((Asn1Sequence) obj);
            }

            throw new ArgumentException("Invalid RsaPublicKeyStructure: " + obj.GetType().Name);

        }

        public RsaPublicKeyStructure(BigInteger  modulus,
                                     BigInteger  publicExponent)
        {

            if (modulus == null)
                throw new ArgumentNullException(nameof(modulus),         "The given modulus must not be null!");

            if (publicExponent == null)
                throw new ArgumentNullException(nameof(publicExponent),  "The given publicExponent must not be null!");

            if (modulus.SignValue <= 0)
                throw new ArgumentException("Not a valid RSA modulus",          nameof(modulus));

            if (publicExponent.SignValue <= 0)
                throw new ArgumentException("Not a valid RSA public exponent",  nameof(publicExponent));


            this.Modulus         = modulus;
            this.PublicExponent  = publicExponent;

        }

        private RsaPublicKeyStructure(Asn1Sequence seq)
        {

            if (seq == null)
                throw new ArgumentNullException(nameof(seq), "The given sequence must not be null!");

            if (seq.Count != 2)
                throw new ArgumentException("Bad sequence size: " + seq.Count);

            // Note: we are accepting technically incorrect (i.e. negative) values here
            Modulus         = DerInteger.GetInstance(seq[0]).PositiveValue;
            PublicExponent  = DerInteger.GetInstance(seq[1]).PositiveValue;

        }


        /// <summary>
        /// This outputs the key in Pkcs1v2 format.
        /// </summary>
        /// <remarks>
        /// RSAPublicKey ::= Sequence {
        ///                     modulus Integer, -- n
        ///                     publicExponent Integer, -- e
        ///                 }
        /// </remarks>
        public override Asn1Object ToAsn1Object()

            => new DerSequence(new DerInteger(Modulus),
                               new DerInteger(PublicExponent));

    }
}
