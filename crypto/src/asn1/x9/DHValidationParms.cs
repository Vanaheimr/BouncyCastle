using System;

namespace Org.BouncyCastle.Asn1.X9
{

    public class DHValidationParms : Asn1Encodable
    {

        public DerBitString  Seed           { get; }

        public DerInteger    PgenCounter    { get; }


        public static DHValidationParms GetInstance(Asn1TaggedObject obj, Boolean IsExplicit)

            => GetInstance(Asn1Sequence.GetInstance(obj, IsExplicit));

        public static DHValidationParms GetInstance(object obj)
        {

            if (obj == null || obj is DHDomainParameters)
                return (DHValidationParms)obj;

            if (obj is Asn1Sequence)
                return new DHValidationParms((Asn1Sequence)obj);

            throw new ArgumentException("Invalid DHValidationParms: " + obj.GetType().FullName, "obj");

        }

        public DHValidationParms(DerBitString seed, DerInteger pgenCounter)
        {

            this.Seed         = seed        ?? throw new ArgumentNullException("seed");
            this.PgenCounter  = pgenCounter ?? throw new ArgumentNullException("pgenCounter");

        }

        private DHValidationParms(Asn1Sequence seq)
        {

            if (seq.Count != 2)
                throw new ArgumentException("Bad sequence size: " + seq.Count, "seq");

            this.Seed         = DerBitString.GetInstance(seq[0]);
            this.PgenCounter  = DerInteger.GetInstance(seq[1]);

        }


        public override Asn1Object ToAsn1Object()
            => new DerSequence(Seed, PgenCounter);

    }

}
