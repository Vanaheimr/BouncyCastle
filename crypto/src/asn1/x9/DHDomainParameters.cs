using System;
using System.Collections;

namespace Org.BouncyCastle.Asn1.X9
{

    public class DHDomainParameters : Asn1Encodable
    {

        public DerInteger         P                  { get; }

        public DerInteger         G                  { get; }

        public DerInteger         Q                  { get; }

        public DerInteger         J                  { get; }

        public DHValidationParms  ValidationParms    { get; }


        public DHDomainParameters(DerInteger         p,
                                  DerInteger         g,
                                  DerInteger         q,
                                  DerInteger         j,
                                  DHValidationParms  validationParms)
        {

            this.P = p ?? throw new ArgumentNullException("p");
            this.G = g ?? throw new ArgumentNullException("g");
            this.Q = q ?? throw new ArgumentNullException("q");
            this.J = j;

            this.ValidationParms = validationParms;

        }

        private DHDomainParameters(Asn1Sequence seq)
        {

            if (seq.Count < 3 || seq.Count > 5)
                throw new ArgumentException("Bad sequence size: " + seq.Count, "seq");

            IEnumerator e = seq.GetEnumerator();
            this.P = DerInteger.GetInstance(GetNext(e));
            this.G = DerInteger.GetInstance(GetNext(e));
            this.Q = DerInteger.GetInstance(GetNext(e));

            var next = GetNext(e);

            if (next != null && next is DerInteger)
            {
                this.J = DerInteger.GetInstance(next);
                next = GetNext(e);
            }

            if (next != null)
                this.ValidationParms = DHValidationParms.GetInstance(next.ToAsn1Object());

        }



        public static DHDomainParameters GetInstance(Asn1TaggedObject obj, Boolean IsExplicit)

            => GetInstance(Asn1Sequence.GetInstance(obj, IsExplicit));

        public static DHDomainParameters GetInstance(object obj)
        {

            if (obj == null || obj is DHDomainParameters)
                return (DHDomainParameters)obj;

            if (obj is Asn1Sequence)
                return new DHDomainParameters((Asn1Sequence)obj);

            throw new ArgumentException("Invalid DHDomainParameters: " + obj.GetType().FullName, "obj");

        }

        private static Asn1Encodable GetNext(IEnumerator e)

            => e.MoveNext() ? (Asn1Encodable)e.Current : null;



        public override Asn1Object ToAsn1Object()
        {

            var v = new Asn1EncodableVector(P, G, Q);

            if (this.J != null)
                v.Add(this.J);

            if (this.ValidationParms != null)
                v.Add(this.ValidationParms);

            return new DerSequence(v);

        }

    }

}
