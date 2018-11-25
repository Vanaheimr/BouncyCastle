using System;

namespace Org.BouncyCastle.Asn1.X509
{

    /// <summary>
    /// PrivateKeyUsagePeriod
    /// </summary>
    /// <remarks>
    /// PrivateKeyUsagePeriod ::= SEQUENCE
    /// {
    ///     notBefore       [0]     GeneralizedTime OPTIONAL,
    ///     notAfter        [1]     GeneralizedTime OPTIONAL
    /// }
    /// </remarks>
    public class PrivateKeyUsagePeriod : Asn1Encodable
    {

        public DerGeneralizedTime  NotBefore    { get; }

        public DerGeneralizedTime  NotAfter     { get; }


        private PrivateKeyUsagePeriod(Asn1Sequence seq)
        {

            foreach (Asn1TaggedObject tObj in seq)
            {

                if (tObj.TagNo == 0)
                    NotBefore = DerGeneralizedTime.GetInstance(tObj, false);

                else if (tObj.TagNo == 1)
                    NotAfter  = DerGeneralizedTime.GetInstance(tObj, false);

            }

        }

        public static PrivateKeyUsagePeriod GetInstance(Object obj)
        {

            if (obj is PrivateKeyUsagePeriod)
                return (PrivateKeyUsagePeriod) obj;

            if (obj is Asn1Sequence)
                return new PrivateKeyUsagePeriod((Asn1Sequence) obj);

            if (obj is X509Extension)
                return GetInstance(X509Extension.ConvertValueToObject((X509Extension) obj));

            throw new ArgumentException("unknown object in GetInstance: " + obj.GetType().FullName, "obj");

        }

        public override Asn1Object ToAsn1Object()
        {

            var v = new Asn1EncodableVector();

            if (NotBefore != null)
                v.Add(new DerTaggedObject(false, 0, NotBefore));

            if (NotAfter != null)
                v.Add(new DerTaggedObject(false, 1, NotAfter));

            return new DerSequence(v);

        }

    }

}
