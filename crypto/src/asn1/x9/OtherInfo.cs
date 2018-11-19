using System.Collections;

namespace Org.BouncyCastle.Asn1.X9
{

    /// <summary>
    /// ANS.1 def for Diffie-Hellman key exchange OtherInfo structure. See
    /// RFC 2631, or X9.42, for further details.
    /// </summary>
    public class OtherInfo : Asn1Encodable
    {

        public KeySpecificInfo  KeyInfo        { get; }

        public Asn1OctetString  PartyAInfo     { get; }

        public Asn1OctetString  SuppPubInfo    { get; }


        public OtherInfo(KeySpecificInfo  keyInfo,
                         Asn1OctetString  partyAInfo,
                         Asn1OctetString  suppPubInfo)
        {

            this.KeyInfo      = keyInfo;
            this.PartyAInfo   = partyAInfo;
            this.SuppPubInfo  = suppPubInfo;

        }

        public OtherInfo(Asn1Sequence seq)
        {

            var e = seq.GetEnumerator();

            e.MoveNext();
            KeyInfo = new KeySpecificInfo((Asn1Sequence) e.Current);

            while (e.MoveNext())
            {

                var o = (DerTaggedObject) e.Current;

                if (o.TagNo == 0)
                    PartyAInfo = (Asn1OctetString) o.GetObject();

                else if ((int) o.TagNo == 2)
                    SuppPubInfo = (Asn1OctetString) o.GetObject();

            }

        }


        /// <summary>
        /// Produce an object suitable for an Asn1OutputStream.
        /// </summary>
        /// <remarks>
        /// OtherInfo ::= Sequence {
        ///     keyInfo KeySpecificInfo,
        ///     partyAInfo [0] OCTET STRING OPTIONAL,
        ///     suppPubInfo [2] OCTET STRING
        /// }
        /// </remarks>
        public override Asn1Object ToAsn1Object()
        {

            var v = new Asn1EncodableVector(KeyInfo);

            if (PartyAInfo != null)
                v.Add(new DerTaggedObject(0, PartyAInfo));

            v.Add(new DerTaggedObject(2, SuppPubInfo));

            return new DerSequence(v);

        }

    }

}
