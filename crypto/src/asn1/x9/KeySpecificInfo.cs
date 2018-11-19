namespace Org.BouncyCastle.Asn1.X9
{

    /// <summary>
    /// ASN.1 def for Diffie-Hellman key exchange KeySpecificInfo structure. See
    /// RFC 2631, or X9.42, for further details.
    /// </summary>
    public class KeySpecificInfo : Asn1Encodable
    {

        public DerObjectIdentifier  Algorithm    { get; }

        public Asn1OctetString      Counter      { get; }


        public KeySpecificInfo(DerObjectIdentifier  algorithm,
                               Asn1OctetString      counter)
        {

            this.Algorithm  = algorithm;
            this.Counter    = counter;

        }

        public KeySpecificInfo(Asn1Sequence seq)
        {

            var e = seq.GetEnumerator();

            e.MoveNext();
            Algorithm = (DerObjectIdentifier) e.Current;

            e.MoveNext();
            Counter   = (Asn1OctetString) e.Current;

        }


        /// <summary>
        /// Produce an object suitable for an Asn1OutputStream.
        /// </summary>
        /// <remarks>
        /// KeySpecificInfo ::= Sequence {
        ///     algorithm OBJECT IDENTIFIER,
        ///     counter OCTET STRING SIZE (4..4)
        /// }
        /// </remarks>
        public override Asn1Object ToAsn1Object()
            => new DerSequence(Algorithm, Counter);

    }

}
