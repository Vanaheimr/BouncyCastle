using System;
using System.Collections;

using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Asn1.X509
{

    public class CrlEntry : Asn1Encodable
    {

        public Asn1Sequence    Seq                   { get; internal set; }
        public DerInteger      UserCertificate       { get; internal set; }
        public Time            RevocationDate        { get; internal set; }
        public X509Extensions  CrlEntryExtensions    { get; internal set; }

        public CrlEntry(Asn1Sequence seq)
        {

            if (seq.Count < 2 || seq.Count > 3)
                throw new ArgumentException("Bad sequence size: " + seq.Count);

            this.Seq = seq;

            UserCertificate  = DerInteger.GetInstance(seq[0]);
            RevocationDate   = Time.      GetInstance(seq[1]);

        }

        public X509Extensions Extensions
        {
            get
            {

                if (CrlEntryExtensions == null && Seq.Count == 3)
                    CrlEntryExtensions = X509Extensions.GetInstance(Seq[2]);

                return CrlEntryExtensions;

            }
        }

        public override Asn1Object ToAsn1Object()
            => Seq;

    }

    /**
     * PKIX RFC-2459 - TbsCertList object.
     * <pre>
     * TbsCertList  ::=  Sequence  {
     *      version                 Version OPTIONAL,
     *                                   -- if present, shall be v2
     *      signature               AlgorithmIdentifier,
     *      issuer                  Name,
     *      thisUpdate              Time,
     *      nextUpdate              Time OPTIONAL,
     *      revokedCertificates     Sequence OF Sequence  {
     *           userCertificate         CertificateSerialNumber,
     *           revocationDate          Time,
     *           crlEntryExtensions      Extensions OPTIONAL
     *                                         -- if present, shall be v2
     *                                }  OPTIONAL,
     *      crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
     *                                         -- if present, shall be v2
     *                                }
     * </pre>
     */
    public class TbsCertificateList : Asn1Encodable
    {

        private class RevokedCertificatesEnumeration
            : IEnumerable
        {
            private readonly IEnumerable en;

            internal RevokedCertificatesEnumeration(
                IEnumerable en)
            {
                this.en = en;
            }

            public IEnumerator GetEnumerator()
            {
                return new RevokedCertificatesEnumerator(en.GetEnumerator());
            }

            private class RevokedCertificatesEnumerator
                : IEnumerator
            {
                private readonly IEnumerator e;

                internal RevokedCertificatesEnumerator(
                    IEnumerator e)
                {
                    this.e = e;
                }

                public bool MoveNext()
                {
                    return e.MoveNext();
                }

                public void Reset()
                {
                    e.Reset();
                }

                public object Current
                {
                    get { return new CrlEntry(Asn1Sequence.GetInstance(e.Current)); }
                }
            }
        }


        public Int32 Version
            => VersionNumber.Value.IntValue + 1;

        public DerInteger           VersionNumber          { get; internal set; }
        public Asn1Sequence         Seq                    { get; internal set; }
        public AlgorithmIdentifier  Signature              { get; internal set; }
        public X509Name             Issuer                 { get; internal set; }
        public Time                 ThisUpdate             { get; internal set; }
        public Time                 NextUpdate             { get; internal set; }
        public Asn1Sequence         RevokedCertificates    { get; internal set; }
        public X509Extensions       Extensions             { get; internal set; }



        public static TbsCertificateList GetInstance(Asn1TaggedObject  obj,
                                                     Boolean           explicitly)

            => GetInstance(Asn1Sequence.GetInstance(obj, explicitly));


        public static TbsCertificateList GetInstance(Object obj)
        {

            var list = obj as TbsCertificateList;

            if (obj == null || list != null)
                return list;

            if (obj is Asn1Sequence)
                return new TbsCertificateList((Asn1Sequence) obj);

            throw new ArgumentException("unknown object in factory: " + obj.GetType().Name, "obj");

        }

        internal TbsCertificateList(Asn1Sequence seq)
        {

            if (seq.Count < 3 || seq.Count > 7)
                throw new ArgumentException("Bad sequence size: " + seq.Count);

            int seqPos = 0;

            this.Seq = seq;

            if (seq[seqPos] is DerInteger)
                VersionNumber = DerInteger.GetInstance(seq[seqPos++]);

            else
                VersionNumber = new DerInteger(0);

            Signature   = AlgorithmIdentifier.GetInstance(seq[seqPos++]);
            Issuer      = X509Name.           GetInstance(seq[seqPos++]);
            ThisUpdate  = Time.               GetInstance(seq[seqPos++]);

            if (seqPos < seq.Count
                && (seq[seqPos] is DerUtcTime
                   || seq[seqPos] is DerGeneralizedTime
                   || seq[seqPos] is Time))
            {
                NextUpdate = Time.GetInstance(seq[seqPos++]);
            }

            if (seqPos < seq.Count
                && !(seq[seqPos] is DerTaggedObject))
            {
                RevokedCertificates = Asn1Sequence.GetInstance(seq[seqPos++]);
            }

            if (seqPos < seq.Count
                && seq[seqPos] is DerTaggedObject)
            {
                Extensions = X509Extensions.GetInstance(seq[seqPos]);
            }

        }


        public CrlEntry[] GetRevokedCertificates()
        {

            if (RevokedCertificates == null)
                return new CrlEntry[0];

            var entries = new CrlEntry[RevokedCertificates.Count];

            for (int i = 0; i < entries.Length; i++)
                entries[i] = new CrlEntry(Asn1Sequence.GetInstance(RevokedCertificates[i]));

            return entries;

        }

        public IEnumerable GetRevokedCertificateEnumeration()
        {

            if (RevokedCertificates == null)
                return EmptyEnumerable.Instance;

            return new RevokedCertificatesEnumeration(RevokedCertificates);

        }


        public override Asn1Object ToAsn1Object()
            => Seq;

    }

}
