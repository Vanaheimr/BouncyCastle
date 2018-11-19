using System;

using Org.BouncyCastle.Asn1.Pkcs;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * The TbsCertificate object.
     * <pre>
     * TbsCertificate ::= Sequence {
     *      version          [ 0 ]  Version DEFAULT v1(0),
     *      serialNumber            CertificateSerialNumber,
     *      signature               AlgorithmIdentifier,
     *      issuer                  Name,
     *      validity                Validity,
     *      subject                 Name,
     *      subjectPublicKeyInfo    SubjectPublicKeyInfo,
     *      issuerUniqueID    [ 1 ] IMPLICIT UniqueIdentifier OPTIONAL,
     *      subjectUniqueID   [ 2 ] IMPLICIT UniqueIdentifier OPTIONAL,
     *      extensions        [ 3 ] Extensions OPTIONAL
     *      }
     * </pre>
     * <p>
     * Note: issuerUniqueID and subjectUniqueID are both deprecated by the IETF. This class
     * will parse them, but you really shouldn't be creating new ones.</p>
     */
    public class TbsCertificateStructure : Asn1Encodable
    {

        public Int32 Version
            => VersionNumber.Value.IntValue + 1;

        public DerInteger              VersionNumber           { get; internal set; }
        public Asn1Sequence            Seq                     { get; internal set; }
        public DerInteger              SerialNumber            { get; internal set; }
        public AlgorithmIdentifier     Signature               { get; internal set; }
        public X509Name                Issuer                  { get; internal set; }
        public Time                    StartDate               { get; internal set; }
        public Time                    EndDate                 { get; internal set; }
        public X509Name                Subject                 { get; internal set; }
        public SubjectPublicKeyInfo    SubjectPublicKeyInfo    { get; internal set; }
        public DerBitString            IssuerUniqueID          { get; internal set; }
        public DerBitString            SubjectUniqueID         { get; internal set; }
        public X509Extensions          Extensions              { get; internal set; }

        public static TbsCertificateStructure GetInstance(Asn1TaggedObject  obj,
                                                          Boolean           explicitly)

            => GetInstance(Asn1Sequence.GetInstance(obj, explicitly));


        public static TbsCertificateStructure GetInstance(object obj)
        {

            if (obj is TbsCertificateStructure)
                return (TbsCertificateStructure) obj;

            if (obj != null)
                return new TbsCertificateStructure(Asn1Sequence.GetInstance(obj));

            return null;

        }

        internal TbsCertificateStructure(Asn1Sequence seq)
        {

            int seqStart = 0;

            this.Seq = seq;

            // Some certficates don't include a version number - we assume v1
            if (seq[0] is DerTaggedObject)
                VersionNumber = DerInteger.GetInstance((Asn1TaggedObject)seq[0], true);

            else
            {
                seqStart      = -1;          // field 0 is missing!
                VersionNumber = new DerInteger(0);
            }

            SerialNumber = DerInteger.         GetInstance(seq[seqStart + 1]);
            Signature    = AlgorithmIdentifier.GetInstance(seq[seqStart + 2]);
            Issuer       = X509Name.           GetInstance(seq[seqStart + 3]);

            // before and after dates
            var dates = (Asn1Sequence) seq[seqStart + 4];

            StartDate    = Time.               GetInstance(dates[0]);
            EndDate      = Time.               GetInstance(dates[1]);
            Subject      = X509Name.           GetInstance(seq[seqStart + 5]);

            // public key info.
            SubjectPublicKeyInfo = SubjectPublicKeyInfo.GetInstance(seq[seqStart + 6]);

            for (int extras = seq.Count - (seqStart + 6) - 1; extras > 0; extras--)
            {

                var extra = (DerTaggedObject) seq[seqStart + 6 + extras];

                switch (extra.TagNo)
                {
                    case 1:
                        IssuerUniqueID = DerBitString.GetInstance(extra, false);
                        break;
                    case 2:
                        SubjectUniqueID = DerBitString.GetInstance(extra, false);
                        break;
                    case 3:
                        Extensions = X509Extensions.GetInstance(extra);
                        break;
                }

            }

        }


        public override Asn1Object ToAsn1Object()
            => Seq;

    }

}
