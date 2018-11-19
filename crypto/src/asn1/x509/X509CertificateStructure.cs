using System;

using Org.BouncyCastle.Asn1.Pkcs;

namespace Org.BouncyCastle.Asn1.X509
{

    /// <summary>
    /// An X509Certificate structure.
    /// </summary>
    /// <remarks>
    /// Certificate ::= Sequence {
    ///     tbsCertificate          TbsCertificate,
    ///     signatureAlgorithm      AlgorithmIdentifier,
    ///     signature               BIT STRING
    /// }
    /// </remarks>
    public class X509CertificateStructure : Asn1Encodable
    {

        public TbsCertificateStructure  TbsCertificate        { get; }

        public AlgorithmIdentifier      SignatureAlgorithm    { get; }

        public DerBitString             Signature             { get; }



        public int Version
            => TbsCertificate.Version;

        public DerInteger SerialNumber
            => TbsCertificate?.SerialNumber;

        public X509Name Issuer
            => TbsCertificate?.Issuer;

        public Time StartDate
            => TbsCertificate?.StartDate;

        public Time EndDate
            => TbsCertificate?.EndDate;

        public X509Name Subject
            => TbsCertificate?.Subject;

        public SubjectPublicKeyInfo SubjectPublicKeyInfo
            => TbsCertificate?.SubjectPublicKeyInfo;



        public static X509CertificateStructure GetInstance(Asn1TaggedObject  obj,
                                                           Boolean           explicitly)

            => GetInstance(Asn1Sequence.GetInstance(obj, explicitly));


        public static X509CertificateStructure GetInstance(Object obj)
        {

            if (obj == null)
                return null;

            if (obj is X509CertificateStructure x509CertificateStructure)
                return x509CertificateStructure;

            return new X509CertificateStructure(Asn1Sequence.GetInstance(obj));

        }

        public X509CertificateStructure(TbsCertificateStructure  tbsCert,
                                        AlgorithmIdentifier      sigAlgID,
                                        DerBitString             sig)
        {

            this.TbsCertificate      = tbsCert  ?? throw new ArgumentNullException(nameof(tbsCert),  "The given certificate must not be null!");
            this.SignatureAlgorithm  = sigAlgID ?? throw new ArgumentNullException(nameof(sigAlgID), "The given signature algorithm identifier must not be null!");
            this.Signature           = sig      ?? throw new ArgumentNullException(nameof(sig),      "The given signature must not be null!");

        }

        private X509CertificateStructure(Asn1Sequence seq)
        {

            if (seq == null)
                throw new ArgumentNullException(nameof(seq), "The given Asn1 sequence must not be null!");

            if (seq.Count != 3)
                throw new ArgumentException("The Asn1 sequence has a wrong size for a certificate!", nameof(seq));

            // Correct x509 certficate
            TbsCertificate      = TbsCertificateStructure.GetInstance(seq[0]);
            SignatureAlgorithm  = AlgorithmIdentifier.GetInstance(seq[1]);
            Signature           = DerBitString.GetInstance(seq[2]);

        }


        public override Asn1Object ToAsn1Object()

            => new DerSequence(TbsCertificate,
                               SignatureAlgorithm,
                               Signature);

    }

}
