using System;
using System.Collections;
using System.Collections.Generic;

using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    /// <summary>
    /// Generator for signature subpackets.
    /// </summary>
    public class PgpSignatureSubpacketGenerator
    {

        #region Data

        private readonly List<SignatureSubpacket> SignatureSubpacketList;

        #endregion

        #region Constructor(s)

        public PgpSignatureSubpacketGenerator()
        {
            this.SignatureSubpacketList = new List<SignatureSubpacket>();
        }

        #endregion


        #region SetRevocable(IsCritical, IsRevocable)

        public PgpSignatureSubpacketGenerator SetRevocable(Boolean  IsCritical,
                                                           Boolean  IsRevocable)
        {

            SignatureSubpacketList.Add(new Revocable(IsCritical, IsRevocable));

            return this;

        }

        #endregion

        #region SetExportable(IsCritical, IsExportable)

        public PgpSignatureSubpacketGenerator SetExportable(Boolean  IsCritical,
                                                            Boolean  IsExportable)
        {

            SignatureSubpacketList.Add(new Exportable(IsCritical, IsExportable));

            return this;

        }

        #endregion

        #region SetTrust(IsCritical, Depth, TrustAmount)

        /// <summary>
        /// Add a TrustSignature packet to the signature. The values for depth and trust are largely
        /// installation dependent but there are some guidelines in RFC 4880 - 5.2.3.13.
        /// </summary>
        /// <param name="IsCritical">true if the packet is critical.</param>
        /// <param name="Depth">depth level.</param>
        /// <param name="TrustAmount">trust amount.</param>
        public PgpSignatureSubpacketGenerator SetTrust(Boolean  IsCritical,
                                                       Int32    Depth,
                                                       Int32    TrustAmount)
        {

            SignatureSubpacketList.Add(new TrustSignature(IsCritical, Depth, TrustAmount));

            return this;

        }

        #endregion

        #region SetKeyExpirationTime(IsCritical, Seconds)

        /// <summary>
        /// Set the number of seconds a key is valid for after the time of its creation.
        /// A value of zero means the key never expires.
        /// </summary>
        /// <param name="IsCritical">True, if should be treated as critical, false otherwise.</param>
        /// <param name="Seconds">The number of seconds the key is valid, or zero if no expiry.</param>
        public PgpSignatureSubpacketGenerator SetKeyExpirationTime(Boolean  IsCritical,
                                                                   UInt64   Seconds)
        {

            SignatureSubpacketList.Add(new KeyExpirationTime(IsCritical, Seconds));

            return this;

        }

        #endregion

        #region SetSignatureExpirationTime(IsCritical, Seconds)

        /// <summary>
        /// Set the number of seconds a signature is valid for after the time of its creation.
        /// A value of zero means the signature never expires.
        /// </summary>
        /// <param name="IsCritical">True, if should be treated as critical, false otherwise.</param>
        /// <param name="Seconds">The number of seconds the signature is valid, or zero if no expiry.</param>
        public PgpSignatureSubpacketGenerator SetSignatureExpirationTime(Boolean  IsCritical,
                                                                         UInt64   Seconds)
        {

            SignatureSubpacketList.Add(new SignatureExpirationTime(IsCritical, Seconds));

            return this;

        }

        #endregion

        #region SetSignatureCreationTime(IsCritical, Seconds)

        /// <summary>
        /// Set the creation time for the signature.
        /// <p>
        /// Note: this overrides the generation of a creation time when the signature
        /// is generated.</p>
        /// </summary>
        public PgpSignatureSubpacketGenerator SetSignatureCreationTime(Boolean   IsCritical,
                                                                       DateTime  Date)
        {

            SignatureSubpacketList.Add(new SignatureCreationTime(IsCritical, Date));

            return this;

        }

        #endregion

        #region SetPreferredHashAlgorithms(IsCritical, Seconds)

        public PgpSignatureSubpacketGenerator SetPreferredHashAlgorithms(Boolean  IsCritical,
                                                                         Int32[]  Algorithms)
        {

            SignatureSubpacketList.Add(new PreferredAlgorithms(SignatureSubpackets.PreferredHashAlgorithms, IsCritical, Algorithms));

            return this;

        }

        #endregion

        #region SetPreferredSymmetricAlgorithms(IsCritical, Seconds)

        public PgpSignatureSubpacketGenerator SetPreferredSymmetricAlgorithms(Boolean  IsCritical,
                                                                              Int32[]  Algorithms)
        {

            SignatureSubpacketList.Add(new PreferredAlgorithms(SignatureSubpackets.PreferredSymmetricAlgorithms, IsCritical, Algorithms));

            return this;

        }

        #endregion

        #region SetPreferredCompressionAlgorithms(IsCritical, Seconds)

        public PgpSignatureSubpacketGenerator SetPreferredCompressionAlgorithms(Boolean  IsCritical,
                                                                                Int32[]  Algorithms)
        {

            SignatureSubpacketList.Add(new PreferredAlgorithms(SignatureSubpackets.PreferredCompressionAlgorithms, IsCritical, Algorithms));

            return this;

        }

        #endregion

        #region SetKeyFlags(IsCritical, Flags)

        public PgpSignatureSubpacketGenerator SetKeyFlags(Boolean  IsCritical,
                                                          Int32    Flags)
        {

            SignatureSubpacketList.Add(new KeyFlags(IsCritical, Flags));

            return this;

        }

        #endregion

        #region SetKeyFlags(IsCritical, UserId)

        public PgpSignatureSubpacketGenerator SetSignerUserId(Boolean  IsCritical,
                                                              String   UserId)
        {

            if (UserId == null)
                throw new ArgumentNullException("UserId");

            SignatureSubpacketList.Add(new SignerUserId(IsCritical, UserId));

            return this;

        }

        #endregion

        #region SetKeyFlags(IsCritical, Signature)

        public PgpSignatureSubpacketGenerator SetEmbeddedSignature(Boolean       IsCritical,
                                                                   PgpSignature  Signature)
        {

            Byte[] data;
            var sig = Signature.Encoded;

            // TODO Should be >= ?
            if (sig.Length - 1 > 256)
                data = new byte[sig.Length - 3];

            else
                data = new byte[sig.Length - 2];


            Array.Copy(sig, sig.Length - data.Length, data, 0, data.Length);

            SignatureSubpacketList.Add(new EmbeddedSignature(IsCritical, data));

            return this;

        }

        #endregion

        #region SetKeyFlags(IsCritical, IsPrimaryUserId)

        public PgpSignatureSubpacketGenerator SetPrimaryUserId(Boolean  IsCritical,
                                                               Boolean  IsPrimaryUserId)
        {

            SignatureSubpacketList.Add(new PrimaryUserId(IsCritical, IsPrimaryUserId));

            return this;

        }

        #endregion

        #region SetKeyFlags(IsCritical, IsHumanReadable, NotationName, NotationValue)

        public PgpSignatureSubpacketGenerator SetNotationData(Boolean  IsCritical,
                                                              Boolean  IsHumanReadable,
                                                              String   NotationName,
                                                              String   NotationValue)
        {

            SignatureSubpacketList.Add(new NotationData(IsCritical, IsHumanReadable, NotationName, NotationValue));

            return this;

        }

        #endregion

        #region SetKeyFlags(IsCritical, Reason, Description)

        /// <summary>
        /// Sets revocation reason sub packet
        /// </summary>
        public PgpSignatureSubpacketGenerator SetRevocationReason(Boolean               IsCritical,
                                                                  RevocationReasonType  Reason,
                                                                  String                Description)
        {

            SignatureSubpacketList.Add(new RevocationReason(IsCritical, Reason, Description));

            return this;

        }

        #endregion

        #region SetRevocationKey(IsCritical, KeyAlgorithm, Fingerprint)

        /// <summary>
        /// Sets revocation key sub packet
        /// </summary>
        public PgpSignatureSubpacketGenerator SetRevocationKey(Boolean              IsCritical,
                                                               PublicKeyAlgorithms  KeyAlgorithm,
                                                               Byte[]               Fingerprint)
        {

            SignatureSubpacketList.Add(new RevocationKey(IsCritical, RevocationKeyType.ClassDefault, KeyAlgorithm, Fingerprint));

            return this;

        }

        #endregion

        #region SetIssuerKeyId(IsCritical, KeyId)

        /// <summary>
        /// Sets issuer key sub packet
        /// </summary>
        public PgpSignatureSubpacketGenerator SetIssuerKeyId(Boolean  IsCritical,
                                                             UInt64   KeyId)
        {

            SignatureSubpacketList.Add(new IssuerKeyId(IsCritical, KeyId));

            return this;

        }

        #endregion


        #region Generate()

        public PgpSignatureSubpacketVector Generate()
        {

            var a = new SignatureSubpacket[SignatureSubpacketList.Count];

            for (int i = 0; i < SignatureSubpacketList.Count; ++i)
                a[i] = SignatureSubpacketList[i];

            return new PgpSignatureSubpacketVector(a);

        }

        #endregion

    }

}
