using System;
using System.IO;
using Org.BouncyCastle.Asn1;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Date;
using System.Collections.Generic;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    public enum PgpSignatures
    {

        BinaryDocument             = 0x00,
        CanonicalTextDocument      = 0x01,
        StandAlone                 = 0x02,

        DefaultCertification       = 0x10,
        NoCertification            = 0x11,
        CasualCertification        = 0x12,
        PositiveCertification      = 0x13,

        SubkeyBinding              = 0x18,
        PrimaryKeyBinding          = 0x19,
        DirectKey                  = 0x1f,
        KeyRevocation              = 0x20,
        SubkeyRevocation           = 0x28,
        CertificationRevocation    = 0x30,
        Timestamp                  = 0x40

    }

    /// <summary>
    /// A PGP signature object.
    /// </summary>
    public class PgpSignature
    {

        #region Data

        private readonly SignaturePacket  sigPck;
        private readonly PgpSignatures    signatureType;
        private readonly TrustPacket      trustPck;

        private ISigner sig;
        private byte    lastb; // Initial value anything but '\r'

        #endregion

        #region Properties

        #region Version

        /// <summary>
        /// The OpenPGP version number for this signature.
        /// </summary>
        public Int32 Version
        {
            get
            {
                return sigPck.Version;
            }
        }

        #endregion

        #region KeyAlgorithm

        /// <summary>
        /// The key algorithm associated with this signature.
        /// </summary>
        public PublicKeyAlgorithms KeyAlgorithm
        {
            get
            {
                return sigPck.KeyAlgorithm;
            }
        }

        #endregion

        #region HashAlgorithm

        /// <summary>
        /// The hash algorithm associated with this signature.
        /// </summary>
        public HashAlgorithms HashAlgorithm
        {
            get
            {
                return sigPck.HashAlgorithm;
            }
        }

        #endregion

        #region SignatureType

        public PgpSignatures SignatureType
        {
            get
            {
                return sigPck.SignatureType;
            }
        }

        #endregion

        #region KeyId

        /// <summary>
        /// The identification of the key that created the signature.
        /// </summary>
        public UInt64 KeyId
        {
            get
            {
                return sigPck.KeyId;
            }
        }

        #endregion

        #region KeyIdHex

        /// <summary>
        /// The identification of the key that created the signature as hex-value.
        /// </summary>
        public String KeyIdHex
        {
            get
            {
                return "0x" + ((UInt64)sigPck.KeyId).ToString("X");
            }
        }

        #endregion

        #region CreationTime

        /// <summary>
        /// The creation time of this signature.
        /// </summary>
        public DateTime CreationTime
        {
            get
            {
                return DateTimeUtilities.UnixMsToDateTime(sigPck.CreationTime);
            }
        }

        #endregion

        #region HasSubpackets

        /// <summary>
        /// Return true if the signature has either hashed or unhashed subpackets.
        /// </summary>
        public Boolean HasSubpackets
        {
            get
            {
                return sigPck.HashedSubPackets != null ||
                       sigPck.UnhashedSubPackets != null;
            }
        }

        #endregion

        #region HashedSubPackets

        public PgpSignatureSubpacketVector HashedSubPackets
        {
            get
            {
                return createSubpacketVector(sigPck.HashedSubPackets);
            }
        }

        #endregion

        #region UnhashedSubPackets

        public PgpSignatureSubpacketVector UnhashedSubPackets
        {
            get
            {
                return createSubpacketVector(sigPck.UnhashedSubPackets);
            }
        }

        #endregion

        #region Signature

        public Byte[] Signature
        {

            get
            {

                var sigValues = sigPck.Signature;

                if (sigValues != null)
                {

                    // An RSA signature...
                    if (sigValues.Length == 1)
                        return sigValues[0].Value.ToByteArrayUnsigned();

                    else
                    {

                        try
                        {
                            return new DerSequence(new DerInteger(sigValues[0].Value),
                                                   new DerInteger(sigValues[1].Value)).GetEncoded();
                        }
                        catch (IOException e)
                        {
                            throw new PgpException("exception encoding DSA sig.", e);
                        }

                    }

                }

                return sigPck.GetSignatureBytes();

            }

        }

        #endregion

        #region SignatureTrailer

        public Byte[] SignatureTrailer
        {
            get
            {
                return sigPck.SignatureTrailer;
            }
        }

        #endregion

        #region Encoded

        public Byte[] Encoded
        {
            get
            {
                return Encode(new MemoryStream()).ToArray();
            }
        }

        #endregion

        #region IsValid

        public Boolean IsValid
        {
            get
            {

                var trailer = SignatureTrailer;
                sig.BlockUpdate(trailer, 0, trailer.Length);

                return sig.VerifySignature(Signature);

            }

        }

        #endregion

        #endregion

        #region Constructor(s)

        internal PgpSignature(BcpgInputStream bcpgInput)
            : this((SignaturePacket) bcpgInput.ReadPacket())
        { }

        internal PgpSignature(SignaturePacket sigPacket)
            : this(sigPacket, null)
        { }

        internal PgpSignature(SignaturePacket  sigPacket,
                              TrustPacket      trustPacket)
        {

            if (sigPacket == null)
                throw new ArgumentNullException("sigPacket");

            this.sigPck         = sigPacket;
            this.signatureType  = sigPck.SignatureType;
            this.trustPck       = trustPacket;

        }

        #endregion



        #region Encode<T>(OutputStream)

        public T Encode<T>(T OutputStream)
            where T : Stream
        {

            var bcpgOut = BcpgOutputStream.Wrap(OutputStream);

            bcpgOut.WritePacket(sigPck);

            if (trustPck != null)
                bcpgOut.WritePacket(trustPck);

            return OutputStream;

        }

        #endregion

        #region Update(InByte)

        public void Update(Byte InByte)
        {

            if (signatureType == PgpSignatures.CanonicalTextDocument)
                doCanonicalUpdateByte(InByte);

            else
                sig.Update(InByte);

        }

        #endregion

        #region Update(params InBytes)

        public void Update(params Byte[] InBytes)
        {
            Update(InBytes, 0, (UInt64) InBytes.Length);
        }

        #endregion

        #region Update(InBytes, Offset, Length)

        public void Update(Byte[]  InBytes,
                           UInt64  Offset,
                           UInt64  Length)
        {

            if (signatureType == PgpSignatures.CanonicalTextDocument)
            {

                var finish = Offset + Length;

                for (var i = Offset; i != finish; i++)
                    doCanonicalUpdateByte(InBytes[i]);

            }

            else
                sig.BlockUpdate(InBytes, (Int32) Offset, (Int32) Length);

        }

        #endregion



        #region (private) 

        private void GetSig()
        {
            this.sig = SignerUtilities.GetSigner(PgpUtilities.GetSignatureName(sigPck.KeyAlgorithm, sigPck.HashAlgorithm));
        }

        private void doCanonicalUpdateByte(Byte b)
        {

            if (b == '\r')
                doUpdateCRLF();

            else if (b == '\n')
            {
                if (lastb != '\r')
                    doUpdateCRLF();
            }
            else
                sig.Update(b);

            lastb = b;

        }

        private void doUpdateCRLF()
        {
            sig.Update((byte)'\r');
            sig.Update((byte)'\n');
        }

        private void UpdateWithIdData(Int32   header,
                                      Byte[]  idBytes)
        {

            this.Update((byte) header,
                        (byte) (idBytes.Length >> 24),
                        (byte) (idBytes.Length >> 16),
                        (byte) (idBytes.Length >> 8),
                        (byte) (idBytes.Length));

            this.Update(idBytes);

        }

        private void UpdateWithPublicKey(PgpPublicKey  key)
        {

            var keyBytes = GetEncodedPublicKey(key);

            this.Update((byte) 0x99,
                        (byte) (keyBytes.Length >> 8),
                        (byte) (keyBytes.Length));

            this.Update(keyBytes);

        }

        private PgpSignatureSubpacketVector createSubpacketVector(IEnumerable<SignatureSubpacket> pcks)
        {

            return pcks == null
                ? null
                : new PgpSignatureSubpacketVector(pcks);

        }

        private byte[] GetEncodedPublicKey(PgpPublicKey pubKey)
        {

            try
            {
                return pubKey.publicPk.GetEncodedContents();
            }
            catch (IOException e)
            {
                throw new PgpException("exception preparing key.", e);
            }

        }

        #endregion



        public void InitVerify(PgpPublicKey PublicKey)
        {

            lastb = 0;

            if (sig == null)
                GetSig();

            try
            {
                sig.Init(false, PublicKey.GetKey());
            }
            catch (InvalidKeyException e)
            {
                throw new PgpException("invalid key.", e);
            }

        }

        /// <summary>
        /// Verify the signature as certifying the passed in public key as associated
        /// with the passed in user attributes.
        /// </summary>
        /// <param name="userAttributes">User attributes the key was stored under.</param>
        /// <param name="key">The key to be verified.</param>
        /// <returns>True, if the signature matches, false otherwise.</returns>
        public bool VerifyCertification(PgpUserAttributeSubpacketVector  userAttributes,
                                        PgpPublicKey                     key)
        {

            UpdateWithPublicKey(key);

            // hash in the userAttributes
            try
            {

                var bOut = new MemoryStream();

                foreach (var packet in userAttributes.ToSubpacketArray())
                    packet.Encode(bOut);

                UpdateWithIdData(0xd1, bOut.ToArray());

            }
            catch (IOException e)
            {
                throw new PgpException("cannot encode subpacket array", e);
            }

            this.Update(sigPck.SignatureTrailer);

            return sig.VerifySignature(Signature);

        }

        /// <summary>
        /// Verify the signature as certifying the passed in public key as associated
        /// with the passed in ID.
        /// </summary>
        /// <param name="id">ID the key was stored under.</param>
        /// <param name="key">The key to be verified.</param>
        /// <returns>True, if the signature matches, false otherwise.</returns>
        public Boolean VerifyCertification(String        id,
                                           PgpPublicKey  key)
        {

            UpdateWithPublicKey(key);

            // hash in the id
            UpdateWithIdData(0xb4, Strings.ToUtf8ByteArray(id));

            Update(sigPck.SignatureTrailer);

            return sig.VerifySignature(Signature);

        }

        /// <summary>
        /// Verify a certification for the passed in key against the passed in master key.
        /// </summary>
        /// <param name="masterKey">The key we are verifying against.</param>
        /// <param name="pubKey">The key we are verifying.</param>
        /// <returns>True, if the certification is valid, false otherwise.</returns>
        public Boolean VerifyCertification(PgpPublicKey  masterKey,
                                           PgpPublicKey  pubKey)
        {

            UpdateWithPublicKey(masterKey);
            UpdateWithPublicKey(pubKey);

            Update(sigPck.SignatureTrailer);

            return sig.VerifySignature(Signature);

        }

        /// <summary>
        /// Verify a key certification, such as revocation, for the passed in key.
        /// </summary>
        /// <param name="pubKey">The key we are checking.</param>
        /// <returns>True, if the certification is valid, false otherwise.</returns>
        public Boolean VerifyCertification(PgpPublicKey pubKey)
        {

            if (SignatureType != PgpSignatures.KeyRevocation && SignatureType != PgpSignatures.SubkeyRevocation)
                throw new InvalidOperationException("signature is not a key signature");

            UpdateWithPublicKey(pubKey);

            Update(sigPck.SignatureTrailer);

            return sig.VerifySignature(Signature);

        }


    }

}
