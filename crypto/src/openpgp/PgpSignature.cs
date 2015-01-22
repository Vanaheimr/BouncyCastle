
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    /// <summary>
    /// A PGP signature object.
    /// </summary>
    public class PgpSignature
    {

        #region Data

        private readonly SignaturePacket    _SignaturePacket;
        private readonly PgpSignatureTypes  _SignatureType;
        private readonly TrustPacket        _TrustPacket;

        private ISigner _Signer;
        private Byte    _LastByte; // Initial value anything but '\r'

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
                return _SignaturePacket.Version;
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
                return _SignaturePacket.KeyAlgorithm;
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
                return _SignaturePacket.HashAlgorithm;
            }
        }

        #endregion

        #region SignatureType

        public PgpSignatureTypes SignatureType
        {
            get
            {
                return _SignaturePacket.SignatureType;
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
                return _SignaturePacket.KeyId;
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
                return "0x" + ((UInt64) _SignaturePacket.KeyId).ToString("X");
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
                return DateTimeUtilities.UnixMsToDateTime((UInt64) _SignaturePacket.CreationTime);
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
                return _SignaturePacket.HashedSubPackets != null ||
                       _SignaturePacket.UnhashedSubPackets != null;
            }
        }

        #endregion

        #region HashedSubPackets

        public PgpSignatureSubpacketVector HashedSubPackets
        {
            get
            {
                return createSubpacketVector(_SignaturePacket.HashedSubPackets);
            }
        }

        #endregion

        #region UnhashedSubPackets

        public PgpSignatureSubpacketVector UnhashedSubPackets
        {
            get
            {
                return createSubpacketVector(_SignaturePacket.UnhashedSubPackets);
            }
        }

        #endregion

        #region Signature

        public Byte[] Signature
        {

            get
            {

                var sigValues = _SignaturePacket.Signature;

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

                return _SignaturePacket.GetSignatureBytes();

            }

        }

        #endregion

        #region SignatureTrailer

        public Byte[] SignatureTrailer
        {
            get
            {
                return _SignaturePacket.SignatureTrailer;
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
                _Signer.BlockUpdate(trailer, 0, trailer.Length);

                return _Signer.VerifySignature(Signature);

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

            this._SignaturePacket         = sigPacket;
            this._SignatureType  = _SignaturePacket.SignatureType;
            this._TrustPacket       = trustPacket;

        }

        #endregion


        #region Encode<T>(OutputStream)

        public T Encode<T>(T OutputStream)
            where T : Stream
        {

            var BCPGOutputStream = BcpgOutputStream.Wrap(OutputStream);

            BCPGOutputStream.WritePacket(_SignaturePacket);

            if (_TrustPacket != null)
                BCPGOutputStream.WritePacket(_TrustPacket);

            return OutputStream;

        }

        #endregion

        #region Update(InByte)

        public void Update(Byte InByte)
        {

            if (_SignatureType == PgpSignatureTypes.CanonicalTextDocument)
                doCanonicalUpdateByte(InByte);

            else
                _Signer.Update(InByte);

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

            if (_SignatureType == PgpSignatureTypes.CanonicalTextDocument)
            {

                var finish = Offset + Length;

                for (var i = Offset; i != finish; i++)
                    doCanonicalUpdateByte(InBytes[i]);

            }

            else
                _Signer.BlockUpdate(InBytes, (Int32) Offset, (Int32) Length);

        }

        #endregion



        #region (private) GetSig()

        private void GetSig()
        {
            this._Signer = SignerUtilities.GetSigner(PgpUtilities.GetSignatureName(_SignaturePacket.KeyAlgorithm, _SignaturePacket.HashAlgorithm));
        }

        #endregion

        #region (private) doCanonicalUpdateByte(b)

        private void doCanonicalUpdateByte(Byte b)
        {

            if (b == '\r')
                doUpdateCRLF();

            else if (b == '\n')
            {
                if (_LastByte != '\r')
                    doUpdateCRLF();
            }
            else
                _Signer.Update(b);

            _LastByte = b;

        }

        #endregion

        #region (private) doUpdateCRLF()

        private void doUpdateCRLF()
        {
            _Signer.Update((byte)'\r');
            _Signer.Update((byte)'\n');
        }

        #endregion

        #region (private) UpdateWithIdData(header, idBytes)

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

        #endregion

        #region (private) UpdateWithPublicKey(PublicKey)

        private void UpdateWithPublicKey(PgpPublicKey PublicKey)
        {

            var keyBytes = GetEncodedPublicKey(PublicKey);

            this.Update((byte) 0x99,
                        (byte) (keyBytes.Length >> 8),
                        (byte) (keyBytes.Length));

            this.Update(keyBytes);

        }

        #endregion

        #region (private) createSubpacketVector(SignatureSubpackets)

        private PgpSignatureSubpacketVector createSubpacketVector(IEnumerable<SignatureSubpacket> SignatureSubpackets)
        {

            return SignatureSubpackets == null
                ? null
                : new PgpSignatureSubpacketVector(SignatureSubpackets);

        }

        #endregion

        #region (private) GetEncodedPublicKey(PublicKey)

        private byte[] GetEncodedPublicKey(PgpPublicKey PublicKey)
        {

            try
            {
                return PublicKey._PublicKeyPacket.GetEncodedContents();
            }
            catch (IOException e)
            {
                throw new PgpException("exception preparing key.", e);
            }

        }

        #endregion



        #region InitVerify(PublicKey)

        public void InitVerify(PgpPublicKey PublicKey)
        {

            _LastByte = 0;

            if (_Signer == null)
                GetSig();

            try
            {
                _Signer.Init(false, PublicKey.Key);
            }
            catch (InvalidKeyException e)
            {
                throw new PgpException("invalid key.", e);
            }

        }

        #endregion

        #region VerifyCertification(UserAttributes, PublicKey)

        /// <summary>
        /// Verify the signature as certifying the passed in public key as associated
        /// with the passed in user attributes.
        /// </summary>
        /// <param name="UserAttributes">User attributes the key was stored under.</param>
        /// <param name="PublicKey">The key to be verified.</param>
        /// <returns>True, if the signature matches, false otherwise.</returns>
        public Boolean VerifyCertification(PgpUserAttributeSubpacketVector  UserAttributes,
                                           PgpPublicKey                     PublicKey)
        {

            UpdateWithPublicKey(PublicKey);

            // hash in the userAttributes
            try
            {

                var bOut = new MemoryStream();

                foreach (var packet in UserAttributes.ToSubpacketArray())
                    packet.Encode(bOut);

                UpdateWithIdData(0xd1, bOut.ToArray());

            }
            catch (IOException e)
            {
                throw new PgpException("cannot encode subpacket array", e);
            }

            this.Update(_SignaturePacket.SignatureTrailer);

            return _Signer.VerifySignature(Signature);

        }

        #endregion

        #region VerifyCertification(Id, PublicKey)

        /// <summary>
        /// Verify the signature as certifying the passed in public key as associated
        /// with the passed in ID.
        /// </summary>
        /// <param name="Id">Id the key was stored under.</param>
        /// <param name="PublicKey">The key to be verified.</param>
        /// <returns>True, if the signature matches, false otherwise.</returns>
        public Boolean VerifyCertification(String        Id,
                                           PgpPublicKey  PublicKey)
        {

            UpdateWithPublicKey(PublicKey);

            // hash in the id
            UpdateWithIdData(0xb4, Encoding.UTF8.GetBytes(Id));

            Update(_SignaturePacket.SignatureTrailer);

            return _Signer.VerifySignature(Signature);

        }

        #endregion

        #region VerifyCertification(MasterKey, PublicKey)

        /// <summary>
        /// Verify a certification for the passed in key against the passed in master key.
        /// </summary>
        /// <param name="MasterKey">The key we are verifying against.</param>
        /// <param name="PublicKey">The key we are verifying.</param>
        /// <returns>True, if the certification is valid, false otherwise.</returns>
        public Boolean VerifyCertification(PgpPublicKey  MasterKey,
                                           PgpPublicKey  PublicKey)
        {

            UpdateWithPublicKey(MasterKey);
            UpdateWithPublicKey(PublicKey);

            Update(_SignaturePacket.SignatureTrailer);

            return _Signer.VerifySignature(Signature);

        }

        #endregion

        #region VerifyCertification(PublicKey)

        /// <summary>
        /// Verify a key certification, such as revocation, for the passed in key.
        /// </summary>
        /// <param name="PublicKey">The key we are checking.</param>
        /// <returns>True, if the certification is valid, false otherwise.</returns>
        public Boolean VerifyCertification(PgpPublicKey PublicKey)
        {

            if (SignatureType != PgpSignatureTypes.KeyRevocation && SignatureType != PgpSignatureTypes.SubkeyRevocation)
                throw new InvalidOperationException("signature is not a key signature");

            UpdateWithPublicKey(PublicKey);

            Update(_SignaturePacket.SignatureTrailer);

            return _Signer.VerifySignature(Signature);

        }

        #endregion


        public override String ToString()
        {
            return KeyIdHex + " / " + SignatureType.ToString();
        }

    }

}
