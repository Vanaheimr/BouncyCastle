using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;

using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    /// <summary>
    /// Generator for PGP signatures.
    /// </summary>
    public class PgpSignatureGenerator
    {

        #region Data

        private readonly PublicKeyAlgorithms     PublicKeyAlgorithm;
        private readonly HashAlgorithms          HashAlgorithm;
        private readonly ISigner                 Signer;
        private readonly IDigest                 Digest;
        private          PgpSignatureTypes           SignatureType;
        private          PgpPrivateKey           PrivateKey;
        private          Byte                    lastb;

        private IEnumerable<SignatureSubpacket>  hashed;
        private IEnumerable<SignatureSubpacket>  unhashed;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a generator for the passed in keyAlgorithm and hashAlgorithm codes.
        /// </summary>
        /// <param name="PublicKeyAlgorithm">A public key.</param>
        /// <param name="HashAlgorithm">A hashing algorithm.</param>
        public PgpSignatureGenerator(PublicKeyAlgorithms  PublicKeyAlgorithm,
                                     HashAlgorithms       HashAlgorithm)
        {

            this.PublicKeyAlgorithm  = PublicKeyAlgorithm;
            this.HashAlgorithm       = HashAlgorithm;

            this.Digest              = DigestUtilities.GetDigest(PgpUtilities.GetDigestName(HashAlgorithm));
            this.Signer              = SignerUtilities.GetSigner(PgpUtilities.GetSignatureName(PublicKeyAlgorithm, HashAlgorithm));

            this.hashed              = new SignatureSubpacket[0];
            this.unhashed            = new SignatureSubpacket[0];

        }

        #endregion


        #region InitSign(SignatureType, PrivateKey, Random  = null)

        /// <summary>
        /// Initialise the generator for signing.
        /// </summary>
        public void InitSign(PgpSignatureTypes  SignatureType,
                             PgpPrivateKey      PrivateKey,
                             SecureRandom       Random  = null)
        {

            this.SignatureType  = SignatureType;
            this.PrivateKey     = PrivateKey;

            try
            {

                var cp = (ICipherParameters) PrivateKey.PrivateKey;

                if (Random != null)
                    cp = new ParametersWithRandom(PrivateKey.PrivateKey, Random);

                Signer.Init(true, cp);

            }
            catch (InvalidKeyException e)
            {
                throw new PgpException("invalid key.", e);
            }

            Digest.Reset();
            lastb = 0;

        }

        #endregion


        #region (private) doCanonicalUpdateByte(SingleByte)

        private void doCanonicalUpdateByte(Byte SingleByte)
        {

            if (SingleByte == '\r')
                doUpdateCRLF();

            else if (SingleByte == '\n')
            {
                if (lastb != '\r')
                    doUpdateCRLF();
            }

            else
                doUpdateByte(SingleByte);

            lastb = SingleByte;

        }

        #endregion

        #region (private) doUpdateCRLF()

        private void doUpdateCRLF()
        {
            doUpdateByte((byte)'\r');
            doUpdateByte((byte)'\n');
        }

        #endregion

        #region (private) doUpdateByte()

        private void doUpdateByte(Byte SingleByte)
        {
            Signer.Update(SingleByte);
            Digest.Update(SingleByte);
        }

        #endregion

        #region Update(SingleByte)

        public void Update(Byte SingleByte)
        {

            if (SignatureType == PgpSignatureTypes.CanonicalTextDocument)
                doCanonicalUpdateByte(SingleByte);

            else
                doUpdateByte(SingleByte);

        }

        #endregion

        #region Update(ByteArray)

        public void Update(Byte[] ByteArray)
        {
            Update(ByteArray, 0, ByteArray.Length);
        }

        #endregion

        #region Update(ByteArray, Offset, Length)

        public void Update(Byte[]  ByteArray,
                           Int32   Offset,
                           Int32   Length)
        {

            if (SignatureType == PgpSignatureTypes.CanonicalTextDocument)
            {

                var finish = Offset + Length;

                for (var i = Offset; i != finish; i++)
                    doCanonicalUpdateByte(ByteArray[i]);

            }

            else
            {
                Signer.BlockUpdate(ByteArray, Offset, Length);
                Digest.BlockUpdate(ByteArray, Offset, Length);
            }

        }

        #endregion

        #region UpdateWithIdData(Header, IdBytes)

        private void UpdateWithIdData(Int32 Header,
                                      Byte[] IdBytes)
        {

            this.Update(new Byte[5] { (Byte)  Header,
                                      (Byte) (IdBytes.Length >> 24),
                                      (Byte) (IdBytes.Length >> 16),
                                      (Byte) (IdBytes.Length >>  8),
                                      (Byte) (IdBytes.Length) });

            this.Update(IdBytes);

        }

        #endregion

        #region UpdateWithPublicKey(PublicKey)

        private void UpdateWithPublicKey(PgpPublicKey PublicKey)
        {

            var keyBytes = GetEncodedPublicKey(PublicKey);

            this.Update(new Byte[3] { (Byte)  0x99,
                                      (Byte) (keyBytes.Length >> 8),
                                      (Byte) (keyBytes.Length) });

            this.Update(keyBytes);

        }

        #endregion


        #region SetHashedSubpackets(HashedPackets)

        public void SetHashedSubpackets(PgpSignatureSubpacketVector HashedPackets)
        {

            hashed = HashedPackets != null
                ? (IEnumerable<SignatureSubpacket>) HashedPackets
                : new SignatureSubpacket[0];

        }

        #endregion

        #region SetUnhashedSubpackets(UnhashedPackets)

        public void SetUnhashedSubpackets(PgpSignatureSubpacketVector UnhashedPackets)
        {

            unhashed = UnhashedPackets != null
                ?    (IEnumerable<SignatureSubpacket>) UnhashedPackets
                :    new SignatureSubpacket[0];

        }

        #endregion


        #region GenerateOnePassVersion(IsNested)

        /// <summary>
        /// Return the one pass header associated with the current signature.
        /// </summary>
        public PgpOnePassSignature GenerateOnePassVersion(Boolean IsNested)
        {

            return new PgpOnePassSignature(new OnePassSignaturePacket(SignatureType,
                                                                      HashAlgorithm,
                                                                      PublicKeyAlgorithm,
                                                                      PrivateKey.KeyId,
                                                                      IsNested));

        }

        #endregion

        #region Generate()

        /// <summary>
        /// Return a signature object containing the current signature state.
        /// </summary>
        public PgpSignature Generate()
        {

            var hPkts    = hashed;
            var unhPkts  = unhashed;

            if (!HasSubpacket(hashed,   SignatureSubpackets.CreationTime))
                hPkts   = InsertSubpacket(hPkts, new SignatureCreationTime(false, DateTime.UtcNow));

            if (!HasSubpacket(hashed,   SignatureSubpackets.IssuerKeyId) &&
                !HasSubpacket(unhashed, SignatureSubpackets.IssuerKeyId))
                unhPkts = InsertSubpacket(unhPkts, new IssuerKeyId(false, PrivateKey.KeyId));

            int version = 4;
            byte[] hData;

            try
            {

                var hOut = new MemoryStream();

                //for (int i = 0; i != hPkts.Length; i++)
                //    hPkts[i].Encode(hOut);

                foreach (var _hPkts in hPkts)
                    _hPkts.Encode(hOut);

                var data = hOut.ToArray();


                var sOut = new MemoryStream(data.Length + 6);
                sOut.WriteByte((byte) version);
                sOut.WriteByte((byte) SignatureType);
                sOut.WriteByte((byte) PublicKeyAlgorithm);
                sOut.WriteByte((byte) HashAlgorithm);
                sOut.WriteByte((byte) (data.Length >> 8));
                sOut.WriteByte((byte)  data.Length);
                sOut.Write(data, 0, data.Length);

                hData = sOut.ToArray();

            }
            catch (IOException e)
            {
                throw new PgpException("exception encoding hashed data.", e);
            }

            Signer.BlockUpdate(hData, 0, hData.Length);
            Digest.BlockUpdate(hData, 0, hData.Length);

            hData = new byte[]
            {
                (byte)  version,
                 0xff,
                (byte) (hData.Length >> 24),
                (byte) (hData.Length >> 16),
                (byte) (hData.Length >>  8),
                (byte)  hData.Length
            };

            Signer.BlockUpdate(hData, 0, hData.Length);
            Digest.BlockUpdate(hData, 0, hData.Length);

            var sigBytes     = Signer.GenerateSignature();
            var digest       = DigestUtilities.DoFinal(Digest);
            var fingerPrint  = new byte[] { digest[0], digest[1] };

            // An RSA signature?
            var isRsa  = PublicKeyAlgorithm == PublicKeyAlgorithms.RsaSign ||
                         PublicKeyAlgorithm == PublicKeyAlgorithms.RsaGeneral;

            var sigValues = isRsa
                ?    PgpUtilities.RsaSigToMpi(sigBytes)
                :    PgpUtilities.DsaSigToMpi(sigBytes);

            return new PgpSignature(new SignaturePacket(SignatureType,
                                                        PrivateKey.KeyId,
                                                        PublicKeyAlgorithm,
                                                        HashAlgorithm,
                                                        hPkts,
                                                        unhPkts,
                                                        fingerPrint,
                                                        sigValues));

        }

        #endregion

        #region GenerateCertification(Id, PublicKey)

        /// <summary>
        /// Generate a certification for the passed in Id and public key.
        /// </summary>
        /// <param name="Id">The Id we are certifying against the public key.</param>
        /// <param name="PublicKey">The key we are certifying against the Id.</param>
        /// <returns>The certification.</returns>
        public PgpSignature GenerateCertification(String        Id,
                                                  PgpPublicKey  PublicKey)
        {

            UpdateWithPublicKey(PublicKey);

            // Hash in the id
            UpdateWithIdData(0xb4, Strings.ToUtf8ByteArray(Id));

            return Generate();

        }

        #endregion

        #region GenerateCertification(UserAttributes, PublicKey)

        /// <summary>Generate a certification for the passed in userAttributes.</summary>
        /// <param name="UserAttributes">The ID we are certifying against the public key.</param>
        /// <param name="PublicKey">The key we are certifying against the ID.</param>
        /// <returns>The certification.</returns>
        public PgpSignature GenerateCertification(PgpUserAttributeSubpacketVector  UserAttributes,
                                                  PgpPublicKey                     PublicKey)
        {

            UpdateWithPublicKey(PublicKey);

            // hash in the attributes
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

            return this.Generate();

        }

        #endregion

        #region GenerateCertification(MasterKey, PublicKey)

        /// <summary>
        /// Generate a certification for the passed in key against the passed in master key.
        /// </summary>
        /// <param name="MasterKey">The key we are certifying against.</param>
        /// <param name="PublicKey">The key we are certifying.</param>
        /// <returns>The certification.</returns>
        public PgpSignature GenerateCertification(PgpPublicKey  MasterKey,
                                                  PgpPublicKey  PublicKey)
        {

            UpdateWithPublicKey(MasterKey);
            UpdateWithPublicKey(PublicKey);

            return Generate();

        }

        #endregion

        #region GenerateCertification(PublicKey)

        /// <summary>Generate a certification, such as a revocation, for the passed in key.</summary>
        /// <param name="PublicKey">The key we are certifying.</param>
        /// <returns>The certification.</returns>
        public PgpSignature GenerateCertification(PgpPublicKey PublicKey)
        {

            UpdateWithPublicKey(PublicKey);

            return Generate();

        }

        #endregion


        #region (private) GetEncodedPublicKey(PublicKey)

        private Byte[] GetEncodedPublicKey(PgpPublicKey PublicKey) 
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

        #region (private) HasSubpacket(SignatureSubpackets, SignatureSubpacketType)

        private Boolean HasSubpacket(IEnumerable<SignatureSubpacket>  SignatureSubpackets,
                                     SignatureSubpackets              SignatureSubpacketType)
        {
            return SignatureSubpackets.Any(packet => packet.SubpacketType == SignatureSubpacketType);
        }

        #endregion

        #region (private) InsertSubpacket(Subpackets, Subpacket)

        private IEnumerable<SignatureSubpacket> InsertSubpacket(IEnumerable<SignatureSubpacket>  Subpackets,
                                                                SignatureSubpacket               Subpacket)
        {
            var tmp = new List<SignatureSubpacket>() { Subpacket };
            tmp.AddRange(Subpackets);
            return tmp;
        }

        #endregion


    }

}
