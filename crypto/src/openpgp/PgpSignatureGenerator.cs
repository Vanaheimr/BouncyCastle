using System;
using System.Linq;
using System.IO;

using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System.Collections.Generic;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    /// <remarks>Generator for PGP signatures.</remarks>
    // TODO Should be able to implement ISigner?
    public class PgpSignatureGenerator
    {

        private static readonly IEnumerable<SignatureSubpacket> EmptySignatureSubpackets = new SignatureSubpacket[0];

        private PublicKeyAlgorithms  keyAlgorithm;
        private HashAlgorithms       hashAlgorithm;
        private PgpPrivateKey        privKey;
        private ISigner              sig;
        private IDigest              dig;
        private PgpSignatures        signatureType;
        private Byte                 lastb;

        private IEnumerable<SignatureSubpacket> unhashed  = EmptySignatureSubpackets;
        private IEnumerable<SignatureSubpacket> hashed    = EmptySignatureSubpackets;

        /// <summary>Create a generator for the passed in keyAlgorithm and hashAlgorithm codes.</summary>
        public PgpSignatureGenerator(PublicKeyAlgorithms  keyAlgorithm,
                                     HashAlgorithms       hashAlgorithm)
        {

            this.keyAlgorithm   = keyAlgorithm;
            this.hashAlgorithm  = hashAlgorithm;

            dig = DigestUtilities.GetDigest(PgpUtilities.GetDigestName(hashAlgorithm));
            sig = SignerUtilities.GetSigner(PgpUtilities.GetSignatureName(keyAlgorithm, hashAlgorithm));

        }

        /// <summary>Initialise the generator for signing.</summary>
        public void InitSign(PgpSignatures  sigType,
                             PgpPrivateKey  key)
        {

            InitSign(sigType, key, null);

        }

        /// <summary>Initialise the generator for signing.</summary>
        public void InitSign(PgpSignatures  sigType,
                             PgpPrivateKey  key,
                             SecureRandom   random)
        {

            this.privKey        = key;
            this.signatureType  = sigType;

            try
            {

                ICipherParameters cp = key.Key;

                if (random != null)
                    cp = new ParametersWithRandom(key.Key, random);

                sig.Init(true, cp);

            }
            catch (InvalidKeyException e)
            {
                throw new PgpException("invalid key.", e);
            }

            dig.Reset();
            lastb = 0;

        }

        public void Update(Byte b)
        {

            if (signatureType == PgpSignatures.CanonicalTextDocument)
                doCanonicalUpdateByte(b);

            else
                doUpdateByte(b);

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
                doUpdateByte(b);

            lastb = b;

        }

        private void doUpdateCRLF()
        {
            doUpdateByte((byte)'\r');
            doUpdateByte((byte)'\n');
        }

        private void doUpdateByte(Byte b)
        {
            sig.Update(b);
            dig.Update(b);
        }

        public void Update(params Byte[] b)
        {
            Update(b, 0, b.Length);
        }

        public void Update(Byte[]  b,
                           int     off,
                           int     len)
        {

            if (signatureType == PgpSignatures.CanonicalTextDocument)
            {

                int finish = off + len;

                for (int i = off; i != finish; i++)
                    doCanonicalUpdateByte(b[i]);

            }

            else
            {
                sig.BlockUpdate(b, off, len);
                dig.BlockUpdate(b, off, len);
            }

        }

        public void SetHashedSubpackets(PgpSignatureSubpacketVector hashedPackets)
        {
            hashed = hashedPackets == null
                ?    EmptySignatureSubpackets
                :    hashedPackets.ToSubpacketArray();
        }

        public void SetUnhashedSubpackets(PgpSignatureSubpacketVector unhashedPackets)
        {
            unhashed = unhashedPackets == null
                ?    EmptySignatureSubpackets
                :    unhashedPackets.ToSubpacketArray();
        }

        /// <summary>Return the one pass header associated with the current signature.</summary>
        public PgpOnePassSignature GenerateOnePassVersion(Boolean isNested)
        {
            return new PgpOnePassSignature(
                new OnePassSignaturePacket(
                    signatureType, hashAlgorithm, keyAlgorithm, privKey.KeyId, isNested));
        }

        /// <summary>
        /// Return a signature object containing the current signature state.
        /// </summary>
        public PgpSignature Generate()
        {

            var hPkts    = hashed;
            var unhPkts  = unhashed;

            if (!packetPresent(hashed,   SignatureSubpackets.CreationTime))
                hPkts   = insertSubpacket(hPkts, new SignatureCreationTime(false, DateTime.UtcNow));

            if (!packetPresent(hashed,   SignatureSubpackets.IssuerKeyId) &&
                !packetPresent(unhashed, SignatureSubpackets.IssuerKeyId))
                unhPkts = insertSubpacket(unhPkts, new IssuerKeyId(false, privKey.KeyId));

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
                sOut.WriteByte((byte) signatureType);
                sOut.WriteByte((byte) keyAlgorithm);
                sOut.WriteByte((byte) hashAlgorithm);
                sOut.WriteByte((byte) (data.Length >> 8));
                sOut.WriteByte((byte)  data.Length);
                sOut.Write(data, 0, data.Length);

                hData = sOut.ToArray();

            }
            catch (IOException e)
            {
                throw new PgpException("exception encoding hashed data.", e);
            }

            sig.BlockUpdate(hData, 0, hData.Length);
            dig.BlockUpdate(hData, 0, hData.Length);

            hData = new byte[]
            {
                (byte)  version,
                0xff,
                (byte) (hData.Length >> 24),
                (byte) (hData.Length >> 16),
                (byte) (hData.Length >>  8),
                (byte)  hData.Length
            };

            sig.BlockUpdate(hData, 0, hData.Length);
            dig.BlockUpdate(hData, 0, hData.Length);

            var sigBytes     = sig.GenerateSignature();
            var digest       = DigestUtilities.DoFinal(dig);
            var fingerPrint  = new byte[] { digest[0], digest[1] };

            // An RSA signature?
            var isRsa  = keyAlgorithm == PublicKeyAlgorithms.RsaSign ||
                         keyAlgorithm == PublicKeyAlgorithms.RsaGeneral;

            var sigValues = isRsa
                ?    PgpUtilities.RsaSigToMpi(sigBytes)
                :    PgpUtilities.DsaSigToMpi(sigBytes);

            return new PgpSignature(new SignaturePacket(signatureType,
                                                        privKey.KeyId,
                                                        keyAlgorithm,
                                                        hashAlgorithm,
                                                        hPkts,
                                                        unhPkts,
                                                        fingerPrint,
                                                        sigValues));

        }

        /// <summary>Generate a certification for the passed in ID and key.</summary>
        /// <param name="id">The ID we are certifying against the public key.</param>
        /// <param name="pubKey">The key we are certifying against the ID.</param>
        /// <returns>The certification.</returns>
        public PgpSignature GenerateCertification(String        id,
                                                  PgpPublicKey  pubKey)
        {

            UpdateWithPublicKey(pubKey);

            // hash in the id
            UpdateWithIdData(0xb4, Strings.ToUtf8ByteArray(id));

            return Generate();

        }

        /// <summary>Generate a certification for the passed in userAttributes.</summary>
        /// <param name="userAttributes">The ID we are certifying against the public key.</param>
        /// <param name="pubKey">The key we are certifying against the ID.</param>
        /// <returns>The certification.</returns>
        public PgpSignature GenerateCertification(PgpUserAttributeSubpacketVector    userAttributes,
                                                  PgpPublicKey                    pubKey)
        {

            UpdateWithPublicKey(pubKey);

            // hash in the attributes
            try
            {

                MemoryStream bOut = new MemoryStream();

                foreach (UserAttributeSubpacket packet in userAttributes.ToSubpacketArray())
                {
                    packet.Encode(bOut);
                }

                UpdateWithIdData(0xd1, bOut.ToArray());

            }
            catch (IOException e)
            {
                throw new PgpException("cannot encode subpacket array", e);
            }

            return this.Generate();

        }

        /// <summary>Generate a certification for the passed in key against the passed in master key.</summary>
        /// <param name="masterKey">The key we are certifying against.</param>
        /// <param name="pubKey">The key we are certifying.</param>
        /// <returns>The certification.</returns>
        public PgpSignature GenerateCertification(PgpPublicKey  masterKey,
                                                  PgpPublicKey  pubKey)
        {

            UpdateWithPublicKey(masterKey);
            UpdateWithPublicKey(pubKey);

            return Generate();

        }

        /// <summary>Generate a certification, such as a revocation, for the passed in key.</summary>
        /// <param name="pubKey">The key we are certifying.</param>
        /// <returns>The certification.</returns>
        public PgpSignature GenerateCertification(PgpPublicKey pubKey)
        {

            UpdateWithPublicKey(pubKey);

            return Generate();

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

        private bool packetPresent(IEnumerable<SignatureSubpacket>  packets,
                                   SignatureSubpackets              type)
        {
            return packets.Any(Item => Item.SubpacketType == type);
        }

        private IEnumerable<SignatureSubpacket> insertSubpacket(IEnumerable<SignatureSubpacket>  packets,
                                                                SignatureSubpacket               subpacket)
        {
            var tmp = new List<SignatureSubpacket>() { subpacket };
            tmp.AddRange(packets);
            return tmp;
        }

        private void UpdateWithIdData(int     header,
                                      byte[]  idBytes)
        {

            this.Update(
                (byte) header,
                (byte)(idBytes.Length >> 24),
                (byte)(idBytes.Length >> 16),
                (byte)(idBytes.Length >> 8),
                (byte)(idBytes.Length));

            this.Update(idBytes);

        }

        private void UpdateWithPublicKey(PgpPublicKey key)
        {

            byte[] keyBytes = GetEncodedPublicKey(key);

            this.Update(
                (byte) 0x99,
                (byte)(keyBytes.Length >> 8),
                (byte)(keyBytes.Length));

            this.Update(keyBytes);

        }

    }

}
