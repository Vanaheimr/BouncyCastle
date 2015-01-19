using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    /// <remarks>Generator for old style PGP V3 Signatures.</remarks>
    // TODO Should be able to implement ISigner?
    public class PgpV3SignatureGenerator
    {

        private PublicKeyAlgorithms   keyAlgorithm;
        private HashAlgorithms        hashAlgorithm;
        private PgpPrivateKey         privKey;
        private ISigner               sig;
        private IDigest               dig;
        private PgpSignatureTypes         signatureType;
        private Byte                  lastb;

        /// <summary>Create a generator for the passed in keyAlgorithm and hashAlgorithm codes.</summary>
        public PgpV3SignatureGenerator(PublicKeyAlgorithms  keyAlgorithm,
                                       HashAlgorithms       hashAlgorithm)
        {

            this.keyAlgorithm   = keyAlgorithm;
            this.hashAlgorithm  = hashAlgorithm;

            dig = DigestUtilities.GetDigest(PgpUtilities.GetDigestName(hashAlgorithm));
            sig = SignerUtilities.GetSigner(PgpUtilities.GetSignatureName(keyAlgorithm, hashAlgorithm));

        }

        /// <summary>Initialise the generator for signing.</summary>
        public void InitSign(PgpSignatureTypes  sigType,
                             PgpPrivateKey  key)
        {
            InitSign(sigType, key, null);
        }

        /// <summary>Initialise the generator for signing.</summary>
        public void InitSign(PgpSignatureTypes  sigType,
                             PgpPrivateKey  key,
                             SecureRandom   random)
        {

            this.privKey        = key;
            this.signatureType  = sigType;

            try
            {
                ICipherParameters cp = key.PrivateKey;
                if (random != null)
                {
                    cp = new ParametersWithRandom(key.PrivateKey, random);
                }

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

            if (signatureType == PgpSignatureTypes.CanonicalTextDocument)
            {
                doCanonicalUpdateByte(b);
            }
            else
            {
                doUpdateByte(b);
            }

        }

        private void doCanonicalUpdateByte(byte b)
        {

            if (b == '\r')
            {
                doUpdateCRLF();
            }
            else if (b == '\n')
            {
                if (lastb != '\r')
                {
                    doUpdateCRLF();
                }
            }
            else
            {
                doUpdateByte(b);
            }

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

        public void Update(Byte[] b)
        {

            if (signatureType == PgpSignatureTypes.CanonicalTextDocument)
            {
                for (int i = 0; i != b.Length; i++)
                {
                    doCanonicalUpdateByte(b[i]);
                }
            }
            else
            {
                sig.BlockUpdate(b, 0, b.Length);
                dig.BlockUpdate(b, 0, b.Length);
            }

        }

        public void Update(Byte[]  b,
                           int     off,
                           int     len)
        {

            if (signatureType == PgpSignatureTypes.CanonicalTextDocument)
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

        /// <summary>Return the one pass header associated with the current signature.</summary>
        public PgpOnePassSignature GenerateOnePassVersion(Boolean isNested)
        {
            return new PgpOnePassSignature(new OnePassSignaturePacket(signatureType, hashAlgorithm, keyAlgorithm, privKey.KeyId, isNested));
        }

        /// <summary>Return a V3 signature object containing the current signature state.</summary>
        public PgpSignature Generate()
        {

            var creationTime = (UInt64) DateTimeUtilities.CurrentUnixMs() / 1000L;

            var hData = new byte[]
            {
                (byte)  signatureType,
                (byte) (creationTime >> 24),
                (byte) (creationTime >> 16),
                (byte) (creationTime >>  8),
                (byte)  creationTime
            };

            sig.BlockUpdate(hData, 0, hData.Length);
            dig.BlockUpdate(hData, 0, hData.Length);

            var sigBytes = sig.GenerateSignature();
            var digest = DigestUtilities.DoFinal(dig);
            var fingerPrint = new byte[]{ digest[0], digest[1] };

            // an RSA signature
            var isRsa = keyAlgorithm == PublicKeyAlgorithms.RsaSign ||
                        keyAlgorithm == PublicKeyAlgorithms.RsaGeneral;

            MPInteger[] sigValues = isRsa
                ?    PgpUtilities.RsaSigToMpi(sigBytes)
                :    PgpUtilities.DsaSigToMpi(sigBytes);

            return new PgpSignature(new SignaturePacket(3,
                                                        signatureType,
                                                        privKey.KeyId,
                                                        keyAlgorithm,
                                                        hashAlgorithm,
                                                        (Int64) creationTime * 1000L,
                                                        fingerPrint,
                                                        sigValues));

        }

    }

}
