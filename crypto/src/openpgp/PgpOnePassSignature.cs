using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>A one pass signature object.</remarks>
    public class PgpOnePassSignature
    {

        private OnePassSignaturePacket  sigPack;
        private PgpSignatures           signatureType;
        private ISigner                 sig;
        private Byte                    lastb;

        internal PgpOnePassSignature(BcpgInputStream bcpgInput)
            : this((OnePassSignaturePacket) bcpgInput.ReadPacket())
        { }

        internal PgpOnePassSignature(OnePassSignaturePacket sigPack)
        {
            this.sigPack        = sigPack;
            this.signatureType  = sigPack.SignatureType;
        }

        /// <summary>Initialise the signature object for verification.</summary>
        public void InitVerify(PgpPublicKey pubKey)
        {

            lastb = 0;

            try
            {
                sig = SignerUtilities.GetSigner(PgpUtilities.GetSignatureName(sigPack.KeyAlgorithm, sigPack.HashAlgorithm));
            }
            catch (Exception e)
            {
                throw new PgpException("can't set up signature object.",  e);
            }

            try
            {
                sig.Init(false, pubKey.GetKey());
            }
            catch (InvalidKeyException e)
            {
                throw new PgpException("invalid key.", e);
            }

        }

        public void Update(Byte b)
        {

            if (signatureType == PgpSignatures.CanonicalTextDocument)
                doCanonicalUpdateByte(b);

            else
                sig.Update(b);

        }

        private void doCanonicalUpdateByte(Byte b)
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
                sig.Update(b);
            }

            lastb = b;
        }

        private void doUpdateCRLF()
        {
            sig.Update((byte)'\r');
            sig.Update((byte)'\n');
        }

        public void Update(
            byte[] bytes)
        {
            if (signatureType == PgpSignatures.CanonicalTextDocument)
            {
                for (int i = 0; i != bytes.Length; i++)
                {
                    doCanonicalUpdateByte(bytes[i]);
                }
            }
            else
            {
                sig.BlockUpdate(bytes, 0, bytes.Length);
            }
        }

        public void Update(
            byte[]  bytes,
            int     off,
            int     length)
        {
            if (signatureType == PgpSignatures.CanonicalTextDocument)
            {
                int finish = off + length;

                for (int i = off; i != finish; i++)
                {
                    doCanonicalUpdateByte(bytes[i]);
                }
            }
            else
            {
                sig.BlockUpdate(bytes, off, length);
            }
        }

        /// <summary>Verify the calculated signature against the passed in PgpSignature.</summary>
        public bool Verify(PgpSignature pgpSig)
        {

            var trailer = pgpSig.SignatureTrailer;

            sig.BlockUpdate(trailer, 0, trailer.Length);

            return sig.VerifySignature(pgpSig.Signature);

        }

        public UInt64 KeyId
        {
            get { return sigPack.KeyId; }
        }

        public PgpSignatures SignatureType
        {
            get { return sigPack.SignatureType; }
        }

        public HashAlgorithms HashAlgorithm
        {
            get { return sigPack.HashAlgorithm; }
        }

        public PublicKeyAlgorithms KeyAlgorithm
        {
            get { return sigPack.KeyAlgorithm; }
        }

        public byte[] GetEncoded()
        {
            MemoryStream bOut = new MemoryStream();

            Encode(bOut);

            return bOut.ToArray();
        }

        public void Encode(Stream outStr)
        {
            BcpgOutputStream.Wrap(outStr).WritePacket(sigPack);
        }

    }

}
