using System;
using System.Collections;
using System.IO;
using System.Text;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Signers
{

    public class DsaDigestSigner : ISigner
    {

        private readonly IDigest  digest;
        private readonly IDsa     dsaSigner;
        private          Boolean  forSigning;

        public DsaDigestSigner(IDsa     signer,
                               IDigest  digest)
        {

            this.digest     = digest;
            this.dsaSigner  = signer;

        }

        public string AlgorithmName
        {
            get
            {
                return digest.AlgorithmName + "with" + dsaSigner.AlgorithmName;
            }
        }

        public void Init(Boolean            forSigning,
                         ICipherParameters  parameters)
        {

            this.forSigning = forSigning;

            AsymmetricKeyParameter k;

            if (parameters is ParametersWithRandom)
            {
                k = (AsymmetricKeyParameter) ((ParametersWithRandom) parameters).Parameters;
            }
            else
            {
                k = (AsymmetricKeyParameter) parameters;
            }

            if (forSigning && !k.IsPrivateKey)
                throw new InvalidKeyException("Signing Requires Private Key.");

            if (!forSigning && k.IsPrivateKey)
                throw new InvalidKeyException("Verification Requires Public Key.");

            Reset();

            dsaSigner.Init(forSigning, parameters);

        }

        /// <summary>
        /// Update the internal digest with the byte b.
        /// </summary>
        public void Update(Byte input)
        {
            digest.Update(input);
        }

        /// <summary>
        /// update the internal digest with the byte array in.
        /// </summary>
        public void BlockUpdate(Byte[]  input,
                                int     inOff,
                                int     length)
        {
            digest.BlockUpdate(input, inOff, length);
        }

        /// <summary>
        /// Generate a signature for the message we've been loaded with using the key we were initialised with.
        /// </summary>
        public byte[] GenerateSignature()
        {

            if (!forSigning)
                throw new InvalidOperationException("DSADigestSigner not initialised for signature generation.");

            var hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);

            var sig = dsaSigner.GenerateSignature(hash);

            return DerEncode(sig[0], sig[1]);

        }

        /// <summary>
        /// True if the internal state represents the signature described in the passed in array.
        /// </summary>
        public Boolean VerifySignature(Byte[] signature)
        {

            if (forSigning)
                throw new InvalidOperationException("DSADigestSigner not initialised for verification");

            byte[] hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);

            try
            {
                var sig = DerDecode(signature);
                return dsaSigner.VerifySignature(hash, sig[0], sig[1]);
            }
            catch (IOException e)
            {
                return false;
            }

        }


        public Boolean VerifySignature(BigInteger  sig0,
                                       BigInteger  sig1)
        {

            if (forSigning)
                throw new InvalidOperationException("DSADigestSigner not initialised for verification");

            var hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);

            try
            {
                return dsaSigner.VerifySignature(hash, sig0, sig1);
            }
            catch (IOException e)
            {
                return false;
            }

        }

        /// <summary>
        /// Reset the internal state.
        /// </summary>
        public void Reset()
        {
            digest.Reset();
        }

        private Byte[] DerEncode(BigInteger  r,
                                 BigInteger  s)
        {
            return new DerSequence(new DerInteger(r), new DerInteger(s)).GetDerEncoded();
        }

        private BigInteger[] DerDecode(Byte[] encoding)
        {

            var s = (Asn1Sequence) Asn1Object.FromByteArray(encoding);

            return new BigInteger[]
            {
                ((DerInteger) s[0]).Value,
                ((DerInteger) s[1]).Value
            };

        }

    }

}
