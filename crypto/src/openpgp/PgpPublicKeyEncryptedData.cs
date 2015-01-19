using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    /// <summary>
    /// A public key encrypted data object.
    /// </summary>
    public class PgpPublicKeyEncryptedData : PgpEncryptedData
    {

        private PublicKeyEncSessionPacket keyData;

        internal PgpPublicKeyEncryptedData(PublicKeyEncSessionPacket    keyData,
                                           InputStreamPacket            encData)
            : base(encData)
        {
            this.keyData = keyData;
        }

        private static IBufferedCipher GetKeyCipher(PublicKeyAlgorithms PublicKeyAlgorithm)
        {

            try
            {

                switch (PublicKeyAlgorithm)
                {

                    case PublicKeyAlgorithms.RsaEncrypt:
                    case PublicKeyAlgorithms.RsaGeneral:
                        return CipherUtilities.GetCipher("RSA//PKCS1Padding");

                    case PublicKeyAlgorithms.ElGamalEncrypt:
                    case PublicKeyAlgorithms.ElGamalGeneral:
                        return CipherUtilities.GetCipher("ElGamal/ECB/PKCS1Padding");

                    default:
                        throw new PgpException("unknown asymmetric algorithm: " + PublicKeyAlgorithm);

                }

            }
            catch (PgpException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception creating cipher", e);
            }

        }

        private bool ConfirmCheckSum(Byte[] sessionInfo)
        {

            int check = 0;

            for (int i = 1; i != sessionInfo.Length - 2; i++)
                check += sessionInfo[i] & 0xff;

            return (sessionInfo[sessionInfo.Length - 2] == (byte) (check >> 8)) &&
                   (sessionInfo[sessionInfo.Length - 1] == (byte) (check));

        }

        /// <summary>The key ID for the key used to encrypt the data.</summary>
        public UInt64 KeyId
        {
            get { return keyData.KeyId; }
        }

        /// <summary>
        /// Return the algorithm code for the symmetric algorithm used to encrypt the data.
        /// </summary>
        public SymmetricKeyAlgorithms GetSymmetricAlgorithm(PgpPrivateKey PrivateKey)
        {

            var plain = fetchSymmetricKeyData(PrivateKey);

            return (SymmetricKeyAlgorithms) plain[0];

        }

        /// <summary>Return the decrypted data stream for the packet.</summary>
        public Stream GetDataStream(PgpPrivateKey PrivateKey)
        {

            var plain = fetchSymmetricKeyData(PrivateKey);

            IBufferedCipher c2;
            var cipherName  = PgpUtilities.GetSymmetricCipherName((SymmetricKeyAlgorithms) plain[0]);
            var cName       = cipherName;

            try
            {
                if (encData is SymmetricEncIntegrityPacket)
                {
                    cName += "/CFB/NoPadding";
                }
                else
                {
                    cName += "/OpenPGPCFB/NoPadding";
                }

                c2 = CipherUtilities.GetCipher(cName);
            }
            catch (PgpException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PgpException("exception creating cipher", e);
            }

            if (c2 == null)
                return encData.GetInputStream();

            try
            {

                var key  = ParameterUtilities.CreateKeyParameter(cipherName, plain, 1, plain.Length - 3);
                var iv   = new Byte[c2.GetBlockSize()];

                c2.Init(false, new ParametersWithIV(key, iv));

                encStream = BcpgInputStream.Wrap(new CipherStream(encData.GetInputStream(), c2, null));

                if (encData is SymmetricEncIntegrityPacket)
                {
                    truncStream = new TruncatedStream(encStream);

                    var digestName  = PgpUtilities.GetDigestName(HashAlgorithms.Sha1);
                    var digest      = DigestUtilities.GetDigest(digestName);

                    encStream = new DigestStream(truncStream, digest, null);
                }

                if (Streams.ReadFully(encStream, iv, 0, iv.Length) < iv.Length)
                    throw new EndOfStreamException("unexpected end of stream.");

                int v1 = encStream.ReadByte();
                int v2 = encStream.ReadByte();

                if (v1 < 0 || v2 < 0)
                    throw new EndOfStreamException("unexpected end of stream.");

                // Note: the oracle attack on the "quick check" bytes is deemed
                // a security risk for typical public key encryption usages,
                // therefore we do not perform the check.

//                bool repeatCheckPassed =
//                    iv[iv.Length - 2] == (byte)v1
//                    &&    iv[iv.Length - 1] == (byte)v2;
//
//                // Note: some versions of PGP appear to produce 0 for the extra
//                // bytes rather than repeating the two previous bytes
//                bool zeroesCheckPassed =
//                    v1 == 0
//                    &&    v2 == 0;
//
//                if (!repeatCheckPassed && !zeroesCheckPassed)
//                {
//                    throw new PgpDataValidationException("quick check failed.");
//                }

                return encStream;

            }
            catch (PgpException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception starting decryption", e);
            }

        }

        private byte[] fetchSymmetricKeyData(PgpPrivateKey privKey)
        {

            var Cipher = GetKeyCipher(keyData.Algorithm);

            try
            {
                Cipher.Init(false, privKey.PrivateKey);
            }
            catch (InvalidKeyException e)
            {
                throw new PgpException("error setting asymmetric cipher", e);
            }

            var keyD = keyData.GetEncSessionKey();

            if (keyData.Algorithm == PublicKeyAlgorithms.RsaEncrypt ||
                keyData.Algorithm == PublicKeyAlgorithms.RsaGeneral)
            {
                Cipher.ProcessBytes(keyD[0].ToByteArrayUnsigned());
            }

            else
            {

                var k     = (ElGamalPrivateKeyParameters) privKey.PrivateKey;
                int size  = (k.Parameters.P.BitLength + 7) / 8;

                byte[] bi = keyD[0].ToByteArray();

                int diff = bi.Length - size;
                if (diff >= 0)
                {
                    Cipher.ProcessBytes(bi, diff, size);
                }
                else
                {
                    byte[] zeros = new byte[-diff];
                    Cipher.ProcessBytes(zeros);
                    Cipher.ProcessBytes(bi);
                }

                bi = keyD[1].ToByteArray();

                diff = bi.Length - size;
                if (diff >= 0)
                {
                    Cipher.ProcessBytes(bi, diff, size);
                }
                else
                {
                    byte[] zeros = new byte[-diff];
                    Cipher.ProcessBytes(zeros);
                    Cipher.ProcessBytes(bi);
                }

            }

            byte[] plain;
            try
            {
                plain = Cipher.DoFinal();
            }
            catch (Exception e)
            {
                throw new PgpException("exception decrypting secret key", e);
            }

            if (!ConfirmCheckSum(plain))
                throw new PgpKeyValidationException("key checksum failed");

            return plain;

        }

    }

}
