using System;
using System.IO;
using System.Text;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>Basic utility class.</remarks>
    public sealed class PgpUtilities
    {

        private PgpUtilities()
        {
        }

        public static MPInteger[] DsaSigToMpi(byte[] encoding)
        {

            DerInteger i1, i2;

            try
            {
                Asn1Sequence s = (Asn1Sequence) Asn1Object.FromByteArray(encoding);

                i1 = (DerInteger) s[0];
                i2 = (DerInteger) s[1];
            }
            catch (IOException e)
            {
                throw new PgpException("exception encoding signature", e);
            }

            return new MPInteger[]{ new MPInteger(i1.Value), new MPInteger(i2.Value) };

        }

        public static MPInteger[] RsaSigToMpi(byte[] encoding)
        {
            return new MPInteger[]{ new MPInteger(new BigInteger(1, encoding)) };
        }

        public static String GetDigestName(HashAlgorithms hashAlgorithm)
        {

            switch (hashAlgorithm)
            {
                case HashAlgorithms.Sha1:
                    return "SHA1";
                case HashAlgorithms.MD2:
                    return "MD2";
                case HashAlgorithms.MD5:
                    return "MD5";
                case HashAlgorithms.RipeMD160:
                    return "RIPEMD160";
                case HashAlgorithms.Sha224:
                    return "SHA224";
                case HashAlgorithms.Sha256:
                    return "SHA256";
                case HashAlgorithms.Sha384:
                    return "SHA384";
                case HashAlgorithms.Sha512:
                    return "SHA512";
                default:
                    throw new PgpException("unknown hash algorithm tag in GetDigestName: " + hashAlgorithm);
            }

        }

        public static String GetSignatureName(PublicKeyAlgorithms  keyAlgorithm,
                                              HashAlgorithms       hashAlgorithm)
        {

            string encAlg;

            switch (keyAlgorithm)
            {

                case PublicKeyAlgorithms.RsaGeneral:
                case PublicKeyAlgorithms.RsaSign:
                    encAlg = "RSA";
                    break;

                case PublicKeyAlgorithms.Dsa:
                    encAlg = "DSA";
                    break;

                case PublicKeyAlgorithms.ElGamalEncrypt: // in some malformed cases.
                case PublicKeyAlgorithms.ElGamalGeneral:
                    encAlg = "ElGamal";
                    break;

                default:
                    throw new PgpException("unknown algorithm tag in signature:" + keyAlgorithm);

            }

            return GetDigestName(hashAlgorithm) + "with" + encAlg;

        }

        public static String GetSymmetricCipherName(SymmetricKeyAlgorithms algorithm)
        {

            switch (algorithm)
            {
                case SymmetricKeyAlgorithms.Null:
                    return null;
                case SymmetricKeyAlgorithms.TripleDes:
                    return "DESEDE";
                case SymmetricKeyAlgorithms.Idea:
                    return "IDEA";
                case SymmetricKeyAlgorithms.Cast5:
                    return "CAST5";
                case SymmetricKeyAlgorithms.Blowfish:
                    return "Blowfish";
                case SymmetricKeyAlgorithms.Safer:
                    return "SAFER";
                case SymmetricKeyAlgorithms.Des:
                    return "DES";
                case SymmetricKeyAlgorithms.Aes128:
                    return "AES";
                case SymmetricKeyAlgorithms.Aes192:
                    return "AES";
                case SymmetricKeyAlgorithms.Aes256:
                    return "AES";
                case SymmetricKeyAlgorithms.Twofish:
                    return "Twofish";
                case SymmetricKeyAlgorithms.Camellia128:
                    return "Camellia";
                case SymmetricKeyAlgorithms.Camellia192:
                    return "Camellia";
                case SymmetricKeyAlgorithms.Camellia256:
                    return "Camellia";
                default:
                    throw new PgpException("unknown symmetric algorithm: " + algorithm);
            }

        }

        public static int GetKeySize(SymmetricKeyAlgorithms algorithm)
        {

            int keySize;

            switch (algorithm)
            {

                case SymmetricKeyAlgorithms.Des:
                    keySize = 64;
                    break;

                case SymmetricKeyAlgorithms.Idea:
                case SymmetricKeyAlgorithms.Cast5:
                case SymmetricKeyAlgorithms.Blowfish:
                case SymmetricKeyAlgorithms.Safer:
                case SymmetricKeyAlgorithms.Aes128:
                case SymmetricKeyAlgorithms.Camellia128:
                    keySize = 128;
                    break;

                case SymmetricKeyAlgorithms.TripleDes:
                case SymmetricKeyAlgorithms.Aes192:
                case SymmetricKeyAlgorithms.Camellia192:
                    keySize = 192;
                    break;

                case SymmetricKeyAlgorithms.Aes256:
                case SymmetricKeyAlgorithms.Twofish:
                case SymmetricKeyAlgorithms.Camellia256:
                    keySize = 256;
                    break;

                default:
                    throw new PgpException("unknown symmetric algorithm: " + algorithm);

            }

            return keySize;

        }

        public static KeyParameter MakeKey(SymmetricKeyAlgorithms  algorithm,
                                           Byte[]                  keyBytes)
        {

            var algName = GetSymmetricCipherName(algorithm);

            return ParameterUtilities.CreateKeyParameter(algName, keyBytes);

        }

        public static KeyParameter MakeRandomKey(SymmetricKeyAlgorithms  algorithm,
                                                 SecureRandom            random)
        {

            var keySize   = GetKeySize(algorithm);
            var keyBytes  = new byte[(keySize + 7) / 8];
            random.NextBytes(keyBytes);

            return MakeKey(algorithm, keyBytes);

        }

        public static KeyParameter MakeKeyFromPassPhrase(SymmetricKeyAlgorithms  algorithm,
                                                         S2k                       s2k,
                                                         String                    passPhrase)
        {

            var keySize   = GetKeySize(algorithm);
            var pBytes    = Strings.ToByteArray(passPhrase);
            var keyBytes  = new byte[(keySize + 7) / 8];

            int generatedBytes  = 0;
            int loopCount       = 0;

            while (generatedBytes < keyBytes.Length)
            {

                IDigest digest;

                if (s2k != null)
                {
                    string digestName = GetDigestName(s2k.HashAlgorithm);

                    try
                    {
                        digest = DigestUtilities.GetDigest(digestName);
                    }
                    catch (Exception e)
                    {
                        throw new PgpException("can't find S2k digest", e);
                    }

                    for (int i = 0; i != loopCount; i++)
                    {
                        digest.Update(0);
                    }

                    byte[] iv = s2k.GetIV();

                    switch (s2k.Type)
                    {
                        case S2k.Simple:
                            digest.BlockUpdate(pBytes, 0, pBytes.Length);
                            break;
                        case S2k.Salted:
                            digest.BlockUpdate(iv, 0, iv.Length);
                            digest.BlockUpdate(pBytes, 0, pBytes.Length);
                            break;
                        case S2k.SaltedAndIterated:
                            long count = s2k.IterationCount;
                            digest.BlockUpdate(iv, 0, iv.Length);
                            digest.BlockUpdate(pBytes, 0, pBytes.Length);

                            count -= iv.Length + pBytes.Length;

                            while (count > 0)
                            {
                                if (count < iv.Length)
                                {
                                    digest.BlockUpdate(iv, 0, (int)count);
                                    break;
                                }
                                else
                                {
                                    digest.BlockUpdate(iv, 0, iv.Length);
                                    count -= iv.Length;
                                }

                                if (count < pBytes.Length)
                                {
                                    digest.BlockUpdate(pBytes, 0, (int)count);
                                    count = 0;
                                }
                                else
                                {
                                    digest.BlockUpdate(pBytes, 0, pBytes.Length);
                                    count -= pBytes.Length;
                                }
                            }
                            break;
                        default:
                            throw new PgpException("unknown S2k type: " + s2k.Type);
                    }
                }
                else
                {
                    try
                    {
                        digest = DigestUtilities.GetDigest("MD5");

                        for (int i = 0; i != loopCount; i++)
                        {
                            digest.Update(0);
                        }

                        digest.BlockUpdate(pBytes, 0, pBytes.Length);
                    }
                    catch (Exception e)
                    {
                        throw new PgpException("can't find MD5 digest", e);
                    }
                }

                byte[] dig = DigestUtilities.DoFinal(digest);

                if (dig.Length > (keyBytes.Length - generatedBytes))
                {
                    Array.Copy(dig, 0, keyBytes, generatedBytes, keyBytes.Length - generatedBytes);
                }
                else
                {
                    Array.Copy(dig, 0, keyBytes, generatedBytes, dig.Length);
                }

                generatedBytes += dig.Length;

                loopCount++;
            }

            Array.Clear(pBytes, 0, pBytes.Length);

            return MakeKey(algorithm, keyBytes);
        }

        /// <summary>
        /// Write out the passed in file as a literal data packet.
        /// </summary>
        public static void WriteFileToLiteralData(Stream    output,
                                                  Char      fileType,
                                                  FileInfo  file)
        {
            var lData = new PgpLiteralDataGenerator();
            var pOut = lData.Open(fileType, file.Name, (UInt64) file.Length, file.LastWriteTime, output);
            PipeFileContents(file, pOut, 4096);
        }

        /// <summary>
        /// Write out the passed in file as a literal data packet in partial packet format.
        /// </summary>
        public static void WriteFileToLiteralData(Stream    output,
                                                  Char      fileType,
                                                  FileInfo  file,
                                                  Byte[]    buffer)
        {
            var lData = new PgpLiteralDataGenerator();
            var pOut  = lData.Open(fileType, file.Name, file.LastWriteTime, output, buffer);
            PipeFileContents(file, pOut, buffer.Length);
        }

        private static void PipeFileContents(FileInfo  file,
                                             Stream    pOut,
                                             Int32     bufSize)
        {

            var inputStream  = file.OpenRead();
            var buf          = new byte[bufSize];

            int len;
            while ((len = inputStream.Read(buf, 0, buf.Length)) > 0)
            {
                pOut.Write(buf, 0, len);
            }

            pOut.Close();
            inputStream.Close();

        }

        private const Int32 ReadAhead = 60;

        private static Boolean IsPossiblyBase64(Int32 ch)
        {

            return (ch >= 'A' && ch <= 'Z') ||
                   (ch >= 'a' && ch <= 'z') ||
                   (ch >= '0' && ch <= '9') ||
                   (ch == '+')              ||
                   (ch == '/')              ||
                   (ch == '\r')             ||
                   (ch == '\n');

        }

        /// <summary>
        /// Return either an ArmoredInputStream or a BcpgInputStream based on whether
        /// the initial characters of the stream are binary PGP encodings or not.
        /// </summary>
        public static Stream GetDecoderStream(Stream InputStream)
        {

            // TODO Remove this restriction?
            if (!InputStream.CanSeek)
                throw new ArgumentException("inputStream must be seek-able", "inputStream");

            var markedPos = InputStream.Position;

            int ch = InputStream.ReadByte();
            if ((ch & 0x80) != 0)
            {
                InputStream.Position = markedPos;
                return InputStream;
            }

            else
            {

                if (!IsPossiblyBase64(ch))
                {
                    InputStream.Position = markedPos;
                    return new ArmoredInputStream(InputStream);
                }

                var buf    = new Byte[ReadAhead];
                var count  = 1;
                var index  = 1;

                buf[0] = (byte) ch;
                while (count != ReadAhead && (ch = InputStream.ReadByte()) >= 0)
                {

                    if (!IsPossiblyBase64(ch))
                    {

                        InputStream.Position = markedPos;

                        return new ArmoredInputStream(InputStream);

                    }

                    if (ch != '\n' && ch != '\r')
                        buf[index++] = (byte)ch;

                    count++;

                }

                InputStream.Position = markedPos;

                // nothing but new lines, little else, assume regular armoring
                if (count < 4)
                    return new ArmoredInputStream(InputStream);


                // test our non-blank data
                var firstBlock = new byte[8];
                Array.Copy(buf, 0, firstBlock, 0, firstBlock.Length);
                var decoded = Base64.Decode(firstBlock);


                // it's a base64 PGP block.
                var hasHeaders = (decoded[0] & 0x80) == 0;

                return new ArmoredInputStream(InputStream, hasHeaders);

            }

        }

    }

}
