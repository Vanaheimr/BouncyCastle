using System;
using System.Collections;
using System.IO;
using System.Text;

using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Examples
{

    /**
    * A simple utility class that creates clear signed files and verifies them.
    * <p>
    * To sign a file: ClearSignedFileProcessor -s fileName secretKey passPhrase HashAlgorithm
    * </p>
    * <p>
    * To decrypt: ClearSignedFileProcessor -v fileName signatureFile publicKeyFile.
    * </p>
    */
    public sealed class ClearSignedFileProcessor
    {

        private ClearSignedFileProcessor()
        {
        }

        private static int ReadInputLine(MemoryStream    bOut,
                                         Stream          fIn)
        {

            bOut.SetLength(0);

            int lookAhead = -1;
            int ch;

            while ((ch = fIn.ReadByte()) >= 0)
            {
                bOut.WriteByte((byte) ch);
                if (ch == '\r' || ch == '\n')
                {
                    lookAhead = ReadPassedEol(bOut, ch, fIn);
                    break;
                }
            }

            return lookAhead;

        }

        private static int ReadInputLine(MemoryStream  bOut,
                                         Int32         lookAhead,
                                         Stream        fIn)
        {

            bOut.SetLength(0);

            int ch = lookAhead;

            do
            {
                bOut.WriteByte((byte) ch);
                if (ch == '\r' || ch == '\n')
                {
                    lookAhead = ReadPassedEol(bOut, ch, fIn);
                    break;
                }
            }
            while ((ch = fIn.ReadByte()) >= 0);

            if (ch < 0)
            {
                lookAhead = -1;
            }

            return lookAhead;

        }

        private static int ReadPassedEol(
            MemoryStream    bOut,
            int                lastCh,
            Stream            fIn)
        {
            int lookAhead = fIn.ReadByte();

            if (lastCh == '\r' && lookAhead == '\n')
            {
                bOut.WriteByte((byte) lookAhead);
                lookAhead = fIn.ReadByte();
            }

            return lookAhead;
        }

        /*
        * verify a clear text signed file
        */
        private static void VerifyFile(
            Stream    inputStream,
            Stream    keyIn,
            string    resultName)
        {
            ArmoredInputStream aIn = new ArmoredInputStream(inputStream);
            Stream outStr = File.Create(resultName);

            //
            // write out signed section using the local line separator.
            // note: trailing white space needs to be removed from the end of
            // each line RFC 4880 Section 7.1
            //
            MemoryStream lineOut = new MemoryStream();
            int lookAhead = ReadInputLine(lineOut, aIn);
            byte[] lineSep = LineSeparator;

            if (lookAhead != -1 && aIn.IsClearText)
            {
                byte[] line = lineOut.ToArray();
                outStr.Write(line, 0, GetLengthWithoutSeparatorOrTrailingWhitespace(line));
                outStr.Write(lineSep, 0, lineSep.Length);

                while (lookAhead != -1 && aIn.IsClearText)
                {
                    lookAhead  = ReadInputLine(lineOut, lookAhead, aIn);
                    line       = lineOut.ToArray();
                    outStr.Write(line, 0, GetLengthWithoutSeparatorOrTrailingWhitespace(line));
                    outStr.Write(lineSep, 0, lineSep.Length);
                }
            }

            outStr.Close();

            PgpPublicKeyRingBundle pgpRings = new PgpPublicKeyRingBundle(keyIn);

            PgpObjectFactory pgpFact = new PgpObjectFactory(aIn);
            PgpSignatureList p3 = (PgpSignatureList) pgpFact.NextPgpObject();
            PgpSignature sig = p3[0];

            sig.InitVerify(pgpRings.GetPublicKey(sig.KeyId));

            //
            // read the input, making sure we ignore the last (Environment.NewLine).
            //
            Stream sigIn = File.OpenRead(resultName);

            lookAhead = ReadInputLine(lineOut, sigIn);

            ProcessLine(sig, lineOut.ToArray());

            if (lookAhead != -1)
            {
                do
                {
                    lookAhead = ReadInputLine(lineOut, lookAhead, sigIn);

                    sig.Update((byte) '\r');
                    sig.Update((byte) '\n');

                    ProcessLine(sig, lineOut.ToArray());
                }
                while (lookAhead != -1);
            }

            sigIn.Close();

            if (sig.IsValid)
                Console.WriteLine("signature verified.");

            else
                Console.WriteLine("signature verification failed.");

        }

        private static byte[] LineSeparator
        {
            get { return Encoding.ASCII.GetBytes(Environment.NewLine); }
        }


        private static void SignFile(String  fileName,
                                     Stream  keyIn,
                                     Stream  outputStream,
                                     String  pass,
                                     String  digestName)
        {

            HashAlgorithms HashAlgorithm;

            if (digestName.Equals("SHA256"))
                HashAlgorithm = HashAlgorithms.Sha256;

            else if (digestName.Equals("SHA384"))
                HashAlgorithm = HashAlgorithms.Sha384;

            else if (digestName.Equals("SHA512"))
                HashAlgorithm = HashAlgorithms.Sha512;

            else if (digestName.Equals("MD5"))
                HashAlgorithm = HashAlgorithms.MD5;

            else if (digestName.Equals("RIPEMD160"))
                HashAlgorithm = HashAlgorithms.RipeMD160;

            else
                HashAlgorithm = HashAlgorithms.Sha1;

            var SecretKey                    = PgpExampleUtilities.ReadSecretKey(keyIn);
            var PrivateKey                   = SecretKey.ExtractPrivateKey(pass);
            var SignatureGenerator           = new PgpSignatureGenerator(SecretKey.PublicKey.Algorithm, HashAlgorithm);
            var SignatureSubpacketGenerator  = new PgpSignatureSubpacketGenerator();

            SignatureGenerator.InitSign(PgpSignatureTypes.CanonicalTextDocument, PrivateKey);

            foreach (var UserId in SecretKey.PublicKey.UserIds)
            {
                SignatureSubpacketGenerator.SetSignerUserId(false, UserId);
                SignatureGenerator.SetHashedSubpackets(SignatureSubpacketGenerator.Generate());
            }

            var FileToSignStream  = File.OpenRead(fileName);
            var aOutputStream     = new ArmoredOutputStream(outputStream);

            aOutputStream.BeginClearText(HashAlgorithm);

            // note the last \n/\r/\r\n in the file is ignored
            var lineOut    = new MemoryStream();
            var lookAhead  = ReadInputLine(lineOut, FileToSignStream);

            ProcessLine(aOutputStream, SignatureGenerator, lineOut.ToArray());

            if (lookAhead != -1)
            {

                do
                {

                    lookAhead = ReadInputLine(lineOut, lookAhead, FileToSignStream);

                    SignatureGenerator.Update((byte) '\r');
                    SignatureGenerator.Update((byte) '\n');

                    ProcessLine(aOutputStream, SignatureGenerator, lineOut.ToArray());

                }

                while (lookAhead != -1);

            }

            FileToSignStream.Close();

            aOutputStream.EndClearText();

            var bOut = new BcpgOutputStream(aOutputStream);

            SignatureGenerator.Generate().Encode(bOut);

            aOutputStream.Close();

        }

        private static void ProcessLine(PgpSignature  sig,
                                        byte[]        line)
        {

            // note: trailing white space needs to be removed from the end of
            // each line for signature calculation RFC 4880 Section 7.1
            var length = GetLengthWithoutWhiteSpace(line);
            if (length > 0)
            {
                sig.Update(line, 0, length);
            }

        }

        private static void ProcessLine(Stream                 aOut,
                                        PgpSignatureGenerator  sGen,
                                        Byte[]                 line)
        {

            var length = GetLengthWithoutWhiteSpace(line);

            if (length > 0)
                sGen.Update(line, 0, (Int32) length);

            aOut.Write(line, 0, line.Length);

        }

        private static int GetLengthWithoutSeparatorOrTrailingWhitespace(Byte[] line)
        {

            var end = line.Length - 1;

            while (end >= 0 && IsWhiteSpace(line[end]))
                end--;

            return end + 1;

        }

        private static bool IsLineEnding(Byte b)
        {
            return b == '\r' || b == '\n';
        }

        private static UInt64 GetLengthWithoutWhiteSpace(byte[] line)
        {

            var end = (UInt64) line.Length - 1;

            while (end >= 0 && IsWhiteSpace(line[end]))
            {
                end--;
            }

            return end + 1;

        }

        private static bool IsWhiteSpace(byte b)
        {
            return IsLineEnding(b) || b == '\t' || b == ' ';
        }

        public static void Main(String[] args)
        {

            // ClearSignedFileProcessor -s fileName secretKey passPhrase HashAlgorithm
            if (args[0].Equals("-s"))
            {

                var FileToSignName          = args[1];
                var SecretKeyStream         = File.OpenRead(args[2]);
                var SignedFileStream        = File.Create(args[1] + ".asc");
                var SecretKeyDecodedStream  = PgpUtilities.GetDecoderStream(SecretKeyStream);
                var passPhrase              = args[3];
                var HashDigestName          = (args.Length == 4) ? "SHA512" : args[4];

                SignFile(FileToSignName, SecretKeyDecodedStream, SignedFileStream, passPhrase, HashDigestName);

                SecretKeyStream.Close();
                SignedFileStream.Close();

            }

            else if (args[0].Equals("-v"))
            {

                if (args[1].IndexOf(".asc") < 0)
                {
                    Console.Error.WriteLine("file needs to end in \".asc\"");
                    Environment.Exit(1);
                }

                Stream fin = File.OpenRead(args[1]);
                Stream fis = File.OpenRead(args[2]);

                Stream keyIn = PgpUtilities.GetDecoderStream(fis);

                VerifyFile(fin, keyIn, args[1].Substring(0, args[1].Length - 4));

                fin.Close();
                fis.Close();

            }

            else
                Console.Error.WriteLine("usage: ClearSignedFileProcessor [-s file keyfile passPhrase]|[-v sigFile keyFile]");

        }

    }

}
