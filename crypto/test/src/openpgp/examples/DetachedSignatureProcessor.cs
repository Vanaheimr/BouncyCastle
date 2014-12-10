using System;
using System.Collections;
using System.IO;


using Org.BouncyCastle.Bcpg.OpenPgp;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Examples
{
    /**
    * A simple utility class that creates seperate signatures for files and verifies them.
    * <p>
    * To sign a file: DetachedSignatureProcessor -s [-a] fileName secretKey passPhrase.<br/>
    * If -a is specified the output file will be "ascii-armored".</p>
    * <p>
    * To decrypt: DetachedSignatureProcessor -v  fileName signatureFile publicKeyFile.</p>
    * <p>
    * Note: this example will silently overwrite files.
    * It also expects that a single pass phrase
    * will have been used.</p>
    */
    public sealed class DetachedSignatureProcessor
    {

        private DetachedSignatureProcessor()
        {
        }

        private static void VerifySignature(String  fileName,
                                            String  inputFileName,
                                            String  keyFileName)
        {

            using (Stream input  = File.OpenRead(inputFileName),
                          keyIn  = File.OpenRead(keyFileName))
            {
                VerifySignature(fileName, input, keyIn);
            }

        }

        /**
        * verify the signature in in against the file fileName.
        */
        private static void VerifySignature(String  fileName,
                                            Stream  inputStream,
                                            Stream  keyIn)
        {

            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            var               pgpFact    = new PgpObjectFactory(inputStream);
            PgpSignatureList  p3         = null;
            var               PGPObject  = pgpFact.NextPgpObject();

            if (PGPObject is PgpCompressedData)
            {
                var c1  = (PgpCompressedData) PGPObject;
                pgpFact = new PgpObjectFactory(c1.GetDataStream());
                p3      = (PgpSignatureList) pgpFact.NextPgpObject();
            }

            else
                p3 = (PgpSignatureList) PGPObject;

            var pgpPubRingCollection = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(keyIn));
            Stream                 dIn = File.OpenRead(fileName);
            var sig = p3[0];
            var key = pgpPubRingCollection.GetPublicKey(sig.KeyId);
            sig.InitVerify(key);

            int ch;
            while ((ch = dIn.ReadByte()) >= 0)
            {
                sig.Update((byte)ch);
            }

            dIn.Close();

            if (sig.Verify())
            {
                Console.WriteLine("signature verified.");
            }
            else
            {
                Console.WriteLine("signature verification failed.");
            }

        }

        private static void CreateSignature(String   inputFileName,
                                            String   keyFileName,
                                            String   outputFileName,
                                            String   passphrase,
                                            Boolean  armor)
        {
            using (var keyIn = File.OpenRead(keyFileName))
            {
                using (var output = File.Open(outputFileName, FileMode.Create, FileAccess.Write))
                {
                    CreateSignature(inputFileName, keyIn, output, passphrase, armor);
                }
            }
        }

        private static void CreateSignature(String   fileName,
                                            Stream   keyIn,
                                            Stream   outputStream,
                                            String   passphrase,
                                            Boolean  armor)
        {

            if (armor)
                outputStream = new ArmoredOutputStream(outputStream);

            var pgpSec      = PgpExampleUtilities.ReadSecretKey(keyIn);
            var pgpPrivKey  = pgpSec.ExtractPrivateKey(passphrase);
            var sGen        = new PgpSignatureGenerator(pgpSec.PublicKey.Algorithm, HashAlgorithmTag.Sha512);

            sGen.InitSign(PgpSignature.BinaryDocument, pgpPrivKey);

            var bOut        = new BcpgOutputStream(outputStream);

            Stream fIn = File.OpenRead(fileName);

            int ch;
            while ((ch = fIn.ReadByte()) >= 0)
            {
                sGen.Update((byte) ch);
            }

            fIn.Close();

            sGen.Generate().Encode(bOut);

            if (armor)
                outputStream.Close();

        }

        public static void Main(String[] args)
        {

            if (args[0].Equals("-s"))
            {
                if (args[1].Equals("-a"))
                {
                    CreateSignature(args[2], args[3], args[2] + ".asc", args[4], true);
                }
                else
                {
                    CreateSignature(args[1], args[2], args[1] + ".bpg", args[3], false);
                }
            }

            else if (args[0].Equals("-v"))
                VerifySignature(args[1], args[2], args[3]);

            else
                Console.Error.WriteLine("usage: DetachedSignatureProcessor [-s [-a] file keyfile passPhrase]|[-v file sigFile keyFile]");

        }

    }

}
