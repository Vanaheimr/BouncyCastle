using System;
using System.Collections;
using System.IO;
using System.Text;

using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Examples
{

    /**
    * Simple routine to encrypt and decrypt using a passphrase.
    * This service routine provides the basic PGP services between
    * byte arrays.
    *
    * Note: this code plays no attention to -Console in the file name
    * the specification of "_CONSOLE" in the filename.
    * It also expects that a single pass phrase will have been used.
    *
    */
    public sealed class ByteArrayHandler
    {

        /// <summary>
        /// Decrypt the passed in message stream.
        /// I18N considerations are not handled by this routine.
        /// </summary>
        /// <param name="EncryptedText">The message to be decrypted.</param>
        /// <param name="Passphrase">Pass phrase (key)</param>
        /// <returns></returns>
        public static Byte[] Decrypt(Byte[]  EncryptedText,
                                     String  Passphrase)
        {

            Stream inputStream = new MemoryStream(EncryptedText);

            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            var pgpF = new PgpObjectFactory(inputStream);
            PgpEncryptedDataList enc = null;
            var o = pgpF.NextPgpObject();

            //
            // the first object might be a PGP marker packet.
            //
            if (o is PgpEncryptedDataList)
                enc = (PgpEncryptedDataList) o;

            else
                enc = (PgpEncryptedDataList) pgpF.NextPgpObject();

            PgpPbeEncryptedData pbe = (PgpPbeEncryptedData) enc[0];

            Stream clear = pbe.GetDataStream(Passphrase);

            PgpObjectFactory pgpFact = new PgpObjectFactory(clear);

            PgpCompressedData cData = (PgpCompressedData) pgpFact.NextPgpObject();

            pgpFact = new PgpObjectFactory(cData.GetDataStream());

            PgpLiteralData ld = (PgpLiteralData) pgpFact.NextPgpObject();

            Stream unc = ld.InputStream;

            return Streams.ReadAll(unc);

        }



        /// <summary>
        /// Simple PGP encryptor between byte[].
        /// </summary>
        /// <param name="Plaintext">The test to be encrypted</param>
        /// <param name="Passphrase">The pass phrase (key). This method assumes that the key is a simple pass phrase, and does not yet support RSA or more sophisiticated keying.</param>
        /// <param name="fileName">
        /// File name. This is used in the Literal Data Packet (tag 11)
        /// which is really inly important if the data is to be
        /// related to a file to be recovered later.  Because this
        /// routine does not know the source of the information, the
        /// caller can set something here for file name use that
        /// will be carried.  If this routine is being used to
        /// encrypt SOAP MIME bodies, for example, use the file name from the
        /// MIME type, if applicable. Or anything else appropriate.
        /// </param>
        /// <param name="EncryptionAlgorithm"></param>
        /// <param name="UseArmor"></param>
        public static Byte[] Encrypt(Byte[]                  Plaintext,
                                     String                  Passphrase,
                                     String                  fileName,
                                     SymmetricKeyAlgorithms  EncryptionAlgorithm,
                                     Boolean                 UseArmor)
        {

            if (fileName == null)
                fileName = PgpLiteralData.Console;

            var compressedData = Compress(Plaintext, fileName, CompressionAlgorithms.Zip);

            var bOut = new MemoryStream();

            Stream output = bOut;
            if (UseArmor)
                output = new ArmoredOutputStream(output);

            var encGen = new PgpEncryptedDataGenerator(EncryptionAlgorithm, new SecureRandom());
            encGen.AddMethod(Passphrase);

            Stream encOut = encGen.Open(output, (UInt64) compressedData.Length);

            encOut.Write(compressedData, 0, compressedData.Length);
            encOut.Close();

            if (UseArmor)
                output.Close();

            return bOut.ToArray();

        }

        private static byte[] Compress(Byte[] clearData, String fileName, CompressionAlgorithms algorithm)
        {

            var bOut    = new MemoryStream();
            var comData = new PgpCompressedDataGenerator(algorithm);
            var cos     = comData.Open(bOut); // open it with the final destination
            var lData   = new PgpLiteralDataGenerator();

            // we want to Generate compressed data. This might be a user option later,
            // in which case we would pass in bOut.
            var pOut = lData.Open(
                cos,                        // the compressed output stream
                PgpLiteralData.Binary,
                fileName,                   // "filename" to store
                (UInt64) clearData.Length,  // length of clear data
                DateTime.UtcNow             // current time
            );

            pOut.Write(clearData, 0, clearData.Length);
            pOut.Close();

            comData.Close();

            return bOut.ToArray();

        }

        private static String GetAsciiString(Byte[] bs)
        {
            return Encoding.ASCII.GetString(bs, 0, bs.Length);
        }

        public static void Main(String[] args)
        {

            var passPhrase  = "Dick Beck";

            var original    = Encoding.ASCII.GetBytes("Hello world");
            Console.WriteLine("Starting PGP test");
            var encrypted   = Encrypt(original, passPhrase, "iway", SymmetricKeyAlgorithms.Cast5, true);

            Console.WriteLine("\nencrypted data = '"+Hex.ToHexString(encrypted)+"'");
            var decrypted   = Decrypt(encrypted, passPhrase);

            Console.WriteLine("\ndecrypted data = '"+GetAsciiString(decrypted)+"'");

            encrypted = Encrypt(original, passPhrase, "iway", SymmetricKeyAlgorithms.Aes256, false);

            Console.WriteLine("\nencrypted data = '"+Hex.ToHexString(encrypted)+"'");
            decrypted = Decrypt(encrypted, passPhrase);

            Console.WriteLine("\ndecrypted data = '"+GetAsciiString(decrypted)+"'");

        }

    }

}
