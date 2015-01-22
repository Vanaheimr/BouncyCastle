using System;
using System.IO;
using System.Text;

using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Examples
{

    /// <summary>
    /// Simple routine to encrypt and decrypt using a passphrase.
    /// This service routine provides the basic PGP services between
    /// byte arrays.
    /// 
    /// Note: this code plays no attention to -Console in the file name
    /// the specification of "_CONSOLE" in the filename.
    /// It also expects that a single pass phrase will have been used.
    /// </summary>
    public sealed class ByteArrayHandler
    {

        #region (static) Decrypt(EncryptedText, Passphrase)

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

            var InputStream        = PgpUtilities.GetDecoderStream(new MemoryStream(EncryptedText));
            var PGPObjectFactory1  = new PgpObjectFactory(InputStream);

            PgpEncryptedDataList enc = null;
            var o = PGPObjectFactory1.NextPgpObject();

            // the first object might be a PGP marker packet.
            if (o is PgpEncryptedDataList)
                enc = (PgpEncryptedDataList) o;

            else
                enc = (PgpEncryptedDataList) PGPObjectFactory1.NextPgpObject();

            var pbe = (PgpPbeEncryptedData) enc[0];

            var ClearTextStream = pbe.GetDataStream(Passphrase);


            var PGPObjectFactory2 = new PgpObjectFactory(ClearTextStream);
            var CompressedData = (PgpCompressedData) PGPObjectFactory2.NextPgpObject();

            PGPObjectFactory2 = new PgpObjectFactory(CompressedData.GetDataStream());
            var LiteralData = (PgpLiteralData) PGPObjectFactory2.NextPgpObject();

            return Streams.ReadAll(LiteralData.InputStream);

        }

        #endregion

        #region (static) Encrypt(Plaintext, Passphrase, Filename, EncryptionAlgorithm, UseArmor)

        /// <summary>
        /// Simple PGP encryptor between byte[].
        /// </summary>
        /// <param name="Plaintext">The test to be encrypted</param>
        /// <param name="Passphrase">The pass phrase (key). This method assumes that the key is a simple pass phrase, and does not yet support RSA or more sophisiticated keying.</param>
        /// <param name="Filename">
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
                                     String                  Filename,
                                     SymmetricKeyAlgorithms  EncryptionAlgorithm,
                                     Boolean                 UseArmor)
        {

            if (Filename == null)
                Filename = PgpLiteralData.Console;

            var compressedData = Compress(Plaintext, Filename, CompressionAlgorithms.Zip);

            var bOut = new MemoryStream();

            Stream output = bOut;
            if (UseArmor)
                output = new ArmoredOutputStream(output);

            var encGen = new PgpEncryptedDataGenerator(EncryptionAlgorithm);
            encGen.AddMethod(Passphrase);

            Stream encOut = encGen.Open(output, (UInt64) compressedData.Length);

            encOut.Write(compressedData, 0, compressedData.Length);
            encOut.Close();

            if (UseArmor)
                output.Close();

            return bOut.ToArray();

        }

        #endregion

        #region (static) Compress(ClearText, Filename, CompressionAlgorithm)

        private static Byte[] Compress(Byte[] ClearText, String Filename, CompressionAlgorithms CompressionAlgorithm)
        {

            var OutputStream             = new MemoryStream();
            var CompressedDataGenerator  = new PgpCompressedDataGenerator(CompressionAlgorithm);
            var CompressedOutputStream   = CompressedDataGenerator.Open(OutputStream);
            var LiteralDataGenerator     = new PgpLiteralDataGenerator();

            // we want to Generate compressed data. This might be a user option later,
            // in which case we would pass in bOut.
            var pOut = LiteralDataGenerator.Open(PgpLiteralData.Binary,
                                                 Filename,                   // "filename" to store
                                                 (UInt64) ClearText.Length,
                                                 DateTime.UtcNow,
                                                 CompressedOutputStream);

            pOut.Write(ClearText, 0, ClearText.Length);
            pOut.Close();

            CompressedDataGenerator.Close();

            return OutputStream.ToArray();

        }

        #endregion


        public static void Main(String[] args)
        {

            var passPhrase  = "Dick Beck";

            var original    = Encoding.ASCII.GetBytes("Hello world");
            Console.WriteLine("Starting PGP test");
            var encrypted   = Encrypt(original, passPhrase, "iway", SymmetricKeyAlgorithms.Cast5, true);

            Console.WriteLine("\nencrypted data = '"+Hex.ToHexString(encrypted)+"'");
            var decrypted   = Decrypt(encrypted, passPhrase);

            Console.WriteLine("\ndecrypted data = '" + Encoding.ASCII.GetString(decrypted, 0, decrypted.Length) + "'");

            encrypted = Encrypt(original, passPhrase, "iway", SymmetricKeyAlgorithms.Aes256, false);

            Console.WriteLine("\nencrypted data = '"+Hex.ToHexString(encrypted)+"'");
            decrypted = Decrypt(encrypted, passPhrase);

            Console.WriteLine("\ndecrypted data = '" + Encoding.ASCII.GetString(decrypted, 0, decrypted.Length) + "'");

        }

    }

}
