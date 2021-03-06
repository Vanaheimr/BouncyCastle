using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Examples
{
    internal class PgpExampleUtilities
    {

        internal static byte[] CompressFile(String fileName, CompressionAlgorithms algorithm)
        {
            var bOut     = new MemoryStream();
            var comData  = new PgpCompressedDataGenerator(algorithm);
            PgpUtilities.WriteFileToLiteralData(comData.Open(bOut), PgpLiteralData.Binary, new FileInfo(fileName));
            comData.Close();
            return bOut.ToArray();
        }

        /**
         * Search a secret key ring collection for a secret key corresponding to keyID if it
         * exists.
         * 
         * @param pgpSec a secret key ring collection.
         * @param keyID keyID we want.
         * @param pass passphrase to decrypt secret key with.
         * @return
         * @throws PGPException
         * @throws NoSuchProviderException
         */
        internal static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, UInt64 keyID, String pass)
        {

            var pgpSecKey = pgpSec.GetSecretKey(keyID);

            if (pgpSecKey == null)
                return null;

            return pgpSecKey.ExtractPrivateKey(pass);

        }

        internal static PgpPublicKey ReadPublicKey(String fileName)
        {
            using (var KeyStream = File.OpenRead(fileName))
            {
                return ReadPublicKey(KeyStream);
            }
        }

        /**
         * A simple routine that opens a key ring file and loads the first available key
         * suitable for encryption.
         * 
         * @param input
         * @return
         * @throws IOException
         * @throws PGPException
         */
        internal static PgpPublicKey ReadPublicKey(Stream input)
        {

            var PublicKeyRingBundle = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(input));

            // we just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.
            foreach (var PublicKeyRing in PublicKeyRingBundle)
            {
                foreach (var PublicKey in PublicKeyRing)
                {
                    if (PublicKey.IsEncryptionKey)
                        return PublicKey;
                }
            }

            throw new ArgumentException("Can't find encryption key in key ring.");

        }

        internal static PgpSecretKey ReadSecretKey(String fileName)
        {
            using (var KeyStream = File.OpenRead(fileName))
            {
                return ReadSecretKey(KeyStream);
            }
        }

        /**
         * A simple routine that opens a key ring file and loads the first available key
         * suitable for signature generation.
         * 
         * @param input stream to read the secret key ring collection from.
         * @return a secret key.
         * @throws IOException on a problem with using the input stream.
         * @throws PGPException if there is an issue parsing the input stream.
         */
        internal static PgpSecretKey ReadSecretKey(Stream input)
        {

            var SecretKeyRingBundle = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(input));

            // we just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.
            foreach (var SecretKeyRing in SecretKeyRingBundle)
            {
                foreach (var SecretKey in SecretKeyRing)
                {
                    if (SecretKey.IsSigningKey)
                        return SecretKey;
                }
            }

            throw new ArgumentException("Can't find signing key in key ring.");

        }

    }

}
