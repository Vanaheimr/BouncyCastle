using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Asn1.Utilities;

using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Examples
{
    /**
    * Basic class which just lists the contents of the public key file passed
    * as an argument. If the file contains more than one "key ring" they are
    * listed in the order found.
    */
    public sealed class PublicKeyRingDump
    {
        private PublicKeyRingDump()
        {
        }

        public static string GetAlgorithm(
            PublicKeyAlgorithms algId)
        {
            switch (algId)
            {
                case PublicKeyAlgorithms.RsaGeneral:
                    return "RsaGeneral";
                case PublicKeyAlgorithms.RsaEncrypt:
                    return "RsaEncrypt";
                case PublicKeyAlgorithms.RsaSign:
                    return "RsaSign";
                case PublicKeyAlgorithms.ElGamalEncrypt:
                    return "ElGamalEncrypt";
                case PublicKeyAlgorithms.Dsa:
                    return "DSA";
                case PublicKeyAlgorithms.EC:
                    return "EC";
                case PublicKeyAlgorithms.ECDsa:
                    return "ECDSA";
                case PublicKeyAlgorithms.ElGamalGeneral:
                    return "ElGamalGeneral";
                case PublicKeyAlgorithms.DiffieHellman:
                    return "DiffieHellman";
            }

            return "unknown";

        }

        public static void Main(
            string[] args)
        {
            Stream fs = File.OpenRead(args[0]);

            //
            // Read the public key rings
            //
            var PublicKeyRingBundle = new PgpPublicKeyRingBundle(
                PgpUtilities.GetDecoderStream(fs));

            fs.Close();

            foreach (var pgpPub in PublicKeyRingBundle)
            {
                try
                {
                    PgpPublicKey pubKey = pgpPub.PublicKey;
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine(e.Message);
                    Console.Error.WriteLine(e.StackTrace);
                    continue;
                }

                bool first = true;

                foreach (var pgpKey in pgpPub)
                {
                    if (first)
                    {
                        Console.WriteLine("Key ID: " +  pgpKey.KeyId.ToString("X"));
                        first = false;
                    }
                    else
                    {
                        Console.WriteLine("Key ID: " + pgpKey.KeyId.ToString("X") + " (subkey)");
                    }

                    Console.WriteLine("            Algorithm: " + GetAlgorithm(pgpKey.Algorithm));
                    Console.WriteLine("            Fingerprint: " + Hex.ToHexString(pgpKey.Fingerprint));
                }
            }
        }
    }
}
