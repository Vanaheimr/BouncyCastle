using System;
using System.Collections;
using System.Collections.Generic;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    /// <remarks>
    /// Generator for a PGP master and subkey ring.
    /// This class will generate both the secret and public key rings
    /// </remarks>
    public class PgpKeyRingGenerator
    {

        #region Data

        private List<PgpSecretKey>           keys;
        private String                       id;
        private SymmetricKeyAlgorithms       encAlgorithm;
        private PgpSignatureTypes            certificationLevel;
        private String                       passPhrase;
        private Boolean                      useSha1;
        private PgpKeyPair                   masterKey;
        private PgpSignatureSubpacketVector  hashedPacketVector;
        private PgpSignatureSubpacketVector  unhashedPacketVector;
        private SecureRandom                 rand;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new key ring generator.
        /// </summary>
        /// <param name="certificationLevel">The certification level for keys on this ring.</param>
        /// <param name="masterKey">The master key pair.</param>
        /// <param name="id">The id to be associated with the ring.</param>
        /// <param name="encAlgorithm">The algorithm to be used to protect secret keys.</param>
        /// <param name="passPhrase">The passPhrase to be used to protect secret keys.</param>
        /// <param name="hashedPackets">Packets to be included in the certification hash.</param>
        /// <param name="unhashedPackets">Packets to be attached unhashed to the certification.</param>
        /// <param name="rand">input secured random.</param>
        /// <param name="useSha1">Checksum the secret keys with SHA1 rather than the older 16 bit checksum.</param>
        public PgpKeyRingGenerator(PgpSignatureTypes            certificationLevel,
                                   PgpKeyPair                   masterKey,
                                   String                       id,
                                   SymmetricKeyAlgorithms       encAlgorithm,
                                   String                       passPhrase,
                                   PgpSignatureSubpacketVector  hashedPackets,
                                   PgpSignatureSubpacketVector  unhashedPackets,
                                   SecureRandom                 rand,
                                   Boolean                      useSha1 = true)
        {

            this.certificationLevel    = certificationLevel;
            this.masterKey             = masterKey;
            this.id                    = id;
            this.encAlgorithm          = encAlgorithm;
            this.passPhrase            = passPhrase;
            this.useSha1               = useSha1;
            this.hashedPacketVector    = hashedPackets;
            this.unhashedPacketVector  = unhashedPackets;
            this.rand                  = rand;

            this.keys = new List<PgpSecretKey>() {
                new PgpSecretKey(certificationLevel, masterKey, id, encAlgorithm, passPhrase, useSha1, hashedPackets, unhashedPackets, rand)
            };

        }

        #endregion


        #region AddSubKey(KeyPair)

        /// <summary>
        /// Add a subkey to the key ring to be generated with default certification.
        /// </summary>
        public void AddSubKey(PgpKeyPair KeyPair)
        {
            AddSubKey(KeyPair, this.hashedPacketVector, this.unhashedPacketVector);
        }

        #endregion

        #region AddSubKey(KeyPair, HashedPackets, UnhashedPackets)

        /// <summary>
        /// Add a subkey with specific hashed and unhashed packets associated with it and
        /// default certification.
        /// </summary>
        /// <param name="KeyPair">Public/private key pair.</param>
        /// <param name="HashedPackets">Hashed packet values to be included in certification.</param>
        /// <param name="UnhashedPackets">Unhashed packets values to be included in certification.</param>
        /// <exception cref="PgpException"></exception>
        public void AddSubKey(PgpKeyPair                   KeyPair,
                              PgpSignatureSubpacketVector  HashedPackets,
                              PgpSignatureSubpacketVector  UnhashedPackets)
        {

            try
            {

                var sGen = new PgpSignatureGenerator(masterKey.PublicKey.Algorithm, HashAlgorithms.Sha1);

                // Generate the certification
                sGen.InitSign(PgpSignatureTypes.SubkeyBinding, masterKey.PrivateKey);
                sGen.SetHashedSubpackets(HashedPackets);
                sGen.SetUnhashedSubpackets(UnhashedPackets);

                var subSigs = new List<PgpSignature>();
                subSigs.Add(sGen.GenerateCertification(masterKey.PublicKey, KeyPair.PublicKey));
                keys.Add(new PgpSecretKey(KeyPair.PrivateKey, new PgpPublicKey(KeyPair.PublicKey, null, subSigs), encAlgorithm, passPhrase, useSha1, rand));

            }
            catch (PgpException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PgpException("exception adding subkey: ", e);
            }

        }

        #endregion


        #region GenerateSecretKeyRing()

        /// <summary>
        /// Return the secret key ring.
        /// </summary>
        public PgpSecretKeyRing GenerateSecretKeyRing()
        {
            return new PgpSecretKeyRing(keys);
        }

        #endregion

        #region GeneratePublicKeyRing()

        /// <summary>
        /// Return the public key ring that corresponds to the secret key ring.
        /// </summary>
        public PgpPublicKeyRing GeneratePublicKeyRing()
        {

            var pubKeys = new List<PgpPublicKey>();

            var enumerator = keys.GetEnumerator();
            enumerator.MoveNext();

            var pgpSecretKey = enumerator.Current;
            pubKeys.Add(pgpSecretKey.PublicKey);

            while (enumerator.MoveNext())
            {
                pgpSecretKey = enumerator.Current;
                pubKeys.Add(new PgpPublicKey(pgpSecretKey.PublicKey, true));
            }

            return new PgpPublicKeyRing(pubKeys);

        }

        #endregion

    }

}
