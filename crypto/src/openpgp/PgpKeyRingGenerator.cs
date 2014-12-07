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

        private List<PgpSecretKey>          keys;
        private String                      id;
        private SymmetricKeyAlgorithmTag    encAlgorithm;
        private Int32                       certificationLevel;
        private Char[]                      passPhrase;
        private Boolean                     useSha1;
        private PgpKeyPair                  masterKey;
        private PgpSignatureSubpacketVector hashedPacketVector;
        private PgpSignatureSubpacketVector unhashedPacketVector;
        private SecureRandom                rand;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new key ring generator using old style checksumming. It is recommended to use
        /// SHA1 checksumming where possible.
        /// </summary>
        /// <param name="certificationLevel">The certification level for keys on this ring.</param>
        /// <param name="masterKey">The master key pair.</param>
        /// <param name="id">The id to be associated with the ring.</param>
        /// <param name="encAlgorithm">The algorithm to be used to protect secret keys.</param>
        /// <param name="passPhrase">The passPhrase to be used to protect secret keys.</param>
        /// <param name="hashedPackets">Packets to be included in the certification hash.</param>
        /// <param name="unhashedPackets">Packets to be attached unhashed to the certification.</param>
        /// <param name="rand">input secured random.</param>
        public PgpKeyRingGenerator(Int32                         certificationLevel,
                                   PgpKeyPair                    masterKey,
                                   String                        id,
                                   SymmetricKeyAlgorithmTag      encAlgorithm,
                                   Char[]                        passPhrase,
                                   PgpSignatureSubpacketVector   hashedPackets,
                                   PgpSignatureSubpacketVector   unhashedPackets,
                                   SecureRandom                  rand)

            : this(certificationLevel, masterKey, id, encAlgorithm, passPhrase, false, hashedPackets, unhashedPackets, rand)

        {
            this.keys = new List<PgpSecretKey>();
        }

        /// <summary>
        /// Create a new key ring generator.
        /// </summary>
        /// <param name="certificationLevel">The certification level for keys on this ring.</param>
        /// <param name="masterKey">The master key pair.</param>
        /// <param name="id">The id to be associated with the ring.</param>
        /// <param name="encAlgorithm">The algorithm to be used to protect secret keys.</param>
        /// <param name="passPhrase">The passPhrase to be used to protect secret keys.</param>
        /// <param name="useSha1">Checksum the secret keys with SHA1 rather than the older 16 bit checksum.</param>
        /// <param name="hashedPackets">Packets to be included in the certification hash.</param>
        /// <param name="unhashedPackets">Packets to be attached unhashed to the certification.</param>
        /// <param name="rand">input secured random.</param>
        public PgpKeyRingGenerator(Int32                        certificationLevel,
                                   PgpKeyPair                   masterKey,
                                   String                       id,
                                   SymmetricKeyAlgorithmTag     encAlgorithm,
                                   Char[]                       passPhrase,
                                   Boolean                      useSha1,
                                   PgpSignatureSubpacketVector  hashedPackets,
                                   PgpSignatureSubpacketVector  unhashedPackets,
                                   SecureRandom                 rand)
        {

            this.certificationLevel     = certificationLevel;
            this.masterKey              = masterKey;
            this.id                     = id;
            this.encAlgorithm           = encAlgorithm;
            this.passPhrase             = passPhrase;
            this.useSha1                = useSha1;
            this.hashedPacketVector     = hashedPackets;
            this.unhashedPacketVector   = unhashedPackets;
            this.rand                   = rand;

            this.keys = new List<PgpSecretKey>() { new PgpSecretKey(certificationLevel, masterKey, id, encAlgorithm, passPhrase, useSha1, hashedPackets, unhashedPackets, rand) };

        }

        #endregion


        /// <summary>Add a subkey to the key ring to be generated with default certification.</summary>
        public void AddSubKey(PgpKeyPair keyPair)
        {
            AddSubKey(keyPair, this.hashedPacketVector, this.unhashedPacketVector);
        }

        /// <summary>
        /// Add a subkey with specific hashed and unhashed packets associated with it and
        /// default certification.
        /// </summary>
        /// <param name="keyPair">Public/private key pair.</param>
        /// <param name="hashedPackets">Hashed packet values to be included in certification.</param>
        /// <param name="unhashedPackets">Unhashed packets values to be included in certification.</param>
        /// <exception cref="PgpException"></exception>
        public void AddSubKey(PgpKeyPair                   keyPair,
                              PgpSignatureSubpacketVector  hashedPackets,
                              PgpSignatureSubpacketVector  unhashedPackets)
        {

            try
            {

                var sGen = new PgpSignatureGenerator(masterKey.PublicKey.Algorithm, HashAlgorithmTag.Sha1);

                // Generate the certification
                sGen.InitSign(PgpSignature.SubkeyBinding, masterKey.PrivateKey);

                sGen.SetHashedSubpackets(hashedPackets);
                sGen.SetUnhashedSubpackets(unhashedPackets);

                var subSigs = new List<PgpSignature>();

                subSigs.Add(sGen.GenerateCertification(masterKey.PublicKey, keyPair.PublicKey));

                keys.Add(new PgpSecretKey(keyPair.PrivateKey, new PgpPublicKey(keyPair.PublicKey, null, subSigs), encAlgorithm, passPhrase, useSha1, rand));

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

        /// <summary>Return the secret key ring.</summary>
        public PgpSecretKeyRing GenerateSecretKeyRing()
        {
            return new PgpSecretKeyRing(keys);
        }

        /// <summary>Return the public key ring that corresponds to the secret key ring.</summary>
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

                var k = new PgpPublicKey(pgpSecretKey.PublicKey);
                k.publicPk = new PublicSubkeyPacket(k.Algorithm, k.CreationTime, k.publicPk.Key);

                pubKeys.Add(k);

            }

            return new PgpPublicKeyRing(pubKeys);

        }

    }

}
