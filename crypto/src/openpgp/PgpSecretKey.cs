using System;
using System.IO;
using System.Collections.Generic;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>General class to handle a PGP secret key object.</remarks>
    public class PgpSecretKey
    {

        #region Data

        private readonly SecretKeyPacket  _SecretKeyPacket;
        private readonly PgpPublicKey     _PublicKey;

        #endregion

        #region Properties

        #region IsSigningKey

        /// <summary>
        /// Check if this key has an algorithm type that makes it suitable to use for signing.
        /// </summary>
        /// <remarks>
        /// Note: with version 4 keys KeyFlags subpackets should also be considered when present for
        /// determining the preferred use of the key.
        /// </remarks>
        public Boolean IsSigningKey
        {
            get
            {
                switch (_PublicKey.Algorithm)
                {
                    case PublicKeyAlgorithms.RsaGeneral:
                    case PublicKeyAlgorithms.RsaSign:
                    case PublicKeyAlgorithms.Dsa:
                    case PublicKeyAlgorithms.ECDsa:
                    case PublicKeyAlgorithms.ElGamalGeneral:
                        return true;
                    default:
                        return false;
                }
            }
        }

        #endregion

        #region IsMasterKey

        /// <summary>
        /// True, if this is a master key.
        /// </summary>
        public Boolean IsMasterKey
        {
            get
            {
                return _PublicKey.IsMasterKey;
            }
        }

        #endregion

        #region IsPrivateKeyEmpty

        /// <summary>
        /// Detect if the Secret Key's Private Key is empty or not
        /// </summary>
        public Boolean IsPrivateKeyEmpty
        {
            get
            {

                var secKeyData = _SecretKeyPacket.GetSecretKeyData();

                return secKeyData == null || secKeyData.Length < 1;

            }
        }

        #endregion

        #region KeyEncryptionAlgorithm

        /// <summary>
        /// The algorithm the key is encrypted with.
        /// </summary>
        public SymmetricKeyAlgorithms KeyEncryptionAlgorithm
        {
            get
            {
                return _SecretKeyPacket.EncAlgorithm;
            }
        }

        #endregion

        #region KeyId

        /// <summary>
        /// The key ID of the public key associated with this key.
        /// </summary>
        public UInt64 KeyId
        {
            get
            {
                return _PublicKey.KeyId;
            }
        }

        #endregion

        #region PublicKey

        /// <summary>
        /// The public key associated with this key.
        /// </summary>
        public PgpPublicKey PublicKey
        {
            get
            {
                return _PublicKey;
            }
        }

        #endregion

        #region UserIds

        /// <summary>
        /// Allows enumeration of any user IDs associated with the key.
        /// </summary>
        public IEnumerable<String> UserIds
        {
            get
            {
                return _PublicKey.UserIds;
            }
        }

        #endregion

        #region UserAttributes

        /// <summary>
        /// Allows enumeration of any user attribute vectors associated with the key.
        /// </summary>
        public IEnumerable<PgpUserAttributeSubpacketVector> UserAttributes
        {
            get
            {
                return _PublicKey.UserAttributes;
            }
        }

        #endregion

        #endregion

        #region Constructor(s)

        internal PgpSecretKey(SecretKeyPacket  secret,
                              PgpPublicKey     pub)
        {
            this._SecretKeyPacket = secret;
            this._PublicKey = pub;
        }

        internal PgpSecretKey(PgpPrivateKey             privKey,
                              PgpPublicKey              pubKey,
                              SymmetricKeyAlgorithms    encAlgorithm,
                              String                    passPhrase,
                              Boolean                   useSha1,
                              SecureRandom              rand)

            : this(privKey, pubKey, encAlgorithm, passPhrase, useSha1, rand, false)

        { }

        internal PgpSecretKey(PgpPrivateKey             privKey,
                              PgpPublicKey              pubKey,
                              SymmetricKeyAlgorithms    encAlgorithm,
                              String                    passPhrase,
                              Boolean                   useSha1,
                              SecureRandom              rand,
                              Boolean                   isMasterKey)
        {

            BcpgObject secKey;

            this._PublicKey = pubKey;

            switch (pubKey.Algorithm)
            {
                case PublicKeyAlgorithms.RsaEncrypt:
                case PublicKeyAlgorithms.RsaSign:
                case PublicKeyAlgorithms.RsaGeneral:
                    RsaPrivateCrtKeyParameters rsK = (RsaPrivateCrtKeyParameters) privKey.Key;
                    secKey = new RsaSecretBcpgKey(rsK.Exponent, rsK.P, rsK.Q);
                    break;
                case PublicKeyAlgorithms.Dsa:
                    DsaPrivateKeyParameters dsK = (DsaPrivateKeyParameters) privKey.Key;
                    secKey = new DsaSecretBcpgKey(dsK.X);
                    break;
                case PublicKeyAlgorithms.ElGamalEncrypt:
                case PublicKeyAlgorithms.ElGamalGeneral:
                    ElGamalPrivateKeyParameters esK = (ElGamalPrivateKeyParameters) privKey.Key;
                    secKey = new ElGamalSecretBcpgKey(esK.X);
                    break;
                default:
                    throw new PgpException("unknown key class");
            }

            try
            {

                var bOut  = new MemoryStream();
                var pOut  = new BcpgOutputStream(bOut);

                pOut.WriteObject(secKey);

                var keyData       = bOut.ToArray();
                var checksumData  = Checksum(useSha1, keyData, keyData.Length);

                keyData = Arrays.Concatenate(keyData, checksumData);

                if (encAlgorithm == SymmetricKeyAlgorithms.Null)
                {
                    if (isMasterKey)
                    {
                        this._SecretKeyPacket = new SecretKeyPacket(_PublicKey._PublicKeyPacket, encAlgorithm, null, null, keyData);
                    }
                    else
                    {
                        this._SecretKeyPacket = new SecretSubkeyPacket(_PublicKey._PublicKeyPacket, encAlgorithm, null, null, keyData);
                    }
                }
                else
                {
                    S2k s2k;
                    byte[] iv;

                    byte[] encData;
                    if (_PublicKey.Version >= 4)
                    {
                        encData = EncryptKeyData(keyData, encAlgorithm, passPhrase, rand, out s2k, out iv);
                    }
                    else
                    {
                        // TODO v3 RSA key encryption
                        throw Platform.CreateNotImplementedException("v3 RSA");
                    }

                    int s2kUsage = useSha1
                        ?    SecretKeyPacket.UsageSha1
                        :    SecretKeyPacket.UsageChecksum;

                    if (isMasterKey)
                    {
                        this._SecretKeyPacket = new SecretKeyPacket(_PublicKey._PublicKeyPacket, encAlgorithm, s2kUsage, s2k, iv, encData);
                    }
                    else
                    {
                        this._SecretKeyPacket = new SecretSubkeyPacket(_PublicKey._PublicKeyPacket, encAlgorithm, s2kUsage, s2k, iv, encData);
                    }
                }
            }
            catch (PgpException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception encrypting key", e);
            }
        }

        public PgpSecretKey(PgpSignatureTypes                certificationLevel,
                            PgpKeyPair                   keyPair,
                            String                       id,
                            SymmetricKeyAlgorithms       encAlgorithm,
                            String                       passPhrase,
                            PgpSignatureSubpacketVector  hashedPackets,
                            PgpSignatureSubpacketVector  unhashedPackets,
                            SecureRandom                 rand)

            : this(certificationLevel, keyPair, id, encAlgorithm, passPhrase, false, hashedPackets, unhashedPackets, rand)

        { }

        public PgpSecretKey(PgpSignatureTypes                certificationLevel,
                            PgpKeyPair                   keyPair,
                            String                       id,
                            SymmetricKeyAlgorithms       encAlgorithm,
                            String                       passPhrase,
                            Boolean                      useSha1,
                            PgpSignatureSubpacketVector  hashedPackets,
                            PgpSignatureSubpacketVector  unhashedPackets,
                            SecureRandom                 rand)

            : this(keyPair.PrivateKey, CertifiedPublicKey(certificationLevel, keyPair, id, hashedPackets, unhashedPackets), encAlgorithm, passPhrase, useSha1, rand, true)

        { }

        public PgpSecretKey(PgpSignatureTypes                certificationLevel,
                            PublicKeyAlgorithms          algorithm,
                            AsymmetricKeyParameter       pubKey,
                            AsymmetricKeyParameter       privKey,
                            DateTime                     time,
                            String                       id,
                            SymmetricKeyAlgorithms       encAlgorithm,
                            String                       passPhrase,
                            PgpSignatureSubpacketVector  hashedPackets,
                            PgpSignatureSubpacketVector  unhashedPackets,
                            SecureRandom                 rand)

            : this(certificationLevel,
                   new PgpKeyPair(algorithm, pubKey, privKey, time),
                   id, encAlgorithm, passPhrase, hashedPackets, unhashedPackets, rand)

        { }

        public PgpSecretKey(PgpSignatureTypes                 certificationLevel,
                            PublicKeyAlgorithms           algorithm,
                            AsymmetricKeyParameter        pubKey,
                            AsymmetricKeyParameter        privKey,
                            DateTime                      time,
                            String                        id,
                            SymmetricKeyAlgorithms        encAlgorithm,
                            String                        passPhrase,
                            Boolean                       useSha1,
                            PgpSignatureSubpacketVector   hashedPackets,
                            PgpSignatureSubpacketVector   unhashedPackets,
                            SecureRandom                  rand)

            : this(certificationLevel, new PgpKeyPair(algorithm, pubKey, privKey, time), id, encAlgorithm, passPhrase, useSha1, hashedPackets, unhashedPackets, rand)

        { }

        #endregion


        #region (private) CertifiedPublicKey(...)

        private static PgpPublicKey CertifiedPublicKey(PgpSignatureTypes            certificationLevel,
                                                       PgpKeyPair                   keyPair,
                                                       String                       id,
                                                       PgpSignatureSubpacketVector  hashedPackets,
                                                       PgpSignatureSubpacketVector  unhashedPackets)

        {

            PgpSignatureGenerator sGen;

            try
            {
                sGen = new PgpSignatureGenerator(keyPair.PublicKey.Algorithm, HashAlgorithms.Sha1);
            }
            catch (Exception e)
            {
                throw new PgpException("Creating signature generator: " + e.Message, e);
            }

            //
            // Generate the certification
            //
            sGen.InitSign(certificationLevel, keyPair.PrivateKey);

            sGen.SetHashedSubpackets(hashedPackets);
            sGen.SetUnhashedSubpackets(unhashedPackets);

            try
            {
                PgpSignature certification = sGen.GenerateCertification(id, keyPair.PublicKey);
                return PgpPublicKey.AddCertification(keyPair.PublicKey, id, certification);
            }
            catch (Exception e)
            {
                throw new PgpException("Exception doing certification: " + e.Message, e);
            }

        }

        #endregion

        #region (private) ExtractKeyData(passPhrase)

        private Byte[] ExtractKeyData(String passPhrase)
        {

            var alg      = _SecretKeyPacket.EncAlgorithm;
            var encData  = _SecretKeyPacket.GetSecretKeyData();

            if (alg == SymmetricKeyAlgorithms.Null)
                // TODO Check checksum here?
                return encData;

            IBufferedCipher c = null;
            try
            {
                string cName = PgpUtilities.GetSymmetricCipherName(alg);
                c = CipherUtilities.GetCipher(cName + "/CFB/NoPadding");
            }
            catch (Exception e)
            {
                throw new PgpException("Exception creating cipher", e);
            }

            // TODO Factor this block out as 'decryptData'
            try
            {

                KeyParameter key = PgpUtilities.MakeKeyFromPassPhrase(_SecretKeyPacket.EncAlgorithm, _SecretKeyPacket.S2k, passPhrase);
                byte[] iv = _SecretKeyPacket.GetIV();
                byte[] data;

                if (_SecretKeyPacket.PublicKeyPacket.Version >= 4)
                {
                    c.Init(false, new ParametersWithIV(key, iv));

                    data = c.DoFinal(encData);

                    bool useSha1 = _SecretKeyPacket.S2kUsage == SecretKeyPacket.UsageSha1;
                    byte[] check = Checksum(useSha1, data, (useSha1) ? data.Length - 20 : data.Length - 2);

                    for (int i = 0; i != check.Length; i++)
                    {
                        if (check[i] != data[data.Length - check.Length + i])
                        {
                            throw new PgpException("Checksum mismatch at " + i + " of " + check.Length);
                        }
                    }
                }
                else // version 2 or 3, RSA only.
                {
                    data = new byte[encData.Length];

                    iv = Arrays.Clone(iv);

                    //
                    // read in the four numbers
                    //
                    int pos = 0;

                    for (int i = 0; i != 4; i++)
                    {
                        c.Init(false, new ParametersWithIV(key, iv));

                        int encLen = (((encData[pos] << 8) | (encData[pos + 1] & 0xff)) + 7) / 8;

                        data[pos] = encData[pos];
                        data[pos + 1] = encData[pos + 1];
                        pos += 2;

                        c.DoFinal(encData, pos, encLen, data, pos);
                        pos += encLen;

                        if (i != 3)
                        {
                            Array.Copy(encData, pos - iv.Length, iv, 0, iv.Length);
                        }
                    }

                    //
                    // verify and copy checksum
                    //

                    data[pos] = encData[pos];
                    data[pos + 1] = encData[pos + 1];

                    int cs = ((encData[pos] << 8) & 0xff00) | (encData[pos + 1] & 0xff);
                    int calcCs = 0;
                    for (int j = 0; j < pos; j++)
                    {
                        calcCs += data[j] & 0xff;
                    }

                    calcCs &= 0xffff;
                    if (calcCs != cs)
                    {
                        throw new PgpException("Checksum mismatch: passphrase wrong, expected "
                            + cs.ToString("X")
                            + " found " + calcCs.ToString("X"));
                    }
                }

                return data;
            }
            catch (PgpException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception decrypting key", e);
            }

        }

        #endregion

        #region (private, static) Checksum(UseSHA1, Bytes, Length)

        private static Byte[] Checksum(Boolean  UseSHA1,
                                       Byte[]   Bytes,
                                       Int32    Length)
        {

            if (UseSHA1)
            {
                try
                {
                    IDigest dig = DigestUtilities.GetDigest("SHA1");
                    dig.BlockUpdate(Bytes, 0, Length);
                    return DigestUtilities.DoFinal(dig);
                }
                //catch (NoSuchAlgorithmException e)
                catch (Exception e)
                {
                    throw new PgpException("Can't find SHA-1", e);
                }
            }

            else
            {
                int Checksum = 0;
                for (int i = 0; i != Length; i++)
                {
                    Checksum += Bytes[i];
                }

                return new byte[] { (byte)(Checksum >> 8), (byte)Checksum };
            }

        }

        #endregion

        #region (private, static) EncryptKeyData(...)

        private static Byte[] EncryptKeyData(Byte[]                  rawKeyData,
                                             SymmetricKeyAlgorithms  encAlgorithm,
                                             String                  passPhrase,
                                             SecureRandom            SecRandom,
                                             out S2k                 s2k,
                                             out Byte[]              iv)
        {

            IBufferedCipher c;

            try
            {
                var cName = PgpUtilities.GetSymmetricCipherName(encAlgorithm);
                    c     = CipherUtilities.GetCipher(cName + "/CFB/NoPadding");
            }
            catch (Exception e)
            {
                throw new PgpException("Exception creating cipher", e);
            }

            byte[] s2kIV = new byte[8];
            SecRandom.NextBytes(s2kIV);
            s2k = new S2k(HashAlgorithms.Sha1, s2kIV, 0x60);

            var kp = PgpUtilities.MakeKeyFromPassPhrase(encAlgorithm, s2k, passPhrase);

            iv = new byte[c.GetBlockSize()];
            SecRandom.NextBytes(iv);

            c.Init(true, new ParametersWithRandom(new ParametersWithIV(kp, iv), SecRandom));

            return c.DoFinal(rawKeyData);

        }

        #endregion


        public Byte[] GetEncoded()
        {
            MemoryStream bOut = new MemoryStream();
            Encode(bOut);
            return bOut.ToArray();
        }

        #region Encode(OutputStream)

        public void Encode(Stream OutputStream)
        {

            var bcpgOut = BcpgOutputStream.Wrap(OutputStream);

            bcpgOut.WritePacket(_SecretKeyPacket);

            if (_PublicKey._TrustPacket != null)
                bcpgOut.WritePacket(_PublicKey._TrustPacket);

            if (_PublicKey._SubSignatures == null) // is not a sub key
            {

                foreach (var keySig in _PublicKey._KeySignatures)
                    keySig.Encode(bcpgOut);

                for (int i = 0; i != _PublicKey._UserIds.Count; i++)
                {

                    var pubID = _PublicKey._UserIds[i];

                    if (pubID is string)
                        bcpgOut.WritePacket(new UserIdPacket(pubID as String));

                    else
                        bcpgOut.WritePacket(new UserAttributePacket((pubID as PgpUserAttributeSubpacketVector).ToSubpacketArray()));

                    if (_PublicKey._idTrusts[i] != null)
                        bcpgOut.WritePacket(_PublicKey._idTrusts[i] as ContainedPacket);

                    foreach (var sig in _PublicKey._idSigs[i])
                        sig.Encode(bcpgOut);

                }

            }
            else
            {
                foreach (var subSig in _PublicKey._SubSignatures)
                    subSig.Encode(bcpgOut);
            }

            // TODO Check that this is right/necessary
            //bcpgOut.Finish();

        }

        #endregion

        #region ExtractPrivateKey(passPhrase)

        /// <summary>
        /// Extract a <c>PgpPrivateKey</c> from this secret key's encrypted contents.
        /// </summary>
        public PgpPrivateKey ExtractPrivateKey(String Passphrase)
        {

            if (IsPrivateKeyEmpty)
                return null;

            var pubPk = _SecretKeyPacket.PublicKeyPacket;

            try
            {

                var data    = ExtractKeyData(Passphrase);
                var bcpgIn  = BcpgInputStream.Wrap(new MemoryStream(data, false));

                AsymmetricKeyParameter PrivateKeyParameter;

                switch (pubPk.Algorithm)
                {

                    case PublicKeyAlgorithms.RsaEncrypt:
                    case PublicKeyAlgorithms.RsaGeneral:
                    case PublicKeyAlgorithms.RsaSign:
                        var rsaPriv      = new RsaSecretBcpgKey(bcpgIn);
                        var rsaPrivSpec  = new RsaPrivateCrtKeyParameters(
                            rsaPriv.Modulus,
                            (pubPk.Key as RsaPublicBcpgKey).PublicExponent,
                            rsaPriv.PrivateExponent,
                            rsaPriv.PrimeP,
                            rsaPriv.PrimeQ,
                            rsaPriv.PrimeExponentP,
                            rsaPriv.PrimeExponentQ,
                            rsaPriv.CrtCoefficient);
                        PrivateKeyParameter = rsaPrivSpec;
                        break;

                    case PublicKeyAlgorithms.Dsa:
                        var dsaPub           = pubPk.Key as DsaPublicBcpgKey;
                        PrivateKeyParameter  = new DsaPrivateKeyParameters(new DsaSecretBcpgKey(bcpgIn).X,
                                                                           new DsaParameters(dsaPub.P, dsaPub.Q, dsaPub.G));
                        break;

                    case PublicKeyAlgorithms.ElGamalEncrypt:
                    case PublicKeyAlgorithms.ElGamalGeneral:
                        var elPub            = pubPk.Key as ElGamalPublicBcpgKey;
                        PrivateKeyParameter  = new ElGamalPrivateKeyParameters(new ElGamalSecretBcpgKey(bcpgIn).X,
                                                                               new ElGamalParameters(elPub.P, elPub.G));
                        break;

                    default:
                        throw new PgpException("unknown public key algorithm encountered");

                }

                return new PgpPrivateKey(PrivateKeyParameter, KeyId);

            }
            catch (PgpException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception constructing key", e);
            }

        }

        #endregion

        #region CopyWithNewPassword(...)

        /// <summary>
        /// Return a copy of the passed in secret key, encrypted using a new password
        /// and the passed in algorithm.
        /// </summary>
        /// <param name="SecretKey">The PgpSecretKey to be copied.</param>
        /// <param name="oldPassPhrase">The current password for the key.</param>
        /// <param name="newPassPhrase">The new password for the key.</param>
        /// <param name="newEncAlgorithm">The algorithm to be used for the encryption.</param>
        /// <param name="SecRandom">Source of randomness.</param>
        public static PgpSecretKey CopyWithNewPassword(PgpSecretKey            SecretKey,
                                                       String                  oldPassPhrase,
                                                       String                  newPassPhrase,
                                                       SymmetricKeyAlgorithms  newEncAlgorithm,
                                                       SecureRandom            SecRandom)
        {

            if (SecretKey.IsPrivateKeyEmpty)
                throw new PgpException("no private key in this SecretKey - public key present only.");

            var     rawKeyData  = SecretKey.ExtractKeyData(oldPassPhrase);
            var     s2kUsage    = SecretKey._SecretKeyPacket.S2kUsage;
            byte[]  iv          = null;
            S2k     s2k         = null;
            byte[]  keyData;

            var pubKeyPacket = SecretKey._SecretKeyPacket.PublicKeyPacket;

            if (newEncAlgorithm == SymmetricKeyAlgorithms.Null)
            {

                s2kUsage = SecretKeyPacket.UsageNone;

                if (SecretKey._SecretKeyPacket.S2kUsage == SecretKeyPacket.UsageSha1)   // SHA-1 hash, need to rewrite Checksum
                {

                    keyData = new byte[rawKeyData.Length - 18];

                    Array.Copy(rawKeyData, 0, keyData, 0, keyData.Length - 2);

                    var check = Checksum(false, keyData, keyData.Length - 2);
                    keyData[keyData.Length - 2] = check[0];
                    keyData[keyData.Length - 1] = check[1];

                }
                else
                {
                    keyData = rawKeyData;
                }

            }
            else
            {

                try
                {

                    if (pubKeyPacket.Version >= 4)
                        keyData = EncryptKeyData(rawKeyData, newEncAlgorithm, newPassPhrase, SecRandom, out s2k, out iv);

                    else
                        // TODO v3 RSA key encryption
                        throw Platform.CreateNotImplementedException("v3 RSA");

                }
                catch (PgpException e)
                {
                    throw e;
                }
                catch (Exception e)
                {
                    throw new PgpException("Exception encrypting key", e);
                }

            }

            SecretKeyPacket secret;
            if (SecretKey._SecretKeyPacket is SecretSubkeyPacket)
                secret = new SecretSubkeyPacket(pubKeyPacket, newEncAlgorithm, s2kUsage, s2k, iv, keyData);

            else
                secret = new SecretKeyPacket(pubKeyPacket, newEncAlgorithm, s2kUsage, s2k, iv, keyData);

            return new PgpSecretKey(secret, SecretKey._PublicKey);

        }

        #endregion

        #region ReplacePublicKey(SecretKey, PublicKey)

        /// <summary>Replace the passed the public key on the passed in secret key.</summary>
        /// <param name="SecretKey">Secret key to change.</param>
        /// <param name="PublicKey">New public key.</param>
        /// <returns>A new secret key.</returns>
        /// <exception cref="ArgumentException">If KeyId's do not match.</exception>
        public static PgpSecretKey ReplacePublicKey(PgpSecretKey  SecretKey,
                                                    PgpPublicKey  PublicKey)
        {

            if (PublicKey.KeyId != SecretKey.KeyId)
                throw new ArgumentException("KeyId's do not match");

            return new PgpSecretKey(SecretKey._SecretKeyPacket, PublicKey);

        }

        #endregion

    }

}
