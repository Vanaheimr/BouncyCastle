using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    /// <remarks>
    /// Class to hold a single master secret key and its subkeys.
    /// <p>
    /// Often PGP keyring files consist of multiple master keys, if you are trying to process
    /// or construct one of these you should use the <c>PgpSecretKeyRingBundle</c> class.
    /// </p>
    /// </remarks>
    public class PgpSecretKeyRing : PgpKeyRing
    {

        #region Data

        private readonly Dictionary<UInt64, PgpSecretKey>  keys;
        private readonly Dictionary<UInt64, PgpPublicKey>  extraPubKeys;

        #endregion

        #region Properties

        #region SecretKeys

        /// <summary>
        /// Returns all secret keys.
        /// </summary>
        public IEnumerable<PgpSecretKey> SecretKeys
        {
            get
            {
                return keys.Values;
            }
        }

        #endregion

        #region FirstSecretKey

        /// <summary>
        /// Return the master private key.
        /// </summary>
        public PgpSecretKey FirstSecretKey
        {
            get
            {
                return keys.First().Value;
            }
        }

        #endregion

        #region ExtraPublicKeys

        /// <summary>
        /// Return an iterator of the public keys in the secret key ring that
        /// have no matching private key. At the moment only personal certificate data
        /// appears in this fashion.
        /// </summary>
        public IEnumerable<PgpPublicKey> ExtraPublicKeys
        {
            get
            {
                return extraPubKeys.Values;
            }
        }

        #endregion

        #region FirstPublicKey

        /// <summary>
        /// Return the public key for the master key.
        /// </summary>
        public PgpPublicKey FirstPublicKey
        {
            get
            {
                return keys.First().Value.PublicKey;
            }
        }

        #endregion

        #endregion

        #region Constructor(s)

        public PgpSecretKeyRing(IEnumerable<PgpSecretKey>  keys,
                                IEnumerable<PgpPublicKey>  extraPubKeys = null)
        {

            if (keys == null)
                throw new ArgumentNullException("keys", "The given keys collection must not be null!");

            this.keys = keys.ToDictionary(key => key.KeyId, key => key);

            if (extraPubKeys != null)
                this.extraPubKeys = extraPubKeys.ToDictionary(key => key.KeyId, key => key);

        }

        public PgpSecretKeyRing(Byte[] encoding)
            : this(new MemoryStream(encoding))
        { }

        public PgpSecretKeyRing(Stream inputStream)
        {

            this.keys          = new Dictionary<UInt64, PgpSecretKey>();
            this.extraPubKeys  = new Dictionary<UInt64, PgpPublicKey>();

            var bcpgInput = BcpgInputStream.Wrap(inputStream);

            var initialTag = bcpgInput.NextPacketTag();

            if (initialTag != PacketTag.SecretKey && initialTag != PacketTag.SecretSubkey)
                throw new IOException("secret key ring doesn't start with secret key tag: "
                    + "tag 0x" + ((int)initialTag).ToString("X"));

            var secret = bcpgInput.ReadPacket<SecretKeyPacket>();

            // ignore GPG comment packets if found.
            while (bcpgInput.NextPacketTag() == PacketTag.Experimental2)
                bcpgInput.ReadPacket();

            var trust = ReadOptionalTrustPacket(bcpgInput);

            // revocation and direct signatures
            var keySigs = new List<PgpSignature>(ReadSignaturesAndTrust(bcpgInput));

            List<Object>              ids;
            List<TrustPacket>         idTrusts;
            List<List<PgpSignature>>  idSigs;
            ReadUserIds(bcpgInput, out ids, out idTrusts, out idSigs);

            var newSecretKey = new PgpSecretKey(secret, new PgpPublicKey(secret.PublicKeyPacket, trust, keySigs, ids, idTrusts, idSigs));
            keys.Add(newSecretKey.KeyId, newSecretKey);


            // Read subkeys
            while (bcpgInput.NextPacketTag() == PacketTag.SecretSubkey ||
                   bcpgInput.NextPacketTag() == PacketTag.PublicSubkey)
            {

                if (bcpgInput.NextPacketTag() == PacketTag.SecretSubkey)
                {

                    var sub = bcpgInput.ReadPacket<SecretSubkeyPacket>();

                    // ignore GPG comment packets if found.
                    while (bcpgInput.NextPacketTag() == PacketTag.Experimental2)
                        bcpgInput.ReadPacket();

                    var subTrust = ReadOptionalTrustPacket(bcpgInput);
                    var sigList  = new List<PgpSignature>(ReadSignaturesAndTrust(bcpgInput));

                    var newSecretKey2 = new PgpSecretKey(sub, new PgpPublicKey(sub.PublicKeyPacket, subTrust, sigList));
                    keys.Add(newSecretKey2.KeyId, newSecretKey2);

                }

                else
                {

                    var sub      = bcpgInput.ReadPacket<PublicSubkeyPacket>();
                    var subTrust = ReadOptionalTrustPacket(bcpgInput);
                    var sigList  = new List<PgpSignature>(ReadSignaturesAndTrust(bcpgInput));

                    var newPublicKey = new PgpPublicKey(sub, subTrust, sigList);
                    extraPubKeys.Add(newPublicKey.KeyId, newPublicKey);

                }

            }

        }

        #endregion




        public Byte[] GetEncoded()
        {

            var bOut = new MemoryStream();
            EncodeToStream(bOut);

            return bOut.ToArray();

        }


        #region EncodeToStream(OutStream)

        public void EncodeToStream(Stream OutStream)
        {

            if (OutStream == null)
                throw new ArgumentNullException("outStr");

            foreach (var key in keys.Values)
                key.Encode(OutStream);

            foreach (var extraPubKey in extraPubKeys.Values)
                extraPubKey.Encode(OutStream);

        }

        #endregion



        #region GetSecretKeyByKeyId(KeyId)

        public PgpSecretKey GetSecretKeyByKeyId(UInt64 KeyId)
        {

            PgpSecretKey _PgpSecretKey = null;

            if (keys.TryGetValue(KeyId, out _PgpSecretKey))
                return _PgpSecretKey;

            return null;

        }

        #endregion

        #region TryGetSecretKeyByKeyId(KeyId, out PgpSecretKey)

        public Boolean TryGetSecretKeyByKeyId(UInt64 KeyId, out PgpSecretKey PgpSecretKey)
        {
            return keys.TryGetValue(KeyId, out PgpSecretKey);
        }

        #endregion





        /// <summary>
        /// Replace the public key set on the secret ring with the corresponding key off the public ring.
        /// </summary>
        /// <param name="SecretRing">Secret ring to be changed.</param>
        /// <param name="PublicRing">Public ring containing the new public key set.</param>
        public static PgpSecretKeyRing ReplacePublicKeys(PgpSecretKeyRing  SecretRing,
                                                         PgpPublicKeyRing  PublicRing)
        {

            var newList = new List<PgpSecretKey>();

            foreach (var sk in SecretRing.keys.Values)
            {
                var pk = PublicRing.GetPublicKeyByKeyId(sk.KeyId);
                newList.Add(PgpSecretKey.ReplacePublicKey(sk, pk));
            }

            return new PgpSecretKeyRing(newList);

        }

        /// <summary>
        /// Return a copy of the passed in secret key ring, with the master key and sub keys encrypted
        /// using a new password and the passed in algorithm.
        /// </summary>
        /// <param name="ring">The <c>PgpSecretKeyRing</c> to be copied.</param>
        /// <param name="oldPassPhrase">The current password for key.</param>
        /// <param name="newPassPhrase">The new password for the key.</param>
        /// <param name="newEncAlgorithm">The algorithm to be used for the encryption.</param>
        /// <param name="rand">Source of randomness.</param>
        public static PgpSecretKeyRing CopyWithNewPassword(PgpSecretKeyRing          ring,
                                                           String                    oldPassPhrase,
                                                           String                    newPassPhrase,
                                                           SymmetricKeyAlgorithms  newEncAlgorithm,
                                                           SecureRandom              rand)

        {

            var newKeys = new List<PgpSecretKey>();

            foreach (var secretKey in ring.SecretKeys)
            {

                if (secretKey.IsPrivateKeyEmpty)
                    newKeys.Add(secretKey);

                else
                    newKeys.Add(PgpSecretKey.CopyWithNewPassword(secretKey, oldPassPhrase, newPassPhrase, newEncAlgorithm, rand));

            }

            return new PgpSecretKeyRing(newKeys, ring.extraPubKeys.Values);

        }

        /// <summary>
        /// Returns a new key ring with the secret key passed in either added or
        /// replacing an existing one with the same key ID.
        /// </summary>
        /// <param name="secRing">The secret key ring to be modified.</param>
        /// <param name="secKey">The secret key to be inserted.</param>
        /// <returns>A new <c>PgpSecretKeyRing</c></returns>
        public static PgpSecretKeyRing InsertSecretKey(PgpSecretKeyRing  secRing,
                                                       PgpSecretKey      secKey)
        {

            var keys         = new List<PgpSecretKey>(secRing.keys.Values);
            var found        = false;
            var masterFound  = false;

            for (int i = 0; i != keys.Count; i++)
            {

                var key = keys[i];

                if (key.KeyId == secKey.KeyId)
                {
                    found = true;
                    keys[i] = secKey;
                }

                if (key.IsMasterKey)
                    masterFound = true;

            }

            if (!found)
            {

                if (secKey.IsMasterKey)
                {
                    if (masterFound)
                        throw new ArgumentException("cannot add a master key to a ring that already has one");

                    keys.Insert(0, secKey);
                }

                else
                    keys.Add(secKey);

            }

            return new PgpSecretKeyRing(keys, secRing.extraPubKeys.Values);

        }

        /// <summary>Returns a new key ring with the secret key passed in removed from the key ring.</summary>
        /// <param name="secRing">The secret key ring to be modified.</param>
        /// <param name="secKey">The secret key to be removed.</param>
        /// <returns>A new <c>PgpSecretKeyRing</c>, or null if secKey is not found.</returns>
        public static PgpSecretKeyRing RemoveSecretKey(PgpSecretKeyRing  secRing,
                                                       PgpSecretKey      secKey)
        {

            var keys   = new List<PgpSecretKey>(secRing.keys.Values);
            var found  = false;

            for (int i = 0; i < keys.Count; i++)
            {

                var key = keys[i];

                if (key.KeyId == secKey.KeyId)
                {
                    found = true;
                    keys.RemoveAt(i);
                }

            }

            return found ? new PgpSecretKeyRing(keys, secRing.extraPubKeys.Values) : null;

        }

    }

}
