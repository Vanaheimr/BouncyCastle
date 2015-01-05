using System;
using System.IO;
using System.Linq;
using System.Collections;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    /// <remarks>
    /// Class to hold a single master public key and its subkeys.
    /// <p>
    /// Often PGP keyring files consist of multiple master keys, if you are trying to process
    /// or construct one of these you should use the <c>PgpPublicKeyRingBundle</c> class.
    /// </p>
    /// </remarks>
    public class PgpPublicKeyRing : PgpKeyRing
    {

        #region Data

        private readonly Dictionary<UInt64, PgpPublicKey> keys;

        #endregion

        #region Properties

        /// <summary>
        /// Return the first public key in the ring.
        /// </summary>
        public virtual PgpPublicKey PublicKey
        {
            get
            {
                return keys.Values.First();
            }
        }

        /// <summary>
        /// Allows enumeration of all the public keys.
        /// </summary>
        /// <returns>An <c>IEnumerable</c> of <c>PgpPublicKey</c> objects.</returns>
        public virtual IEnumerable<PgpPublicKey> PublicKeys
        {
            get
            {
                return keys.Values;
            }
        }

        #endregion

        #region Constructor(s)

        #region (internal) PgpPublicKeyRing(PublicKeys)

        internal PgpPublicKeyRing(IEnumerable<PgpPublicKey> PublicKeys)
        {
            this.keys = PublicKeys.ToDictionary(item => item.KeyId, item => item);
        }

        #endregion

        #region PgpPublicKeyRing(EncodedPublicKeyRing)

        public PgpPublicKeyRing(Byte[] EncodedPublicKeyRing)
            : this(new MemoryStream(EncodedPublicKeyRing, false))
        { }

        #endregion

        #region PgpPublicKeyRing(PublicKeyRingStream)

        public PgpPublicKeyRing(Stream PublicKeyRingStream)
        {

            var BCPGInputStream = BcpgInputStream.Wrap(PublicKeyRingStream);

            var initialTag = BCPGInputStream.NextPacketTag();
            if (initialTag != PacketTag.PublicKey && initialTag != PacketTag.PublicSubkey)
            {
                throw new IOException("public key ring doesn't start with public key tag: "
                    + "tag 0x" + ((int)initialTag).ToString("X"));
            }

            var pubPk   = BCPGInputStream.ReadPacket<PublicKeyPacket>();;
            var trustPk = ReadOptionalTrustPacket(BCPGInputStream);

            // direct signatures and revocations
            var keySigs = new List<PgpSignature>(ReadSignaturesAndTrust(BCPGInputStream));

            List<Object>              Ids;
            List<TrustPacket>         IdTrusts;
            List<List<PgpSignature>>  IdSigs;
            ReadUserIds(BCPGInputStream, out Ids, out IdTrusts, out IdSigs);

            this.keys = new Dictionary<UInt64, PgpPublicKey>();
            var pubKey = new PgpPublicKey(pubPk, trustPk, keySigs, Ids, IdTrusts, IdSigs);
            this.keys.Add(pubKey.KeyId, pubKey);

            // Read subkeys
            while (BCPGInputStream.NextPacketTag() == PacketTag.PublicSubkey)
            {
                var SubKey = ReadSubkey(BCPGInputStream);
                keys.Add(SubKey.KeyId, SubKey);
            }

        }

        #endregion

        #endregion


        #region GetPublicKeyByKeyId(KeyId)

        /// <summary>
        /// Return the public key referred to by the passed in key ID if it is present.
        /// </summary>
        public PgpPublicKey GetPublicKeyByKeyId(UInt64 KeyId)
        {

            PgpPublicKey _PgpPublicKey = null;

            if (keys.TryGetValue(KeyId, out _PgpPublicKey))
                return _PgpPublicKey;

            return null;

        }

        #endregion

        #region TryGetPublicKeyByKeyId(KeyId, out PgpPublicKey)

        public Boolean TryGetPublicKeyByKeyId(UInt64 KeyId, out PgpPublicKey PgpPublicKey)
        {
            return keys.TryGetValue(KeyId, out PgpPublicKey);
        }

        #endregion



        public virtual byte[] GetEncoded()
        {

            var bOut = new MemoryStream();
            Encode(bOut);

            return bOut.ToArray();

        }

        public virtual void Encode(Stream outStr)
        {

            if (outStr == null)
                throw new ArgumentNullException("outStr");

            foreach (var PublicKey in keys.Values)
            {
                PublicKey.Encode(outStr);
            }

        }

        /// <summary>
        /// Returns a new key ring with the public key passed in either added or
        /// replacing an existing one.
        /// </summary>
        /// <param name="pubRing">The public key ring to be modified.</param>
        /// <param name="pubKey">The public key to be inserted.</param>
        /// <returns>A new <c>PgpPublicKeyRing</c></returns>
        public static PgpPublicKeyRing InsertPublicKey(PgpPublicKeyRing  pubRing,
                                                       PgpPublicKey      pubKey)

        {

            var keys         = new List<PgpPublicKey>(pubRing.keys.Values);
            var found        = false;
            var masterFound  = false;

            for (int i = 0; i != keys.Count; i++)
            {

                var key = keys[i];

                if (key.KeyId == pubKey.KeyId)
                {
                    found = true;
                    keys[i] = pubKey;
                }

                if (key.IsMasterKey)
                {
                    masterFound = true;
                }

            }

            if (!found)
            {

                if (pubKey.IsMasterKey)
                {
                    if (masterFound)
                        throw new ArgumentException("cannot add a master key to a ring that already has one");

                    keys.Insert(0, pubKey);
                }

                else
                    keys.Add(pubKey);

            }

            return new PgpPublicKeyRing(keys);

        }

        /// <summary>Returns a new key ring with the public key passed in removed from the key ring.</summary>
        /// <param name="pubRing">The public key ring to be modified.</param>
        /// <param name="pubKey">The public key to be removed.</param>
        /// <returns>A new <c>PgpPublicKeyRing</c>, or null if pubKey is not found.</returns>
        public static PgpPublicKeyRing RemovePublicKey(PgpPublicKeyRing  pubRing,
                                                       PgpPublicKey      pubKey)
        {

            var keys   = new List<PgpPublicKey>(pubRing.keys.Values);
            var found  = false;

            for (int i = 0; i < keys.Count; i++)
            {

                var key = keys[i];

                if (key.KeyId == pubKey.KeyId)
                {
                    found = true;
                    keys.RemoveAt(i);
                }

            }

            return found ? new PgpPublicKeyRing(keys) : null;

        }

        internal static PgpPublicKey ReadSubkey(BcpgInputStream bcpgInput)
        {

            var pk      = bcpgInput.ReadPacket<PublicKeyPacket>();
            var kTrust  = ReadOptionalTrustPacket(bcpgInput);

            // PGP 8 actually leaves out the signature.
            var sigList = new List<PgpSignature>(ReadSignaturesAndTrust(bcpgInput));

            return new PgpPublicKey(pk, kTrust, sigList);

        }

    }

}
