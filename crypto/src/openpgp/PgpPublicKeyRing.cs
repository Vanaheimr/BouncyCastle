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
    public class PgpPublicKeyRing : PgpKeyRing,
                                    IEnumerable<PgpPublicKey>
    {

        #region Data

        private readonly Dictionary<UInt64, PgpPublicKey> _PublicKeys;

        #endregion

        #region Properties

        /// <summary>
        /// Return the first public key in the ring.
        /// </summary>
        public virtual PgpPublicKey PublicKey
        {
            get
            {
                return _PublicKeys.Values.First();
            }
        }

        #endregion

        #region Constructor(s)

        #region (internal) PgpPublicKeyRing(PublicKeys)

        internal PgpPublicKeyRing(IEnumerable<PgpPublicKey> PublicKeys)
        {
            this._PublicKeys = PublicKeys.ToDictionary(item => item.KeyId, item => item);
        }

        internal PgpPublicKeyRing(params PgpPublicKey[] PublicKeys)
        {
            this._PublicKeys = PublicKeys.ToDictionary(item => item.KeyId, item => item);
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

            this._PublicKeys = new Dictionary<UInt64, PgpPublicKey>();
            var pubKey = new PgpPublicKey(pubPk, trustPk, keySigs, Ids, IdTrusts, IdSigs);
            this._PublicKeys.Add(pubKey.KeyId, pubKey);

            // Read subkeys
            while (BCPGInputStream.NextPacketTag() == PacketTag.PublicSubkey)
            {
                var SubKey = ReadSubkey(BCPGInputStream);
                _PublicKeys.Add(SubKey.KeyId, SubKey);
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

            if (_PublicKeys.TryGetValue(KeyId, out _PgpPublicKey))
                return _PgpPublicKey;

            return null;

        }

        #endregion

        #region TryGetPublicKeyByKeyId(KeyId, out PgpPublicKey)

        public Boolean TryGetPublicKeyByKeyId(UInt64 KeyId, out PgpPublicKey PgpPublicKey)
        {
            return _PublicKeys.TryGetValue(KeyId, out PgpPublicKey);
        }

        #endregion



        public byte[] GetEncoded()
        {

            var bOut = new MemoryStream();
            Encode(bOut);

            return bOut.ToArray();

        }

        public void Encode(Stream outStr)
        {

            if (outStr == null)
                throw new ArgumentNullException("outStr");

            foreach (var PublicKey in _PublicKeys.Values)
            {
                PublicKey.Encode(outStr);
            }

        }


        #region (static) InsertPublicKey(PublicKeyRing, PublicKey)

        /// <summary>
        /// Returns a new key ring with the public key passed in either added or
        /// replacing an existing one.
        /// </summary>
        /// <param name="PublicKeyRing">The public key ring to be modified.</param>
        /// <param name="PublicKey">The public key to be inserted.</param>
        /// <returns>A new <c>PgpPublicKeyRing</c></returns>
        public static PgpPublicKeyRing InsertPublicKey(PgpPublicKeyRing  PublicKeyRing,
                                                       PgpPublicKey      PublicKey)

        {

            var keys         = new List<PgpPublicKey>(PublicKeyRing._PublicKeys.Values);
            var found        = false;
            var masterFound  = false;

            for (int i = 0; i != keys.Count; i++)
            {

                var key = keys[i];

                if (key.KeyId == PublicKey.KeyId)
                {
                    found = true;
                    keys[i] = PublicKey;
                }

                if (key.IsMasterKey)
                {
                    masterFound = true;
                }

            }

            if (!found)
            {

                if (PublicKey.IsMasterKey)
                {
                    if (masterFound)
                        throw new ArgumentException("cannot add a master key to a ring that already has one");

                    keys.Insert(0, PublicKey);
                }

                else
                    keys.Add(PublicKey);

            }

            return new PgpPublicKeyRing(keys);

        }

        #endregion

        #region (static) RemovePublicKey(PublicKeyRing, PublicKey)

        /// <summary>Returns a new key ring with the public key passed in removed from the key ring.</summary>
        /// <param name="PublicKeyRing">The public key ring to be modified.</param>
        /// <param name="PublicKey">The public key to be removed.</param>
        /// <returns>A new <c>PgpPublicKeyRing</c>, or null if pubKey is not found.</returns>
        public static PgpPublicKeyRing RemovePublicKey(PgpPublicKeyRing  PublicKeyRing,
                                                       PgpPublicKey      PublicKey)
        {

            var keys   = new List<PgpPublicKey>(PublicKeyRing._PublicKeys.Values);
            var found  = false;

            for (int i = 0; i < keys.Count; i++)
            {

                var key = keys[i];

                if (key.KeyId == PublicKey.KeyId)
                {
                    found = true;
                    keys.RemoveAt(i);
                }

            }

            return found ? new PgpPublicKeyRing(keys) : null;

        }

        #endregion

        #region (internal, static) ReadSubkey(bcpgInput)

        internal static PgpPublicKey ReadSubkey(BcpgInputStream bcpgInput)
        {

            var pk      = bcpgInput.ReadPacket<PublicKeyPacket>();
            var kTrust  = ReadOptionalTrustPacket(bcpgInput);

            // PGP 8 actually leaves out the signature.
            var sigList = new List<PgpSignature>(ReadSignaturesAndTrust(bcpgInput));

            return new PgpPublicKey(pk, kTrust, sigList);

        }

        #endregion


        #region GetEnumerator()

        public IEnumerator<PgpPublicKey> GetEnumerator()
        {
            return _PublicKeys.Values.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return _PublicKeys.Values.GetEnumerator();
        }

        #endregion

    }

}
