using System;
using System.Collections;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>
    /// Often a PGP key ring file is made up of a succession of master/sub-key key rings.
    /// If you want to read an entire secret key file in one hit this is the class for you.
    /// </remarks>
    public class PgpSecretKeyRingBundle
    {

        #region Data

        private readonly Dictionary<UInt64, PgpSecretKeyRing>  secretRings;
        private readonly List<UInt64>                          order;

        #endregion

        #region Constructor(s)

        private PgpSecretKeyRingBundle(Dictionary<UInt64, PgpSecretKeyRing>  secretRings,
                                       List<UInt64>                          order)
        {

            this.secretRings  = secretRings;
            this.order        = order;

        }

        public PgpSecretKeyRingBundle(Byte[] encoding)
            : this(new MemoryStream(encoding, false))
        { }

        /// <summary>Build a PgpSecretKeyRingBundle from the passed in input stream.</summary>
        /// <param name="inputStream">Input stream containing data.</param>
        /// <exception cref="IOException">If a problem parsing the stream occurs.</exception>
        /// <exception cref="PgpException">If an object is encountered which isn't a PgpSecretKeyRing.</exception>
        public PgpSecretKeyRingBundle(Stream inputStream)
            : this(new PgpObjectFactory(inputStream).
                       AllPgpObjects().
                       Select(po => po as PgpSecretKeyRing).
                       Where (po => po != null))
        { }

        public PgpSecretKeyRingBundle(IEnumerable<PgpSecretKeyRing> e)
        {

            this.secretRings  = new Dictionary<UInt64, PgpSecretKeyRing>();
            this.order        = new List<UInt64>();

            foreach (var SecretKeyRing in e)
            {

                var pgpSecret = SecretKeyRing;

                if (pgpSecret == null)
                {
                    throw new PgpException(SecretKeyRing.GetType().FullName + " found where PgpSecretKeyRing expected");
                }

                var key = pgpSecret.GetPublicKey().KeyId;
                secretRings.Add(key, pgpSecret);
                order.Add(key);

            }

        }

        #endregion

        /// <summary>Return the number of rings in this collection.</summary>
        public int Count
        {
            get { return order.Count; }
        }

        /// <summary>Allow enumeration of the secret key rings making up this collection.</summary>
        public IEnumerable<PgpSecretKeyRing> GetKeyRings()
        {
            return secretRings.Values;
        }

        /// <summary>Allow enumeration of the key rings associated with the passed in userId.</summary>
        /// <param name="userId">The user ID to be matched.</param>
        /// <returns>An <c>IEnumerable</c> of key rings which matched (possibly none).</returns>
        public IEnumerable<PgpSecretKeyRing> GetKeyRings(String userId)
        {
            return GetKeyRings(userId, false, false);
        }

        /// <summary>Allow enumeration of the key rings associated with the passed in userId.</summary>
        /// <param name="userId">The user ID to be matched.</param>
        /// <param name="matchPartial">If true, userId need only be a substring of an actual ID string to match.</param>
        /// <returns>An <c>IEnumerable</c> of key rings which matched (possibly none).</returns>
        public IEnumerable<PgpSecretKeyRing> GetKeyRings(String   userId,
                                                         Boolean  matchPartial)
        {
            return GetKeyRings(userId, matchPartial, false);
        }

        /// <summary>Allow enumeration of the key rings associated with the passed in userId.</summary>
        /// <param name="userId">The user ID to be matched.</param>
        /// <param name="matchPartial">If true, userId need only be a substring of an actual ID string to match.</param>
        /// <param name="ignoreCase">If true, case is ignored in user ID comparisons.</param>
        /// <returns>An <c>IEnumerable</c> of key rings which matched (possibly none).</returns>
        public IEnumerable<PgpSecretKeyRing> GetKeyRings(String   userId,
                                                         Boolean  matchPartial,
                                                         Boolean  ignoreCase)
        {

            var rings = new List<PgpSecretKeyRing>();

            if (ignoreCase)
                userId = Platform.ToLowerInvariant(userId);

            foreach (var secRing in GetKeyRings())
            {

                foreach (var nextUserID in secRing.FirstSecretKey.UserIds)
                {

                    var next = nextUserID;

                    if (ignoreCase)
                    {
                        next = Platform.ToLowerInvariant(next);
                    }

                    if (matchPartial)
                    {
                        if (next.IndexOf(userId) > -1)
                            rings.Add(secRing);
                    }
                    else
                    {
                        if (next.Equals(userId))
                            rings.Add(secRing);
                    }

                }

            }

            return rings;

        }

        /// <summary>Return the PGP secret key associated with the given key id.</summary>
        /// <param name="keyId">The ID of the secret key to return.</param>
        public PgpSecretKey GetSecretKey(UInt64 keyId)
        {

            foreach (var secRing in GetKeyRings())
            {

                var sec = secRing.GetSecretKey(keyId);

                if (sec != null)
                    return sec;

            }

            return null;

        }

        /// <summary>Return the secret key ring which contains the key referred to by keyId</summary>
        /// <param name="keyId">The ID of the secret key</param>
        public PgpSecretKeyRing GetSecretKeyRing(UInt64 keyId)
        {

            var id = keyId;

            if (secretRings.ContainsKey(id))
                return secretRings[id];

            foreach (var secretRing in GetKeyRings())
            {

                var secret = secretRing.GetSecretKey(keyId);

                if (secret != null)
                    return secretRing;

            }

            return null;

        }

        /// <summary>
        /// Return true if a key matching the passed in key ID is present, false otherwise.
        /// </summary>
        /// <param name="keyID">key ID to look for.</param>
        public bool Contains(UInt64 keyID)
        {
            return GetSecretKey(keyID) != null;
        }

        public byte[] GetEncoded()
        {

            var bOut = new MemoryStream();
            Encode(bOut);

            return bOut.ToArray();

        }

        public void Encode(Stream outStr)
        {

            var bcpgOut = BcpgOutputStream.Wrap(outStr);

            foreach (var key in order)
            {
                var pub = secretRings[key];
                pub.Encode(bcpgOut);
            }

        }

        /// <summary>
        /// Return a new bundle containing the contents of the passed in bundle and
        /// the passed in secret key ring.
        /// </summary>
        /// <param name="bundle">The <c>PgpSecretKeyRingBundle</c> the key ring is to be added to.</param>
        /// <param name="secretKeyRing">The key ring to be added.</param>
        /// <returns>A new <c>PgpSecretKeyRingBundle</c> merging the current one with the passed in key ring.</returns>
        /// <exception cref="ArgumentException">If the keyId for the passed in key ring is already present.</exception>
        public static PgpSecretKeyRingBundle AddSecretKeyRing(PgpSecretKeyRingBundle  bundle,
                                                              PgpSecretKeyRing        secretKeyRing)
        {

            var key = secretKeyRing.GetPublicKey().KeyId;

            if (bundle.secretRings.ContainsKey(key))
                throw new ArgumentException("Collection already contains a key with a keyId for the passed in ring.");

            var newSecretRings  = new Dictionary<UInt64, PgpSecretKeyRing>(bundle.secretRings);
            var newOrder        = new List<UInt64>(bundle.order);

            newSecretRings[key] = secretKeyRing;
            newOrder.Add(key);

            return new PgpSecretKeyRingBundle(newSecretRings, newOrder);

        }

        /// <summary>
        /// Return a new bundle containing the contents of the passed in bundle with
        /// the passed in secret key ring removed.
        /// </summary>
        /// <param name="bundle">The <c>PgpSecretKeyRingBundle</c> the key ring is to be removed from.</param>
        /// <param name="secretKeyRing">The key ring to be removed.</param>
        /// <returns>A new <c>PgpSecretKeyRingBundle</c> not containing the passed in key ring.</returns>
        /// <exception cref="ArgumentException">If the keyId for the passed in key ring is not present.</exception>
        public static PgpSecretKeyRingBundle RemoveSecretKeyRing(PgpSecretKeyRingBundle  bundle,
                                                                 PgpSecretKeyRing        secretKeyRing)
        {

            var key = secretKeyRing.GetPublicKey().KeyId;

            if (!bundle.secretRings.ContainsKey(key))
                throw new ArgumentException("Collection does not contain a key with a keyId for the passed in ring.");

            var newSecretRings  = new Dictionary<UInt64, PgpSecretKeyRing>(bundle.secretRings);
            var newOrder        = new List<UInt64>(bundle.order);

            newSecretRings.Remove(key);
            newOrder.Remove(key);

            return new PgpSecretKeyRingBundle(newSecretRings, newOrder);

        }

    }

}
