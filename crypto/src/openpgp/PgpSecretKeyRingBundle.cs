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

    /// <summary>
    /// Often a PGP key ring file is made up of a succession of master/sub-key key rings.
    /// If you want to read an entire secret key file in one hit this is the class for you.
    /// </summary>
    public class PgpSecretKeyRingBundle : IEnumerable<PgpSecretKeyRing>
    {

        #region Data

        private readonly Dictionary<UInt64, PgpSecretKeyRing>  SecretKeyRings;

        #endregion

        #region Properties

        #region Count

        /// <summary>
        /// Return the number of key rings in this collection.
        /// </summary>
        public UInt64 Count
        {
            get
            {
                return (UInt64) SecretKeyRings.Count;
            }
        }

        #endregion

        #endregion

        #region Constructor(s)

        #region PgpSecretKeyRingBundle(SecretKeyRings)

        public PgpSecretKeyRingBundle(IEnumerable<PgpSecretKeyRing> SecretKeyRings)
        {
            this.SecretKeyRings = SecretKeyRings.ToDictionary(key => key.FirstPublicKey.KeyId, key => key);
        }

        #endregion

        #region PgpSecretKeyRingBundle(EncodedSecretKeyRingBundle)

        public PgpSecretKeyRingBundle(Byte[] EncodedSecretKeyRingBundle)
            : this(new MemoryStream(EncodedSecretKeyRingBundle, false))
        { }

        #endregion

        #region PgpSecretKeyRingBundle(InputStream)

        /// <summary>Build a PgpSecretKeyRingBundle from the passed in input stream.</summary>
        /// <param name="InputStream">Input stream containing data.</param>
        /// <exception cref="IOException">If a problem parsing the stream occurs.</exception>
        /// <exception cref="PgpException">If an object is encountered which isn't a PgpSecretKeyRing.</exception>
        public PgpSecretKeyRingBundle(Stream InputStream)
            : this(new PgpObjectFactory(InputStream).
                       AllPgpObjects.
                           Select(po => po as PgpSecretKeyRing).
                           Where (po => po != null))
        { }

        #endregion

        #region PgpSecretKeyRingBundle(PgpObjects)

        public PgpSecretKeyRingBundle(IEnumerable<PgpObject> PgpObjects)
        {

            this.SecretKeyRings  = new Dictionary<UInt64, PgpSecretKeyRing>();

            foreach (var SecretKeyRing in PgpObjects)
            {

                var pgpSecret = SecretKeyRing as PgpSecretKeyRing;

                if (pgpSecret == null)
                    throw new PgpException("'" + SecretKeyRing.GetType().FullName + "' found where PgpSecretKeyRing was expected!");

                SecretKeyRings.Add(pgpSecret.FirstPublicKey.KeyId, pgpSecret);

            }

        }

        #endregion

        #endregion



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

            foreach (var secRing in SecretKeyRings.Values)
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
        /// <param name="KeyId">The ID of the secret key to return.</param>
        public PgpSecretKey GetSecretKey(UInt64 KeyId)
        {

            foreach (var SecretKeyRing in SecretKeyRings.Values)
            {

                var sec = SecretKeyRing.GetSecretKeyByKeyId(KeyId);

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

            if (SecretKeyRings.ContainsKey(id))
                return SecretKeyRings[id];

            foreach (var SecretKeyRing in SecretKeyRings.Values)
            {

                var secret = SecretKeyRing.GetSecretKeyByKeyId(keyId);

                if (secret != null)
                    return SecretKeyRing;

            }

            return null;

        }

        /// <summary>
        /// Return true if a key matching the passed in key ID is present, false otherwise.
        /// </summary>
        /// <param name="KeyId">key ID to look for.</param>
        public Boolean ContainsKeyId(UInt64 KeyId)
        {
            return GetSecretKey(KeyId) != null;
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

            // Is the key order important?
            foreach (var key in SecretKeyRings.Keys)
            {
                var pub = SecretKeyRings[key];
                pub.EncodeToStream(bcpgOut);
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

            var key = secretKeyRing.FirstPublicKey.KeyId;

            if (bundle.SecretKeyRings.ContainsKey(key))
                throw new ArgumentException("Collection already contains a key with a keyId for the passed in ring.");

            var newSecretRings  = new Dictionary<UInt64, PgpSecretKeyRing>(bundle.SecretKeyRings);
            newSecretRings[key] = secretKeyRing;

            return new PgpSecretKeyRingBundle(newSecretRings.Values);

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

            var key = secretKeyRing.FirstPublicKey.KeyId;

            if (!bundle.SecretKeyRings.ContainsKey(key))
                throw new ArgumentException("Collection does not contain a key with a keyId for the passed in ring.");

            var newSecretRings  = new Dictionary<UInt64, PgpSecretKeyRing>(bundle.SecretKeyRings);
            newSecretRings.Remove(key);

            return new PgpSecretKeyRingBundle(newSecretRings.Values);

        }


        public IEnumerator<PgpSecretKeyRing> GetEnumerator()
        {
            return SecretKeyRings.Values.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return SecretKeyRings.Values.GetEnumerator();
        }

    }

}
