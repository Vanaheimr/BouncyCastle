using System;
using System.IO;
using System.Linq;
using System.Collections;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using System.Text;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    /// <remarks>
    /// Often a PGP key ring file is made up of a succession of master/sub-key key rings.
    /// If you want to read an entire public key file in one hit this is the class for you.
    /// </remarks>
    public class PgpPublicKeyRingBundle : IEnumerable<PgpPublicKeyRing>
    {

        #region Data

        private readonly Dictionary<UInt64, PgpPublicKeyRing>  PublicKeyRings;

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
                return (UInt64) PublicKeyRings.Count;
            }
        }

        #endregion

        #endregion

        #region Constructor(s)

        #region PgpPublicKeyRingBundle(PublicKeyRings)

        public PgpPublicKeyRingBundle(IEnumerable<PgpPublicKeyRing> PublicKeyRings)
        {
            this.PublicKeyRings = PublicKeyRings.ToDictionary(key => key.PublicKey.KeyId, key => key);
        }

        #endregion

        #region PgpPublicKeyRingBundle(EncodedPublicKeyRingBundle)

        public PgpPublicKeyRingBundle(String EncodedPublicKeyRingBundle)
            : this(new MemoryStream(Encoding.UTF8.GetBytes(EncodedPublicKeyRingBundle), false))
        { }

        #endregion

        #region PgpPublicKeyRingBundle(EncodedPublicKeyRingBundle)

        public PgpPublicKeyRingBundle(Byte[] EncodedPublicKeyRingBundle)
            : this(new MemoryStream(EncodedPublicKeyRingBundle, false))
        { }

        #endregion

        #region PgpPublicKeyRingBundle(InputStream)

        /// <summary>Build a PgpPublicKeyRingBundle from the passed in input stream.</summary>
        /// <param name="InputStream">Input stream containing data.</param>
        /// <exception cref="IOException">If a problem parsing the stream occurs.</exception>
        /// <exception cref="PgpException">If an object is encountered which isn't a PgpPublicKeyRing.</exception>
        public PgpPublicKeyRingBundle(Stream InputStream)
            : this(new PgpObjectFactory(InputStream).AllPgpObjects)
        { }

        #endregion

        #region PgpPublicKeyRingBundle(PGPObjects)

        public PgpPublicKeyRingBundle(IEnumerable<PgpObject> PGPObjects)
        {

            this.PublicKeyRings  = new Dictionary<UInt64, PgpPublicKeyRing>();

            foreach (var PGPObject in PGPObjects)
            {

                var PublicKeyRing = PGPObject as PgpPublicKeyRing;
                if (PublicKeyRing != null)
                    PublicKeyRings.Add(PublicKeyRing.PublicKey.KeyId, PublicKeyRing);

                var PgpSignatureList = PGPObject as PgpSignatureList;
                //if (PgpSignatureList != null)

            }

        }

        #endregion

        #endregion


        #region GetPublicKey(KeyId)

        /// <summary>
        /// Return the PGP public key associated with the given key id.
        /// </summary>
        /// <param name="KeyId">The ID of the public key to return.</param>
        public PgpPublicKey GetPublicKey(UInt64 KeyId)
        {

            foreach (var pubRing in PublicKeyRings.Values)
            {

                var pub = pubRing.GetPublicKeyByKeyId(KeyId);

                if (pub != null)
                    return pub;

            }

            return null;

        }

        #endregion

        #region GetPublicKeyRing(KeyId)

        /// <summary>
        /// Return the public key ring which contains the key referred to by keyId.
        /// </summary>
        /// <param name="KeyId">key ID to match against</param>
        public PgpPublicKeyRing GetPublicKeyRing(UInt64 KeyId)
        {

            if (PublicKeyRings.ContainsKey(KeyId))
                return PublicKeyRings[KeyId];

            foreach (var pubRing in PublicKeyRings.Values)
            {

                var pub = pubRing.GetPublicKeyByKeyId(KeyId);

                if (pub != null)
                    return pubRing;

            }

            return null;

        }

        #endregion

        #region ContainsKeyId(KeyId)

        /// <summary>
        /// Return true if a key matching the passed in key ID is present, false otherwise.
        /// </summary>
        /// <param name="KeyId">key ID to look for.</param>
        public Boolean ContainsKeyId(UInt64 KeyId)
        {
            return GetPublicKey(KeyId) != null;
        }

        #endregion


        #region Search(UserId, MatchPartial = false, IgnoreCase = false)

        /// <summary>
        /// Allow enumeration of the key rings associated with the given UserId.
        /// </summary>
        /// <param name="UserId">The user ID to be matched.</param>
        /// <param name="MatchPartial">If true, userId need only be a substring of an actual ID string to match.</param>
        /// <param name="IgnoreCase">If true, case is ignored in user ID comparisons.</param>
        public IEnumerable<PgpPublicKeyRing> Search(String   UserId,
                                                    Boolean  MatchPartial = false,
                                                    Boolean  IgnoreCase   = false)
        {

            var rings = new List<PgpPublicKeyRing>();

            if (IgnoreCase)
                UserId = Platform.ToLowerInvariant(UserId);

            foreach (var pubRing in PublicKeyRings.Values)
            {
                foreach (var nextUserID in pubRing.PublicKey.UserIds)
                {

                    var next = nextUserID;

                    if (IgnoreCase)
                        next = Platform.ToLowerInvariant(next);

                    if (MatchPartial)
                    {
                        if (next.IndexOf(UserId) > -1)
                            rings.Add(pubRing);
                    }
                    else
                    {
                        if (next.Equals(UserId))
                            rings.Add(pubRing);
                    }

                }
            }

            return rings;

        }

        #endregion



        public Byte[] GetEncoded()
        {

            var bOut = new MemoryStream();
            Encode(bOut);

            return bOut.ToArray();

        }

        public void Encode(Stream outStr)
        {

            var bcpgOut = BcpgOutputStream.Wrap(outStr);

            // Is the key order important?
            foreach (var key in PublicKeyRings.Keys)
            {
                var sec = PublicKeyRings[key];
                sec.Encode(bcpgOut);
            }

        }




        #region (static) AddPublicKeyRing(PublicKeyRingBundle, PublicKeyRing)

        /// <summary>
        /// Return a new bundle containing the contents of the passed in bundle and
        /// the passed in public key ring.
        /// </summary>
        /// <param name="PublicKeyRingBundle">The <c>PgpPublicKeyRingBundle</c> the key ring is to be added to.</param>
        /// <param name="PublicKeyRing">The key ring to be added.</param>
        /// <returns>A new <c>PgpPublicKeyRingBundle</c> merging the current one with the passed in key ring.</returns>
        /// <exception cref="ArgumentException">If the keyId for the passed in key ring is already present.</exception>
        public static PgpPublicKeyRingBundle AddPublicKeyRing(PgpPublicKeyRingBundle  PublicKeyRingBundle,
                                                              PgpPublicKeyRing        PublicKeyRing)
        {

            var key = PublicKeyRing.PublicKey.KeyId;

            if (PublicKeyRingBundle.PublicKeyRings.ContainsKey(key))
                throw new ArgumentException("Bundle already contains a key with a keyId for the passed in ring.");

            var newPubRings  = new Dictionary<UInt64, PgpPublicKeyRing>(PublicKeyRingBundle.PublicKeyRings);

            newPubRings[key] = PublicKeyRing;

            return new PgpPublicKeyRingBundle(newPubRings.Values);

        }

        #endregion

        #region (static) RemovePublicKeyRing(PublicKeyRingBundle, PublicKeyRing)

        /// <summary>
        /// Return a new bundle containing the contents of the passed in bundle with
        /// the passed in public key ring removed.
        /// </summary>
        /// <param name="PublicKeyRingBundle">The <c>PgpPublicKeyRingBundle</c> the key ring is to be removed from.</param>
        /// <param name="PublicKeyRing">The key ring to be removed.</param>
        /// <returns>A new <c>PgpPublicKeyRingBundle</c> not containing the passed in key ring.</returns>
        /// <exception cref="ArgumentException">If the keyId for the passed in key ring is not present.</exception>
        public static PgpPublicKeyRingBundle RemovePublicKeyRing(PgpPublicKeyRingBundle  PublicKeyRingBundle,
                                                                 PgpPublicKeyRing        PublicKeyRing)
        {

            var key = PublicKeyRing.PublicKey.KeyId;

            if (!PublicKeyRingBundle.PublicKeyRings.ContainsKey(key))
                throw new ArgumentException("Bundle does not contain a key with a keyId for the passed in ring.");

            var newPubRings  = new Dictionary<UInt64, PgpPublicKeyRing>(PublicKeyRingBundle.PublicKeyRings);

            newPubRings.Remove(key);

            return new PgpPublicKeyRingBundle(newPubRings.Values);

        }

        #endregion


        public IEnumerator<PgpPublicKeyRing> GetEnumerator()
        {
            return PublicKeyRings.Values.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return PublicKeyRings.Values.GetEnumerator();
        }

    }

}
