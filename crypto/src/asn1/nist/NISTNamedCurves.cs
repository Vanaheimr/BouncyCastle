using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Nist
{

    /// <summary>
    /// Utility class for fetching curves using their NIST names as published in FIPS-PUB 186-3
    /// </summary>
    public sealed class NistNamedCurves
    {
        private NistNamedCurves()
        { }

        private static readonly Dictionary<String,              DerObjectIdentifier> objIds  = new Dictionary<String,              DerObjectIdentifier>();
        private static readonly Dictionary<DerObjectIdentifier, String>              names   = new Dictionary<DerObjectIdentifier, String>();

        private static void DefineCurve(String               name,
                                        DerObjectIdentifier  oid)
        {

            objIds.Add(name, oid);
            names. Add(oid,  name);

        }

        static NistNamedCurves()
        {

            DefineCurve("B-571", SecObjectIdentifiers.SecT571r1);
            DefineCurve("B-409", SecObjectIdentifiers.SecT409r1);
            DefineCurve("B-283", SecObjectIdentifiers.SecT283r1);
            DefineCurve("B-233", SecObjectIdentifiers.SecT233r1);
            DefineCurve("B-163", SecObjectIdentifiers.SecT163r2);

            DefineCurve("K-571", SecObjectIdentifiers.SecT571k1);
            DefineCurve("K-409", SecObjectIdentifiers.SecT409k1);
            DefineCurve("K-283", SecObjectIdentifiers.SecT283k1);
            DefineCurve("K-233", SecObjectIdentifiers.SecT233k1);
            DefineCurve("K-163", SecObjectIdentifiers.SecT163k1);

            DefineCurve("P-521", SecObjectIdentifiers.SecP521r1);
            DefineCurve("P-384", SecObjectIdentifiers.SecP384r1);
            DefineCurve("P-256", SecObjectIdentifiers.SecP256r1);
            DefineCurve("P-224", SecObjectIdentifiers.SecP224r1);
            DefineCurve("P-192", SecObjectIdentifiers.SecP192r1);

        }

        public static X9ECParameters GetByName(String name)
        {

            if (String.IsNullOrEmpty(name) || String.IsNullOrWhiteSpace(name))
                return null;

            if (objIds.TryGetValue(Platform.ToUpperInvariant(name), out DerObjectIdentifier oid))
                return GetByOid(oid);

            return null;

        }

        /// <summary>
        /// return the X9ECParameters object for the named curve represented by
        /// the passed in object identifier. Null if the curve isn't present.
        /// </summary>
        /// <param name="oid"></param>
        /// <returns>oid an object identifier representing a named curve, if present.</returns>
        public static X9ECParameters GetByOid(DerObjectIdentifier oid)
        {

            if (oid == null)
                return null;

            return SecNamedCurves.GetByOid(oid);

        }

        /// <summary>
        /// return the object identifier signified by the passed in name. Null
        /// if there is no object identifier associated with name.
        /// </summary>
        /// <param name="name"></param>
        /// <returns>the object identifier associated with name, if present.</returns>
        public static DerObjectIdentifier GetOid(String name)
        {

            if (String.IsNullOrEmpty(name) || String.IsNullOrWhiteSpace(name))
                return null;

            if (objIds.TryGetValue(Platform.ToUpperInvariant(name), out DerObjectIdentifier oid))
                return oid;

            return null;

        }

        /// <summary>
        /// Return the named curve name represented by the given object identifier.
        /// </summary>
        /// <param name="oid"></param>
        public static String GetName(DerObjectIdentifier oid)
        {

            if (oid == null)
                return null;

            if (names.TryGetValue(oid, out String name))
                return name;

            return null;

        }

        /// <summary>
        /// Returns an enumeration containing the name strings for curves
        /// contained in this structure.
        /// </summary>
        public static IEnumerable Names
            => objIds.Keys.ToArray();

    }
}
