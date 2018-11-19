using System;
using System.Linq;
using System.Collections;

using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.TeleTrust;

namespace Org.BouncyCastle.Asn1.X9
{

    /// <summary>
    /// A general class that reads all X9.62 style EC curve tables.
    /// </summary>
    public class ECNamedCurveTable
    {

        /// <summary>
        /// Return a X9ECParameters object representing the passed in named
        /// curve. The routine returns null if the curve is not present.
        /// </summary>
        /// <param name="CurveName">The name of the curve requested.</param>
        /// <returns>An X9ECParameters object or null if the curve is not available.</returns>
        public static X9ECParameters GetByName(String CurveName)

            => X962NamedCurves.GetByName(CurveName)      ??
               SecNamedCurves.GetByName(CurveName)       ??
               TeleTrusTNamedCurves.GetByName(CurveName) ??
               NistNamedCurves.GetByName(CurveName);

        /// <summary>
        /// Return the object identifier signified by the passed in name, or null when there is no object identifier associated with name.
        /// </summary>
        /// <param name="CurveOID">An object identifier.</param>
        /// <returns>The object identifier associated with name, if present.</returns>
        public static DerObjectIdentifier GetOid(String CurveOID)

            => X962NamedCurves.GetOid(CurveOID)      ??
               SecNamedCurves.GetOid(CurveOID)       ??
               TeleTrusTNamedCurves.GetOid(CurveOID) ??
               NistNamedCurves.GetOid(CurveOID);

        /// <summary>
        /// Return a X9ECParameters object representing the passed in named
        /// </summary>
        /// <param name="CurveOID">Oid the object id of the curve requested</param>
        /// <returns>An X9ECParameters object or null if the curve is not available.</returns>
        public static X9ECParameters GetByOid(DerObjectIdentifier CurveOID)

               // NOTE: All the NIST curves are currently from SEC, so no point in redundant OID lookup
            => X962NamedCurves.GetByOid(CurveOID) ??
               SecNamedCurves.GetByOid(CurveOID)  ??
               TeleTrusTNamedCurves.GetByOid(CurveOID);

        /// <summary>
        /// Return an enumeration of the names of the available curves.
        /// </summary>
        public static IEnumerable Names

            => X962NamedCurves.Names.
                   Concat(SecNamedCurves.Names).
                   Concat(NistNamedCurves.Names).
                   Concat(TeleTrusTNamedCurves.Names);


    }

}
