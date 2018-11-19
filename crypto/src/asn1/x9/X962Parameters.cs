using System;

namespace Org.BouncyCastle.Asn1.X9
{

    public class X962Parameters : Asn1Encodable, IAsn1Choice
    {

        public Asn1Object  Parameters    { get; }


        public X962Parameters(X9ECParameters ecParameters)
        {
            this.Parameters = ecParameters.ToAsn1Object();
        }

        public X962Parameters(DerObjectIdentifier namedCurve)
        {
            this.Parameters = namedCurve;
        }

        public X962Parameters(Asn1Object obj)
        {
            this.Parameters = obj;
        }


        public Boolean IsNamedCurve
            => Parameters is DerObjectIdentifier;


        /// <summary>
        /// Produce an object suitable for an Asn1OutputStream.
        /// </summary>
        /// <remarks>
        /// Parameters ::= CHOICE {
        ///    ecParameters ECParameters,
        ///    namedCurve   CURVES.&amp;id({CurveNames}),
        ///    implicitlyCA Null
        /// }
        /// </remarks>
        public override Asn1Object ToAsn1Object()
            => Parameters;

    }

}
