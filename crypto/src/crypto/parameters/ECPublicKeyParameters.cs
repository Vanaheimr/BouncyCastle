using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Crypto.Parameters
{

    public class ECPublicKeyParameters : ECKeyParameters
    {

        public ECPoint  Q   { get; }


        public ECPublicKeyParameters(ECPoint             q,
                                     ECDomainParameters  parameters)

            : this("EC", q, parameters)

        { }


        [Obsolete("Use version with explicit 'algorithm' parameter")]
        public ECPublicKeyParameters(ECPoint              q,
                                     DerObjectIdentifier  publicKeyParamSet)

            : base("ECGOST3410",
                   false,
                   publicKeyParamSet)

        {

            if (q == null)
                throw new ArgumentNullException("q");

            this.Q = q.Normalize();

        }

        public ECPublicKeyParameters(String              algorithm,
                                     ECPoint             q,
                                     ECDomainParameters  parameters)

            : base(algorithm,
                   false,
                   parameters)

        {

            if (q == null)
                throw new ArgumentNullException("q");

            this.Q = q.Normalize();

        }

        public ECPublicKeyParameters(String               algorithm,
                                     ECPoint              q,
                                     DerObjectIdentifier  publicKeyParamSet)

            : base(algorithm,
                   false,
                   publicKeyParamSet)

        {

            if (q == null)
                throw new ArgumentNullException("q");

            this.Q = q.Normalize();

        }



        public override Boolean Equals(object obj)
        {

            if (obj == this)
                return true;

            if (!(obj is ECPublicKeyParameters other))
                return false;

            return Equals(other);

        }

        protected Boolean Equals(ECPublicKeyParameters other)
            => Q.Equals(other.Q) && base.Equals(other);

        public override Int32 GetHashCode()
            => Q.GetHashCode() ^ base.GetHashCode();


    }

}
