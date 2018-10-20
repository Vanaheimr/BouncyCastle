using System;
using System.Globalization;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{

    public class ECPrivateKeyParameters : ECKeyParameters
    {

        public ECPrivateKeyParameters(BigInteger          d,
                                      ECDomainParameters  parameters)

            : this("EC", d, parameters)

        { }

        //[Obsolete("Use version with explicit 'algorithm' parameter")]
        //public ECPrivateKeyParameters(BigInteger           d,
        //                              DerObjectIdentifier  publicKeyParamSet)

        //    : base("ECGOST3410", true, publicKeyParamSet)

        //{

        //    this.D = d ?? throw new ArgumentNullException("d");

        //}

        public ECPrivateKeyParameters(String              algorithm,
                                      BigInteger          d,
                                      ECDomainParameters  parameters)

            : base(algorithm, true, parameters)

        {

            this.D = d ?? throw new ArgumentNullException("d");

        }

        public ECPrivateKeyParameters(String               algorithm,
                                      BigInteger           d,
                                      DerObjectIdentifier  publicKeyParamSet)

            : base(algorithm, true, publicKeyParamSet)

        {

            this.D = d ?? throw new ArgumentNullException("d");

        }

        public BigInteger D { get; }

        public override bool Equals(object obj)
        {

            if (obj == this)
                return true;

            if (!(obj is ECPrivateKeyParameters other))
                return false;

            return Equals(other);

        }

        protected bool Equals(ECPrivateKeyParameters other)
        {
            return D.Equals(other.D) && base.Equals(other);
        }

        public override int GetHashCode()
        {
            return D.GetHashCode() ^ base.GetHashCode();
        }

    }

}
