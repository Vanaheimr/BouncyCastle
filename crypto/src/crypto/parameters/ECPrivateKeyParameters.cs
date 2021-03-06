using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{

    public class ECPrivateKeyParameters : ECKeyParameters
    {

        public BigInteger  D   { get; }


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



        public override Boolean Equals(object obj)
        {

            if (obj == this)
                return true;

            if (!(obj is ECPrivateKeyParameters other))
                return false;

            return Equals(other);

        }

        protected Boolean Equals(ECPrivateKeyParameters other)
            => D.Equals(other.D) && base.Equals(other);

        public override Int32 GetHashCode()
            => D.GetHashCode() ^ base.GetHashCode();

    }

}
