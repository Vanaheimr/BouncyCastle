using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{

    public class ECDomainParameters
    {

        public ECCurve     Curve    { get; internal set; }
        public byte[]      Seed     { get; internal set; }
        public ECPoint     G        { get; internal set; }
        public BigInteger  N        { get; internal set; }
        public BigInteger  H        { get; internal set; }

        public ECDomainParameters(ECCurve     curve,
                                  ECPoint     g,
                                  BigInteger  n)

            : this(curve, g, n, BigInteger.One)

        { }

        public ECDomainParameters(ECCurve     curve,
                                  ECPoint     g,
                                  BigInteger  n,
                                  BigInteger  h)

            : this(curve, g, n, h, null)

        { }

        public ECDomainParameters(ECCurve     curve,
                                  ECPoint     g,
                                  BigInteger  n,
                                  BigInteger  h,
                                  Byte[]      seed)
        {

            this.Curve  = curve          ?? throw new ArgumentNullException("curve");
            this.G      = g?.Normalize() ?? throw new ArgumentNullException("g");
            this.N      = n              ?? throw new ArgumentNullException("n");
            this.H      = h              ?? throw new ArgumentNullException("h");
            this.Seed   = Arrays.Clone(seed);

        }


        public Byte[] GetSeed()
            => Arrays.Clone(Seed);

        public override Boolean Equals(Object obj)
        {

            if (obj == this)
                return true;

            if (!(obj is ECDomainParameters other))
                return false;

            return Equals(other);

        }

        protected Boolean Equals(ECDomainParameters other)

            => Curve.Equals(other.Curve) &&
                   G.Equals(other.G)     &&
                   N.Equals(other.N)     &&
                   H.Equals(other.H)     &&
                   Arrays.AreEqual(Seed, other.Seed);


        public override int GetHashCode()

            => Curve.GetHashCode() ^
                   G.GetHashCode() ^
                   N.GetHashCode() ^
                   H.GetHashCode() ^
                   Arrays.GetHashCode(Seed);

    }

}
