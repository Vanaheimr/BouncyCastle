using System;



namespace Org.BouncyCastle.Bcpg.Sig
{
    /**
    * packet giving whether or not is revocable.
    */
    public class Revocable
        : SignatureSubpacket
    {
        private static byte[] BooleanToByteArray(
            bool    value)
        {
            byte[]    data = new byte[1];

            if (value)
            {
                data[0] = 1;
                return data;
            }
            else
            {
                return data;
            }
        }

        public Revocable(
            bool    critical,
            byte[]     data)
            : base(SignatureSubpackets.Revocable, critical, data)
    {
        }

        public Revocable(
            bool    critical,
            bool    isRevocable)
            : base(SignatureSubpackets.Revocable, critical, BooleanToByteArray(isRevocable))
    {
        }

        public bool IsRevocable()
        {
            return data[0] != 0;
        }
    }
}
