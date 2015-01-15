using System;

namespace Org.BouncyCastle.Bcpg.Sig
{

    /// <summary>
    /// Packet giving whether or not is revocable.
    /// </summary>
    public class Revocable : SignatureSubpacket
    {

        #region Properties

        #region IsRevocable

        public Boolean IsRevocable
        {
            get
            {
                return _Data[0] != 0;
            }
        }

        #endregion

        #endregion

        #region Constructor(s)

        #region Revocable(IsCritical, Data)

        public Revocable(Boolean  IsCritical,
                         Byte[]   Data)

            : base(SignatureSubpackets.Revocable, IsCritical, Data)

        { }

        #endregion

        #region Revocable(IsCritical, IsRevocable)

        public Revocable(Boolean  IsCritical,
                         Boolean  IsRevocable)

            : base(SignatureSubpackets.Revocable, IsCritical, BooleanToByteArray(IsRevocable))

        { }

        #endregion

        #endregion


        private static Byte[] BooleanToByteArray(Boolean value)
        {

            var data = new Byte[1];

            if (value)
            {
                data[0] = 1;
                return data;
            }

            else
                return data;

        }

    }

}
