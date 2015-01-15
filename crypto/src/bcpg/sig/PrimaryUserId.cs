using System;



namespace Org.BouncyCastle.Bcpg.Sig
{

    /// <summary>
    /// Packet giving whether or not the signature is
    /// signed using the primary UserId for the key.
    /// </summary>
    public class PrimaryUserId : SignatureSubpacket
    {

        #region Properties

        #region IsPrimaryUserId

        public Boolean IsPrimaryUserId
        {
            get
            {
                return _Data[0] != 0;
            }
        }

        #endregion

        #endregion

        #region Constructor(s)

        #region PrimaryUserId(IsCritical, Data)

        public PrimaryUserId(Boolean  IsCritical,
                             Byte[]   Data)

            : base(SignatureSubpackets.PrimaryUserId, IsCritical, Data)

        { }

        #endregion

        #region PrimaryUserId(IsCritical, IsPrimaryUserId)

        public PrimaryUserId(Boolean  IsCritical,
                             Boolean  IsPrimaryUserId)

            : base(SignatureSubpackets.PrimaryUserId, IsCritical, BooleanToByteArray(IsPrimaryUserId))

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
