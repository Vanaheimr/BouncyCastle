using System;

namespace Org.BouncyCastle.Bcpg.Sig
{

    /// <summary>
    /// Packet giving signature expiration time.
    /// </summary>
    public class SignatureExpirationTime : SignatureSubpacket
    {

        #region Properties

        #region Time

        /// <summary>
        /// Time in seconds before signature expires after creation time.
        /// </summary>
        public UInt64 Time
        {
            get
            {

                return (UInt64) (((long) (_Data[0] & 0xff) << 24) |
                                 ((long) (_Data[1] & 0xff) << 16) |
                                 ((long) (_Data[2] & 0xff) <<  8) |
                                 ((long)  _Data[3] & 0xff));

            }
        }

        #endregion

        #endregion

        #region Constructor(s)

        #region SignatureExpirationTime(IsCritical, 

        public SignatureExpirationTime(Boolean  IsCitical,
                                       Byte[]   Data)

            : base(SignatureSubpackets.ExpireTime, IsCitical, Data)

        { }

        #endregion

        #region SignatureExpirationTime(IsCritical, Seconds)

        public SignatureExpirationTime(Boolean  IsCitical,
                                       UInt64   Seconds)

            : base(SignatureSubpackets.ExpireTime, IsCitical, TimeToBytes(Seconds))

        { }

        #endregion

        #endregion


        protected static Byte[] TimeToBytes(UInt64 Time)
        {

            return new Byte[] {
                (byte) (Time >> 24),
                (byte) (Time >> 16),
                (byte) (Time >>  8),
                (byte)  Time
            };

        }

    }

}
