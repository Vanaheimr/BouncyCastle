using System;



namespace Org.BouncyCastle.Bcpg.Sig
{

    /// <summary>
    /// Packet giving time after creation at which the key expires.
    /// </summary>
    public class KeyExpirationTime : SignatureSubpacket
    {

        #region Properties

        #region Time

        /// <summary>
        /// The number of seconds after creation time a key is valid for.
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

        #region KeyExpirationTime(IsCritical, Data)

        public KeyExpirationTime(Boolean  IsCritical,
                                 Byte[]   Data)

            : base(SignatureSubpackets.KeyExpireTime, IsCritical, Data)

        { }

        #endregion

        #region KeyExpirationTime(IsCritical, Seconds)

        public KeyExpirationTime(Boolean  IsCritical,
                                 UInt64   Seconds)

            : base(SignatureSubpackets.KeyExpireTime, IsCritical, TimeToBytes(Seconds))

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
