using System;

using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Bcpg.Sig
{

    /// <summary>
    /// Packet giving signature creation time.
    /// </summary>
    public class SignatureCreationTime : SignatureSubpacket
    {

        #region Properties

        #region Time

        public DateTime Time
        {
            get
            {

                return DateTimeUtilities.UnixMsToDateTime((long)(((uint) _Data[0] << 24) |
                                                                 ((uint) _Data[1] << 16) |
                                                                 ((uint) _Data[2] <<  8) |
                                                                 ((uint) _Data[3])
                                                                ) * 1000L);

            }
        }

        #endregion

        #endregion

        #region Constructor(s)

        #region SignatureCreationTime(IsCritical, Data)

        public SignatureCreationTime(Boolean  IsCritical,
                                     Byte[]   Data)

            : base(SignatureSubpackets.CreationTime, IsCritical, Data)

        { }

        #endregion

        #region SignatureCreationTime(IsCritical, Date)

        public SignatureCreationTime(Boolean   IsCritical,
                                     DateTime  Date)

            : base(SignatureSubpackets.CreationTime, IsCritical, TimeToBytes(Date))

        { }

        #endregion

        #endregion


        protected static Byte[] TimeToBytes(DateTime Time)
        {

            var t = DateTimeUtilities.DateTimeToUnixMs(Time) / 1000L;

            return new Byte[] {
                (byte) (t >> 24),
                (byte) (t >> 16),
                (byte) (t >>  8),
                (byte)  t
            };

        }

    }

}
