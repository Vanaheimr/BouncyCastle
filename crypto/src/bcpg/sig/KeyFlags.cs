using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Bcpg.Sig
{

    /// <summary>
    /// Packet holding the key flag values.
    /// </summary>
    public class KeyFlags : SignatureSubpacket
    {

        #region Data

        public const int CertifyOther    = 0x01;
        public const int SignData        = 0x02;
        public const int EncryptComms    = 0x04;
        public const int EncryptStorage  = 0x08;
        public const int Split           = 0x10;
        public const int Authentication  = 0x20;
        public const int Shared          = 0x80;

        #endregion

        #region Properties

        #region Flags

        /// <summary>
        /// Return the flag values contained in the first 4 octets (note: at the moment
        /// the standard only uses the first one).
        /// </summary>
        public int Flags
        {
            get
            {

                var flags = 0;

                for (var i = 0; i != _Data.Length; i++)
                    flags |= (_Data[i] & 0xff) << (i * 8);

                return flags;

            }
        }

        #endregion

        #endregion

        #region Constructor(s)

        #region KeyFlags(IsCritical, 

        public KeyFlags(Boolean  IsCritical,
                        Byte[]   Data)

            : base(SignatureSubpackets.KeyFlags, IsCritical, Data)

        { }

        #endregion

        #region KeyFlags(IsCritical,

        public KeyFlags(Boolean  IsCritical,
                        Int32    Flags)

            : base(SignatureSubpackets.KeyFlags, IsCritical, IntToByteArray(Flags))

        { }

        #endregion

        #endregion


        private static Byte[] IntToByteArray(Int32 Value)
        {

            var tmp = new byte[4];
            int size = 0;

            for (int i = 0; i != 4; i++)
            {

                tmp[i] = (byte)(Value >> (i * 8));

                if (tmp[i] != 0)
                    size = i;

            }

            var data = new byte[size + 1];
            Array.Copy(tmp, 0, data, 0, data.Length);

            return data;

        }

    }

}
