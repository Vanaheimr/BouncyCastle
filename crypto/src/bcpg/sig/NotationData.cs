using System;
using System.IO;
using System.Text;

namespace Org.BouncyCastle.Bcpg.Sig
{

    /// <summary>
    /// Class provided a NotationData object according to
    /// RFC2440, Chapter 5.2.3.15. Notation Data
    /// </summary>
    public class NotationData : SignatureSubpacket
    {

        #region Data

        public const Byte HeaderFlagLength   = 4;
        public const Byte HeaderNameLength   = 2;
        public const Byte HeaderValueLength  = 2;

        #endregion

        #region Properties

        #region IsHumanReadable

        public Boolean IsHumanReadable
        {
            get
            {
                return _Data[0] == (byte) 0x80;
            }
        }

        #endregion

        #region NotationName

        public String NotationName
        {
            get
            {

                return Encoding.UTF8.GetString(_Data,
                                               HeaderFlagLength + HeaderNameLength + HeaderValueLength,
                                               ((_Data[HeaderFlagLength    ] << 8) +
                                                (_Data[HeaderFlagLength + 1] << 0)));

            }
        }

        #endregion

        #region NotationValue

        public String NotationValue
        {
            get
            {
                return Encoding.UTF8.GetString(_Data,
                                               HeaderFlagLength + HeaderNameLength + HeaderValueLength + ((_Data[HeaderFlagLength    ] << 8) +
                                                                                                          (_Data[HeaderFlagLength + 1] << 0)),
                                               ((_Data[HeaderFlagLength + HeaderNameLength    ] << 8) +
                                                (_Data[HeaderFlagLength + HeaderNameLength + 1] << 0)));
            }
        }

        #endregion

        #endregion

        #region Constructor(s)

        #region NotationData(IsCritical, Data)

        public NotationData(Boolean  IsCritical,
                            Byte[]   Data)

            : base(SignatureSubpackets.NotationData, IsCritical, Data)

        { }

        #endregion

        #region NotationData(IsCritical, IsHumanReadable, NotationName, NotationValue)

        public NotationData(Boolean  IsCritical,
                            Boolean  IsHumanReadable,
                            String   NotationName,
                            String   NotationValue)

            : base(SignatureSubpackets.NotationData, IsCritical, createData(IsHumanReadable, NotationName, NotationValue))

        { }

        #endregion

        #endregion


        private static Byte[] createData(Boolean  IsHumanReadable,
                                         String   NotationName,
                                         String   NotationValue)
        {

            var _MemoryStream = new MemoryStream();

            // (4 octets of flags, 2 octets of name length (M),
            // 2 octets of value length (N),
            // M octets of name data,
            // N octets of value data)

            // flags
            _MemoryStream.WriteByte(IsHumanReadable ? (byte) 0x80 : (byte) 0x00);
            _MemoryStream.WriteByte(0x0);
            _MemoryStream.WriteByte(0x0);
            _MemoryStream.WriteByte(0x0);

            var nameData     = Encoding.UTF8.GetBytes(NotationName);
            var nameLength   = System.Math.Min(nameData.Length, 0xFF);
            var valueData    = Encoding.UTF8.GetBytes(NotationValue);
            var valueLength  = System.Math.Min(valueData.Length, 0xFF);

            // name length
            _MemoryStream.WriteByte((byte)(nameLength >> 8));
            _MemoryStream.WriteByte((byte)(nameLength >> 0));

            // value length
            _MemoryStream.WriteByte((byte)(valueLength >> 8));
            _MemoryStream.WriteByte((byte)(valueLength >> 0));

            // name
            _MemoryStream.Write(nameData, 0, nameLength);

            // value
            _MemoryStream.Write(valueData, 0, valueLength);

            return _MemoryStream.ToArray();

        }

    }

}
