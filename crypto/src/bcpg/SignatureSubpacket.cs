using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{

    /// <summary>
    /// Basic type for a PGP Signature sub-packet.
    /// </summary>
    public class SignatureSubpacket
    {

        #region Data

        internal readonly Byte[] _Data;

        #endregion

        #region Properties

        #region SubpacketType

        private readonly SignatureSubpackets _SubpacketType;

        public SignatureSubpackets SubpacketType
        {
            get
            {
                return _SubpacketType;
            }
        }

        #endregion

        #region IsCritical

        private readonly Boolean _IsCritical;

        public Boolean IsCritical
        {
            get
            {
                return _IsCritical;
            }
        }

        #endregion

        #endregion

        #region (internal) Constructor(s)

        protected internal SignatureSubpacket(SignatureSubpackets  SubpacketType,
                                              Boolean                  IsCritical,
                                              Byte[]                   Data)
        {
            this._SubpacketType  = SubpacketType;
            this._IsCritical     = IsCritical;
            this._Data           = Data;
        }

        #endregion


        #region Encode(OutputStream)

        public void Encode(Stream OutputStream)
        {

            var bodyLen = _Data.Length + 1;

            if (bodyLen < 192)
                OutputStream.WriteByte((byte) bodyLen);

            else if (bodyLen <= 8383)
            {
                bodyLen -= 192;
                OutputStream.WriteByte((byte) (((bodyLen >> 8) & 0xff) + 192));
                OutputStream.WriteByte((byte) bodyLen);
            }

            else
            {
                OutputStream.WriteByte(0xff);
                OutputStream.WriteByte((byte) (bodyLen >> 24));
                OutputStream.WriteByte((byte) (bodyLen >> 16));
                OutputStream.WriteByte((byte) (bodyLen >>  8));
                OutputStream.WriteByte((byte)  bodyLen);
            }

            if (IsCritical)
                OutputStream.WriteByte((byte) (0x80 | (int) _SubpacketType));

            else
                OutputStream.WriteByte((byte) _SubpacketType);

            OutputStream.Write(_Data, 0, _Data.Length);

        }

        #endregion

        #region GetData()

        /// <summary>
        /// Return the generic data making up the packet.
        /// </summary>
        public Byte[] GetData()
        {
            return (Byte[])_Data.Clone();
        }

        #endregion

    }

}
