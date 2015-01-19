using System;
using System.IO;

using Org.BouncyCastle.Utilities;
using System.Text;

namespace Org.BouncyCastle.Bcpg
{

    /// <summary>
    /// >Generic literal data packet.
    /// </summary>
    public class LiteralDataPacket : InputStreamPacket
    {

        #region Properties

        #region Format

        private readonly Int32 _Format;

        /// <summary>
        /// The format tag value.
        /// </summary>
        public Int32 Format
        {
            get
            {
                return _Format;
            }
        }

        #endregion

        #region FileName

        public String FileName
        {
            get
            {
                return Encoding.UTF8.GetString(_RawFileName, 0, _RawFileName.Length);
            }
        }

        #endregion

        #region RawFileName

        private readonly Byte[] _RawFileName;

        public Byte[] RawFileName
        {
            get
            {
                return _RawFileName;
            }
        }

        #endregion

        #region ModificationTime

        private readonly UInt64 _ModificationTime;

        /// <summary>
        /// The modification time of the file in milli-seconds (since Jan 1, 1970 UTC)
        /// </summary>
        public UInt64 ModificationTime
        {
            get
            {
                return _ModificationTime;
            }
        }

        #endregion

        #endregion

        #region Constructor(s)

        internal LiteralDataPacket(BcpgInputStream BCPGInputStream)
            : base(BCPGInputStream)
        {

            _Format  = BCPGInputStream.ReadByte();
            var len = BCPGInputStream.ReadByte();

            _RawFileName = new byte[len];
            for (var i = 0; i != len; ++i)
            {
                _RawFileName[i] = (byte) BCPGInputStream.ReadByte();
            }

            _ModificationTime = (((uint) BCPGInputStream.ReadByte() << 24) |
                                 ((uint) BCPGInputStream.ReadByte() << 16) |
                                 ((uint) BCPGInputStream.ReadByte() <<  8) |
                                  (uint) BCPGInputStream.ReadByte()) * 1000UL;

        }

        #endregion

    }

}
