using System;
using System.IO;

using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    /// <summary>
    /// Class for processing literal data objects.
    /// </summary>
    public class PgpLiteralData : PgpObject
    {

        #region Const

        public const char Binary = 'b';
        public const char Text   = 't';
        public const char Utf8   = 'u';

        /// <summary>
        /// The special name indicating a "for your eyes only" packet.
        /// </summary>
        public const string Console = "_CONSOLE";

        #endregion

        #region Data

        private LiteralDataPacket data;

        #endregion

        #region Properties

        #region Format

        /// <summary>
        /// The format of the data stream - Binary or Text
        /// </summary>
        public Int32 Format
        {
            get
            {
                return data.Format;
            }
        }

        #endregion

        #region FileName

        /// <summary>
        /// The file name that's associated with the data stream.
        /// </summary>
        public String FileName
        {
            get
            {
                return data.FileName;
            }
        }

        #endregion

        #region RawFileName

        /// <summary>
        /// Return the file name as an unintrepreted byte array.
        /// </summary>
        public Byte[] RawFileName
        {
            get
            {
                return data.RawFileName;
            }
        }

        #endregion

        #region ModificationTime

        /// <summary>
        /// The modification time for the file.
        /// </summary>
        public DateTime ModificationTime
        {
            get
            {
                return DateTimeUtilities.UnixMsToDateTime((UInt64) data.ModificationTime);
            }
        }

        #endregion

        #region InputStream

        /// <summary>
        /// The raw input stream for the data stream.
        /// </summary>
        public Stream InputStream
        {
            get
            {
                return data.GetInputStream();
            }
        }

        #endregion

        #region DataStream

        /// <summary>
        /// The input stream representing the data stream.
        /// </summary>
        public Stream DataStream
        {
            get
            {
                return InputStream;
            }
        }

        #endregion

        #endregion

        #region Constructor(s)

        public PgpLiteralData(BcpgInputStream BCPGInputStream)
        {
            data = BCPGInputStream.ReadPacket<LiteralDataPacket>();
        }

        #endregion

    }

}
