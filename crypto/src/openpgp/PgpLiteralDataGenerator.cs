using System;
using System.IO;
using System.Text;

using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    /// <summary>
    /// Class for producing literal data packets.
    /// </summary>
    public class PgpLiteralDataGenerator : IStreamGenerator
    {

        #region Const

        public const char Binary  = PgpLiteralData.Binary;
        public const char Text    = PgpLiteralData.Text;
        public const char Utf8    = PgpLiteralData.Utf8;

        /// <summary>
        /// The special name indicating a "for your eyes only" packet.
        /// </summary>
        public const String Console = PgpLiteralData.Console;

        #endregion

        #region Data

        private          BcpgOutputStream  pkOut;
        private readonly Boolean           UseOldFormat;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Generates literal data objects in the old format.
        /// This is important if you need compatibility with PGP 2.6.x.
        /// </summary>
        /// <param name="UseOldFormat">If true, uses old format.</param>
        public PgpLiteralDataGenerator(Boolean UseOldFormat = false)
        {
            this.UseOldFormat = UseOldFormat;
        }

        #endregion


        #region (private) WriteHeader(Format, NameByteArray, ModificationTime, BCPGOutputStream)

        private void WriteHeader(Char              Format,
                                 Byte[]            NameByteArray,
                                 UInt64            ModificationTime,
                                 BcpgOutputStream  BCPGOutputStream)
        {

            BCPGOutputStream.Write((byte) Format,
                                   (byte) NameByteArray.Length);

            BCPGOutputStream.Write(NameByteArray);

            var modDate = ModificationTime / 1000L;

            BCPGOutputStream.Write((byte) (modDate >> 24),
                                   (byte) (modDate >> 16),
                                   (byte) (modDate >>  8),
                                   (byte)  modDate);
        }

        #endregion

        #region Open(Format, Name, Length, ModificationTime, OutputStream)

        /// <summary>
        /// Open a literal data packet, returning a stream to store the data inside the packet.
        /// 
        /// The stream created can be closed off by either calling Close()
        /// on the stream or Close() on the generator. Closing the returned
        /// stream does not close off the Stream parameter <c>outStr</c>.
        /// </summary>
        /// <param name="OutputStream">The stream we want the packet in.</param>
        /// <param name="Format">The format we are using.</param>
        /// <param name="Name">The name of the 'file'.</param>
        /// <param name="Length">The length of the data we will write.</param>
        /// <param name="ModificationTime">The time of last modification we want stored.</param>
        public Stream Open(Char      Format,
                           String    Name,
                           UInt64    Length,
                           DateTime  ModificationTime,
                           Stream    OutputStream)
        {

            #region Initial checks

            if (pkOut != null)
                throw new InvalidOperationException("generator already in open state");

            if (OutputStream == null)
                throw new ArgumentNullException("The output stream must not be null!");

            #endregion

            var UTF8Name  = Encoding.UTF8.GetBytes(Name);

            pkOut = new BcpgOutputStream(OutputStream,
                                         PacketTag.LiteralData,
                                         Length + 2 + (UInt64) UTF8Name.Length + 4,
                                         UseOldFormat);

            WriteHeader(Format, UTF8Name, DateTimeUtilities.DateTimeToUnixMs(ModificationTime), pkOut);

            return new WrappedGeneratorStream(this, pkOut);

        }

        #endregion

        #region Open(Format, Name, ModificationTime, OutputStream, Buffer)

        /// <summary>
        /// <p>
        /// Open a literal data packet, returning a stream to store the data inside the packet,
        /// as an indefinite length stream. The stream is written out as a series of partial
        /// packets with a chunk size determined by the size of the passed in buffer.
        /// </p>
        /// <p>
        /// The stream created can be closed off by either calling Close()
        /// on the stream or Close() on the generator. Closing the returned
        /// stream does not close off the Stream parameter <c>outStr</c>.
        /// </p>
        /// <p>
        /// <b>Note</b>: if the buffer is not a power of 2 in length only the largest power of 2
        /// bytes worth of the buffer will be used.</p>
        /// </summary>
        /// <param name="Format">The format we are using.</param>
        /// <param name="Name">The name of the 'file'.</param>
        /// <param name="ModificationTime">The time of last modification we want stored.</param>
        /// <param name="OutputStream">The stream we want the packet in.</param>
        /// <param name="Buffer">The buffer to use for collecting data to put into chunks.</param>
        public Stream Open(Char      Format,
                           String    Name,
                           DateTime  ModificationTime,
                           Stream    OutputStream,
                           Byte[]    Buffer)
        {

            #region Initial checks

            if (pkOut != null)
                throw new InvalidOperationException("generator already in open state");

            if (OutputStream == null)
                throw new ArgumentNullException("The output stream must not be null!");

            #endregion

            pkOut = new BcpgOutputStream(OutputStream, PacketTag.LiteralData, Buffer);

            WriteHeader(Format, Encoding.UTF8.GetBytes(Name), DateTimeUtilities.DateTimeToUnixMs(ModificationTime), pkOut);

            return new WrappedGeneratorStream(this, pkOut);

        }

        #endregion

        #region Open(FileIn, Format, OutputStream)

        /// <summary>
        /// Open a literal data packet for the passed in <c>FileInfo</c> object, returning
        /// an output stream for saving the file contents.
        /// The stream created can be closed off by either calling Close()
        /// on the stream or Close() on the generator. Closing the returned
        /// stream does not close off the Stream parameter <c>outStr</c>.
        /// </summary>
        /// <param name="FileIn">The <c>FileInfo</c> object containg the packet details.</param>
        /// <param name="Format">The format we are using.</param>
        /// <param name="OutputStream">The stream we want the packet in.</param>
        public Stream Open(FileInfo  FileIn,
                           Char      Format,
                           Stream    OutputStream)
        {
            return Open(Format, FileIn.Name, (UInt64) FileIn.Length, FileIn.LastWriteTime, OutputStream);
        }

        #endregion


        #region Close()

        /// <summary>
        /// Close the literal data packet - this is equivalent to calling Close()
        /// on the stream returned by the Open() method.
        /// </summary>
        public void Close()
        {
            if (pkOut != null)
            {
                pkOut.Finish();
                pkOut.Flush();
                pkOut = null;
            }
        }

        #endregion

    }

}
