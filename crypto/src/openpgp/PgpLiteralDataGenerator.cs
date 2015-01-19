using System;
using System.IO;
using System.Text;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    /// <summary>
    /// Class for producing literal data packets.
    /// </summary>
    public class PgpLiteralDataGenerator : IStreamGenerator
    {

        public const char Binary  = PgpLiteralData.Binary;
        public const char Text    = PgpLiteralData.Text;
        public const char Utf8    = PgpLiteralData.Utf8;

        /// <summary>
        /// The special name indicating a "for your eyes only" packet.
        /// </summary>
        public const string Console = PgpLiteralData.Console;

        private BcpgOutputStream pkOut;
        private bool oldFormat;

        public PgpLiteralDataGenerator()
        {
        }

        /// <summary>
        /// Generates literal data objects in the old format.
        /// This is important if you need compatibility with PGP 2.6.x.
        /// </summary>
        /// <param name="oldFormat">If true, uses old format.</param>
        public PgpLiteralDataGenerator(bool oldFormat)
        {
            this.oldFormat = oldFormat;
        }

        #region (private) WriteHeader(OutputStream, Format, NameByteArray, ModificationTime)

        private void WriteHeader(BcpgOutputStream  OutputStream,
                                 Char              Format,
                                 Byte[]            NameByteArray,
                                 UInt64            ModificationTime)
        {

            OutputStream.Write((byte) Format,
                               (byte) NameByteArray.Length);

            OutputStream.Write(NameByteArray);

            var modDate = ModificationTime / 1000L;

            OutputStream.Write((byte) (modDate >> 24),
                               (byte) (modDate >> 16),
                               (byte) (modDate >>  8),
                               (byte)  modDate);
        }

        #endregion

        #region Open(OutputStream, Format, Name, Length, ModificationTime)

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
        public Stream Open(Stream    OutputStream,
                           Char      Format,
                           String    Name,
                           UInt64    Length,
                           DateTime  ModificationTime)
        {

            if (pkOut != null)
                throw new InvalidOperationException("generator already in open state");

            if (OutputStream == null)
                throw new ArgumentNullException("outStr");

            // Do this first, since it might throw an exception
            var unixMs        = DateTimeUtilities.DateTimeToUnixMs(ModificationTime);
            var FileNameUTF8  = Encoding.UTF8.GetBytes(Name);

            pkOut = new BcpgOutputStream(OutputStream,
                                         PacketTag.LiteralData,
                                         Length + 2 + (UInt64) FileNameUTF8.Length + 4,
                                         oldFormat);

            WriteHeader(pkOut, Format, FileNameUTF8, unixMs);

            return new WrappedGeneratorStream(this, pkOut);

        }

        #endregion

        #region Open(OutputStream, Format, Name, ModificationTime, Buffer)

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
        /// <param name="OutputStream">The stream we want the packet in.</param>
        /// <param name="Format">The format we are using.</param>
        /// <param name="Name">The name of the 'file'.</param>
        /// <param name="ModificationTime">The time of last modification we want stored.</param>
        /// <param name="Buffer">The buffer to use for collecting data to put into chunks.</param>
        public Stream Open(Stream    OutputStream,
                           Char      Format,
                           String    Name,
                           DateTime  ModificationTime,
                           Byte[]    Buffer)
        {

            if (pkOut != null)
                throw new InvalidOperationException("generator already in open state");

            if (OutputStream == null)
                throw new ArgumentNullException("outStr");

            // Do this first, since it might throw an exception
            var unixMs  = DateTimeUtilities.DateTimeToUnixMs(ModificationTime);
            var encName = Strings.ToUtf8ByteArray(Name);

            pkOut = new BcpgOutputStream(OutputStream, PacketTag.LiteralData, Buffer);

            WriteHeader(pkOut, Format, encName, unixMs);

            return new WrappedGeneratorStream(this, pkOut);

        }

        #endregion

        #region Open(OutputStream, Format, FileIn)

        /// <summary>
        /// Open a literal data packet for the passed in <c>FileInfo</c> object, returning
        /// an output stream for saving the file contents.
        /// The stream created can be closed off by either calling Close()
        /// on the stream or Close() on the generator. Closing the returned
        /// stream does not close off the Stream parameter <c>outStr</c>.
        /// </summary>
        /// <param name="OutputStream">The stream we want the packet in.</param>
        /// <param name="Format">The format we are using.</param>
        /// <param name="FileIn">The <c>FileInfo</c> object containg the packet details.</param>
        public Stream Open(Stream    OutputStream,
                           Char      Format,
                           FileInfo  FileIn)
        {
            return Open(OutputStream, Format, FileIn.Name, (UInt64) FileIn.Length, FileIn.LastWriteTime);
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
