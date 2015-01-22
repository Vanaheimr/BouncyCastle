using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Collections;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{

    /// <summary>
    /// Reader for Base64 armored objects - read the headers and then start returning
    /// bytes when the data is reached. An IOException is thrown if the CRC check
    /// fails.
    /// </summary>
    public class ArmoredInputStream : BaseInputStream
    {

        #region Data

        private readonly static Byte[] decodingTable;

        Stream        InputStream;
        Boolean       _Start        = true;
        Int32[]       outBuf        = new Int32[3];
        Int32         bufPtr        = 3;
        Crc24         crc           = new Crc24();
        Boolean       crcFound      = false;
        Boolean       HasHeaders    = true;
        String        header        = null;
        Boolean       NewLineFound  = false;
        Boolean       clearText     = false;
        Boolean       restart       = false;
        List<String>  HeaderList;
        Int32         lastC         = 0;
        Boolean       isEndOfStream;

        #endregion

        #region Properties

        #region IsClearText

        /// <summary>
        /// True if we are inside the clear text section of a PGP signed message.
        /// </summary>
        public Boolean IsClearText
        {
            get
            {
                return clearText;
            }
        }

        #endregion

        #region IsEndOfStream

        /// <summary>
        /// True if the stream is actually at end of file.
        /// </summary>
        public Boolean IsEndOfStream
        {
            get
            {
                return isEndOfStream;
            }
        }

        #endregion

        #region ArmorHeaderLine

        /// <summary>
        /// Return the armor header line (if there is one)
        /// </summary>
        public String ArmorHeaderLine
        {
            get
            {
                return header;
            }
        }

        #endregion

        #region ArmorHeaders

        /// <summary>
        /// Return the armor headers (the lines after the armor header line)
        /// </summary>
        public IEnumerable<String> ArmorHeaders
        {
            get
            {
                return HeaderList.Skip(1);
            }
        }

        #endregion

        #endregion

        #region Constructor(s)

        #region (static) ArmoredInputStream()

        static ArmoredInputStream()
        {

            decodingTable = new byte[128];

            for (int i = 'A'; i <= 'Z'; i++)
                decodingTable[i] = (byte) (i - 'A');

            for (int i = 'a'; i <= 'z'; i++)
                decodingTable[i] = (byte) (i - 'a' + 26);

            for (int i = '0'; i <= '9'; i++)
                decodingTable[i] = (byte) (i - '0' + 52);

            decodingTable['+'] = 62;
            decodingTable['/'] = 63;

        }

        #endregion

        #region ArmoredInputStream(InputStream)

        /// <summary>
        /// Create a stream for reading a PGP armoured message, parsing up to a header
        /// and then reading the data that follows.
        /// </summary>
        /// <param name="InputStream">The input stream.</param>
        public ArmoredInputStream(Stream InputStream)
            : this(InputStream, true)
        { }

        #endregion

        #region ArmoredInputStream(InputStream, HasHeaders)

        /// <summary>
        /// Create an armoured input stream which will assume the data starts
        /// straight away, or parse for headers first depending on the value of
        /// hasHeaders.
        /// </summary>
        /// <param name="InputStream">The input stream.</param>
        /// <param name="HasHeaders">True if headers are to be looked for, false otherwise.</param>
        public ArmoredInputStream(Stream   InputStream,
                                  Boolean  HasHeaders)
        {

            this.InputStream  = InputStream;
            this.HasHeaders   = HasHeaders;
            this.HeaderList   = new List<String>();

            if (HasHeaders)
                ParseHeaders();

            _Start            = false;

        }

        #endregion

        #endregion


        #region Decode(in0, in1, in2, in3, result)

        /// <summary>
        /// Decode the base 64 encoded input data.
        /// </summary>
        /// <param name="in0"></param>
        /// <param name="in1"></param>
        /// <param name="in2"></param>
        /// <param name="in3"></param>
        /// <param name="result"></param>
        /// <returns>The offset the data starts in out.</returns>
        private Int32 Decode(Int32    in0,
                             Int32    in1,
                             Int32    in2,
                             Int32    in3,
                             Int32[]  result)
        {

            if (in3 < 0)
                throw new EndOfStreamException("unexpected end of file in armored stream.");

            Int32 b1, b2, b3, b4;

            if (in2 == '=')
            {

                b1 = decodingTable[in0] &0xff;
                b2 = decodingTable[in1] & 0xff;
                result[2] = ((b1 << 2) | (b2 >> 4)) & 0xff;

                return 2;

            }

            else if (in3 == '=')
            {

                b1 = decodingTable[in0];
                b2 = decodingTable[in1];
                b3 = decodingTable[in2];
                result[1] = ((b1 << 2) | (b2 >> 4)) & 0xff;
                result[2] = ((b2 << 4) | (b3 >> 2)) & 0xff;

                return 1;

            }

            else
            {

                b1 = decodingTable[in0];
                b2 = decodingTable[in1];
                b3 = decodingTable[in2];
                b4 = decodingTable[in3];
                result[0] = ((b1 << 2) | (b2 >> 4)) & 0xff;
                result[1] = ((b2 << 4) | (b3 >> 2)) & 0xff;
                result[2] = ((b3 << 6) | b4) & 0xff;

                return 0;

            }

        }

        #endregion

        #region ParseHeaders()

        private Boolean ParseHeaders()
        {

            header = null;

            var c            = 0;
            var last         = 0;
            var headerFound  = false;

            // if restart we already have a header
            if (restart)
                headerFound = true;

            else
            {
                while ((c = InputStream.ReadByte()) >= 0)
                {
                    if (c == '-' && (last == 0 || last == '\n' || last == '\r'))
                    {
                        headerFound = true;
                        break;
                    }

                    last = c;
                }
            }

            if (headerFound)
            {
                StringBuilder    Buffer = new StringBuilder("-");
                bool             eolReached = false;
                bool             crLf = false;

                if (restart)    // we've had to look ahead two '-'
                {
                    Buffer.Append('-');
                }

                while ((c = InputStream.ReadByte()) >= 0)
                {

                    if (last == '\r' && c == '\n')
                        crLf = true;

                    if (eolReached && (last != '\r' && c == '\n'))
                        break;

                    if (eolReached && c == '\r')
                        break;

                    if (c == '\r' || (last != '\r' && c == '\n'))
                    {
                        var line = Buffer.ToString();
                        if (line.Trim().Length < 1)
                            break;
                        HeaderList.Add(line);
                        Buffer.Length = 0;
                    }

                    if (c != '\n' && c != '\r')
                    {
                        Buffer.Append((char)c);
                        eolReached = false;
                    }
                    else
                    {
                        if (c == '\r' || (last != '\r' && c == '\n'))
                            eolReached = true;
                    }

                    last = c;

                }

                if (crLf)
                    InputStream.ReadByte(); // skip last \n

            }

            if (HeaderList.Count > 0)
                header = HeaderList[0];

            clearText = "-----BEGIN PGP SIGNED MESSAGE-----".Equals(header);
            NewLineFound = true;

            return headerFound;

        }

        #endregion


        #region (private) ReadIgnoreSpace()

        private Int32 ReadIgnoreSpace()
        {

            int c;

            do
            {
                c = InputStream.ReadByte();
            }
            while (c == ' ' || c == '\t');

            return c;

        }

        #endregion

        #region (private) ReadIgnoreWhitespace()

        private Int32 ReadIgnoreWhitespace()
        {

            int c;

            do
            {
                c = InputStream.ReadByte();
            }
            while (c == ' ' || c == '\t' || c == '\r' || c == '\n');

            return c;

        }

        #endregion

        #region (private) ReadByteClearText()

        private Int32 ReadByteClearText()
        {

            int c = InputStream.ReadByte();

            if (c == '\r' || (c == '\n' && lastC != '\r'))
                NewLineFound = true;

            else if (NewLineFound && c == '-')
            {

                c = InputStream.ReadByte();

                if (c == '-')            // a header, not dash escaped
                {
                    clearText = false;
                    _Start    = true;
                    restart   = true;
                }
                else                   // a space - must be a dash escape
                    c = InputStream.ReadByte();

                NewLineFound = false;

            }
            else
            {
                if (c != '\n' && lastC != '\r')
                    NewLineFound = false;
            }

            lastC = c;

            if (c < 0)
                isEndOfStream = true;

            return c;

        }

        #endregion

        #region (private) ReadClearText(buffer, offset, count)

        private Int32 ReadClearText(Byte[] buffer, Int32 offset, Int32 count)
        {

            var pos = offset;

            try
            {

                var end = offset + count;

                while (pos < end)
                {

                    var c = ReadByteClearText();
                    if (c == -1)
                        break;

                    buffer[pos++] = (byte) c;

                }

            }
            catch (IOException ioe)
            {
                if (pos == offset) throw ioe;
            }

            return pos - offset;

        }

        #endregion

        #region (private) DoReadByte()

        private Int32 DoReadByte()
        {

            if (bufPtr > 2 || crcFound)
            {

                var c = ReadIgnoreSpace();

                if (c == '\n' || c == '\r')
                {

                    c = ReadIgnoreWhitespace();

                    if (c == '=')            // crc reached
                    {

                        bufPtr = Decode(ReadIgnoreSpace(), ReadIgnoreSpace(), ReadIgnoreSpace(), ReadIgnoreSpace(), outBuf);

                        if (bufPtr != 0)
                            throw new IOException("no crc found in armored message.");

                        crcFound = true;

                        int i = ((outBuf[0] & 0xff) << 16) |
                                ((outBuf[1] & 0xff) <<  8) |
                                 (outBuf[2] & 0xff);

                        if (i != crc.Value)
                            throw new IOException("crc check failed in armored message.");

                        return ReadByte();

                    }

                    if (c == '-')        // end of record reached
                    {

                        while ((c = InputStream.ReadByte()) >= 0)
                        {
                            if (c == '\n' || c == '\r')
                                break;
                        }

                        if (!crcFound)
                            throw new IOException("crc check not found.");

                        crcFound  = false;
                        _Start    = true;
                        bufPtr    = 3;

                        if (c < 0)
                            isEndOfStream = true;

                        return -1;

                    }

                }

                if (c < 0)
                {
                    isEndOfStream = true;
                    return -1;
                }

                bufPtr = Decode(c, ReadIgnoreSpace(), ReadIgnoreSpace(), ReadIgnoreSpace(), outBuf);
            }

            return outBuf[bufPtr++];

        }

        #endregion


        #region ReadByte()

        public override Int32 ReadByte()
        {

            if (_Start)
            {

                if (HasHeaders)
                    ParseHeaders();

                crc.Reset();

                _Start     = false;
                clearText  = false;

            }

            if (clearText)
                return ReadByteClearText();

            var c = DoReadByte();

            crc.Update(c);

            return c;

        }

        #endregion

        #region Read(Buffer, Offset, Count)

        public override Int32 Read(Byte[] Buffer, Int32 Offset, Int32 Count)
        {

            if (_Start && Count > 0)
            {

                if (HasHeaders)
                    ParseHeaders();

                _Start = false;

            }

            if (clearText)
                return ReadClearText(Buffer, Offset, Count);

            var pos = Offset;

            try
            {

                var end = Offset + Count;

                while (pos < end)
                {

                    var c = DoReadByte();
                    crc.Update(c);

                    if (c == -1)
                        break;

                    Buffer[pos++] = (byte) c;

                }

            }
            catch (IOException ioe)
            {
                if (pos == Offset) throw ioe;
            }

            return pos - Offset;

        }

        #endregion

        #region Close()

        public override void Close()
        {
            InputStream.Close();
            base.Close();
        }

        #endregion

    }

}
