using System;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Reflection;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{

    /// <summary>
    /// Armored output stream.
    /// </summary>
    public class ArmoredOutputStream : BaseOutputStream
    {

        #region Data

        private static readonly Byte[] encodingTable =
        {
            (byte)'A', (byte)'B', (byte)'C', (byte)'D', (byte)'E', (byte)'F', (byte)'G',
            (byte)'H', (byte)'I', (byte)'J', (byte)'K', (byte)'L', (byte)'M', (byte)'N',
            (byte)'O', (byte)'P', (byte)'Q', (byte)'R', (byte)'S', (byte)'T', (byte)'U',
            (byte)'V', (byte)'W', (byte)'X', (byte)'Y', (byte)'Z',
            (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f', (byte)'g',
            (byte)'h', (byte)'i', (byte)'j', (byte)'k', (byte)'l', (byte)'m', (byte)'n',
            (byte)'o', (byte)'p', (byte)'q', (byte)'r', (byte)'s', (byte)'t', (byte)'u',
            (byte)'v', (byte)'w', (byte)'x', (byte)'y', (byte)'z',
            (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6',
            (byte)'7', (byte)'8', (byte)'9',
            (byte)'+', (byte)'/'
        };

        private readonly Stream  OutputStream;
        private Int32[]          buf        = new Int32[3];
        private Int32            bufPtr     = 0;
        private Crc24            crc        = new Crc24();
        private Int32            chunkCount = 0;
        private Int32            lastb;

        private Boolean          start      = true;
        private Boolean          clearText  = false;
        private Boolean          NewLine    = false;

        private String           TypeOfPGPPaket;

        private static readonly String  PGPSignedMessageStart  = "-----BEGIN PGP SIGNED MESSAGE-----";
        private static readonly String  PGPHeaderStart         = "-----BEGIN PGP ";
        private static readonly String  headerTail             = "-----";
        private static readonly String  PGPFooterStart         = "-----END PGP ";
        private static readonly String  footerTail             = "-----";
        private static readonly String  version                = "BCPG C# v" + Assembly.GetExecutingAssembly().GetName().Version;

        private readonly Dictionary<String, String> headers;

        #endregion

        #region Constructor(s)

        #region ArmoredOutputStream(OutputStream)

        public ArmoredOutputStream(Stream OutputStream)
        {
            this.OutputStream        = OutputStream;
            this.headers             = new Dictionary<String, String>();
            this.headers["Version"]  = version;
        }

        #endregion

        #region ArmoredOutputStream(OutputStream, OtherHeaders)

        public ArmoredOutputStream(Stream                       OutputStream,
                                   IDictionary<String, String>  OtherHeaders)

            : this(OutputStream)

        {

            foreach (var kvp in OtherHeaders)
                this.headers.Add(kvp.Key, kvp.Value);

        }

        #endregion

        #endregion


        public void SetHeader(String name,
                              String Value)
        {
            headers[name] = Value;
        }

        /// <summary>
        /// Reset the headers to only contain a Version string.
        /// </summary>
        public void ResetHeaders()
        {
            headers.Clear();
            headers["Version"] = version;
        }

        /**
         * Start a clear text signed message.
         * @param hashAlgorithm
         */
        public void BeginClearText(HashAlgorithms  hashAlgorithm)
        {

            String hash;

            switch (hashAlgorithm)
            {

                case HashAlgorithms.Sha1:
                    hash = "SHA1";
                    break;

                case HashAlgorithms.Sha256:
                    hash = "SHA256";
                    break;

                case HashAlgorithms.Sha384:
                    hash = "SHA384";
                    break;

                case HashAlgorithms.Sha512:
                    hash = "SHA512";
                    break;

                case HashAlgorithms.MD2:
                    hash = "MD2";
                    break;

                case HashAlgorithms.MD5:
                    hash = "MD5";
                    break;

                case HashAlgorithms.RipeMD160:
                    hash = "RIPEMD160";
                    break;

                default:
                    throw new IOException("unknown hash algorithm tag in beginClearText: " + hashAlgorithm);

            }

            WriteLineToOutputStream(PGPSignedMessageStart);
            WriteLineToOutputStream("Hash: " + hash + Environment.NewLine);

            clearText = true;
            NewLine   = true;
            lastb     = 0;

        }

        public void EndClearText()
        {
            clearText = false;
        }







        /// <summary>
        /// encode the input data producing a base 64 encoded byte array.
        /// </summary>
        private static void Encode(Stream   outStream,
                                   Int32[]  data,
                                   Int32    len)
        {

            Debug.Assert(len > 0);
            Debug.Assert(len < 4);

            var bs  = new byte[4];
            var d1  = data[0];
            bs[0]   = encodingTable[(d1 >> 2) & 0x3f];

            switch (len)
            {

                case 1:
                {
                    bs[1] = encodingTable[(d1 << 4) & 0x3f];
                    bs[2] = (byte)'=';
                    bs[3] = (byte)'=';
                    break;
                }

                case 2:
                {
                    var d2 = data[1];
                    bs[1] = encodingTable[((d1 << 4) | (d2 >> 4)) & 0x3f];
                    bs[2] = encodingTable[(d2 << 2) & 0x3f];
                    bs[3] = (byte)'=';
                    break;
                }

                case 3:
                {
                    var d2 = data[1];
                    var d3 = data[2];
                    bs[1] = encodingTable[((d1 << 4) | (d2 >> 4)) & 0x3f];
                    bs[2] = encodingTable[((d2 << 2) | (d3 >> 6)) & 0x3f];
                    bs[3] = encodingTable[d3 & 0x3f];
                    break;
                }

            }

            outStream.Write(bs, 0, bs.Length);

        }








        public override void WriteByte(Byte b)
        {

            if (clearText)
            {

                OutputStream.WriteByte(b);

                if (NewLine)
                {

                    if (!(b == '\n' && lastb == '\r'))
                        NewLine = false;

                    if (b == '-')
                    {
                        OutputStream.WriteByte((byte)' ');
                        OutputStream.WriteByte((byte)'-');      // dash escape
                    }

                }

                if (b == '\r' || (b == '\n' && lastb != '\r'))
                    NewLine = true;

                lastb = b;
                return;

            }

            if (start)
            {

                var isNewPacket = (b & 0x40) != 0;

                int tag;

                if (isNewPacket)
                    tag = b & 0x3f;
                else
                    tag = (b & 0x3f) >> 2;

                switch ((PacketTag)tag)
                {

                    case PacketTag.PublicKey:
                        TypeOfPGPPaket = "PUBLIC KEY BLOCK";
                        break;

                    case PacketTag.SecretKey:
                        TypeOfPGPPaket = "PRIVATE KEY BLOCK";
                        break;

                    case PacketTag.Signature:
                        TypeOfPGPPaket = "SIGNATURE";
                        break;

                    default:
                        TypeOfPGPPaket = "MESSAGE";
                        break;

                }

                WriteLineToOutputStream(PGPHeaderStart + TypeOfPGPPaket + headerTail);
                WriteToOutputStream("Version", headers["Version"]);

                foreach (var kvp in headers.Where(kvp => kvp.Key != "Version"))
                    WriteToOutputStream(kvp.Key, kvp.Value);

                WriteLineToOutputStream();

                start = false;

            }

            if (bufPtr == 3)
            {

                Encode(OutputStream, buf, bufPtr);
                bufPtr = 0;

                if ((++chunkCount & 0xf) == 0)
                    WriteLineToOutputStream();

            }

            crc.Update(b);
            buf[bufPtr++] = b & 0xff;

        }

        /// <summary>
        /// This method does nor close the underlying stream. So it is possible to write
        /// multiple objects using armoring to a single stream.
        /// </summary>
        public override void Close()
        {

            if (TypeOfPGPPaket != null)
            {

                if (bufPtr > 0)
                    Encode(OutputStream, buf, bufPtr);

                WriteToOutputStream(Environment.NewLine + '=');

                var crcV = crc.Value;
                buf[0] = ((crcV >> 16) & 0xff);
                buf[1] = ((crcV >>  8) & 0xff);
                buf[2] = ( crcV        & 0xff);

                Encode(OutputStream, buf, 3);

                WriteLineToOutputStream();
                WriteLineToOutputStream(PGPFooterStart + TypeOfPGPPaket + footerTail);

                OutputStream.Flush();

                TypeOfPGPPaket  = null;
                start = true;
                base.Close();

            }

        }

        private void WriteToOutputStream(String  Key,
                                         String  Value)
        {
            WriteLineToOutputStream(Key + ": " + Value);
        }

        private void WriteLineToOutputStream(String s = "")
        {
            //ToDo: ASCII??? Really???
            var bs = Strings.ToAsciiByteArray(s + Environment.NewLine);
            OutputStream.Write(bs, 0, bs.Length);
        }

        private void WriteToOutputStream(String s)
        {
            //ToDo: ASCII??? Really???
            var bs = Strings.ToAsciiByteArray(s);
            OutputStream.Write(bs, 0, bs.Length);
        }

    }

}
