using System;
using System.IO;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{

    /// <summary>
    /// Basic output stream.
    /// </summary>
    public class BcpgOutputStream : BaseOutputStream
    {

        #region Data

        private Stream       outStr;
        private Byte[]       partialBuffer;
        private Int32        partialBufferLength;
        private Int32        partialPower;
        private Int32        partialOffset;
        private const Int32  BufferSizePower = 16; // 2^16 size buffer on long files

        #endregion

        #region Constructor(s)

        #region BcpgOutputStream(OutputStream)

        /// <summary>
        /// Create a stream representing a general packet.
        /// </summary>
        /// <param name="OutputStream">Output stream to write to.</param>
        public BcpgOutputStream(Stream OutputStream)
        {

            if (OutputStream == null)
                throw new ArgumentNullException("OutputStream");

            this.outStr = OutputStream;

        }

        #endregion

        #region BcpgOutputStream(OutputStream, Tag)

        /// <summary>
        /// Create a stream representing an old style partial object.
        /// </summary>
        /// <param name="OutputStream">Output stream to write to.</param>
        /// <param name="Tag">The packet tag for the object.</param>
        public BcpgOutputStream(Stream     OutputStream,
                                PacketTag  Tag)
        {

            if (OutputStream == null)
                throw new ArgumentNullException("OutputStream");

            this.outStr = OutputStream;
            this.WriteHeader(Tag, true, true, 0);

        }

        #endregion

        #region BcpgOutputStream(OutputStream, Tag, Length, UseOldFormat)

        /// <summary>Create a stream representing a general packet.</summary>
        /// <param name="OutputStream">Output stream to write to.</param>
        /// <param name="Tag">Packet tag.</param>
        /// <param name="Length">Size of chunks making up the packet.</param>
        /// <param name="UseOldFormat">If true, the header is written out in old format.</param>
        public BcpgOutputStream(Stream      OutputStream,
                                PacketTag   Tag,
                                UInt64      Length,
                                Boolean     UseOldFormat)
        {

            if (OutputStream == null)
                throw new ArgumentNullException("OutputStream");

            this.outStr = OutputStream;

            if (Length > 0xFFFFFFFFL)
            {
                this.WriteHeader(Tag, false, true, 0);
                this.partialBufferLength    = 1 << BufferSizePower;
                this.partialBuffer          = new byte[partialBufferLength];
                this.partialPower           = BufferSizePower;
                this.partialOffset          = 0;
            }

            else
                this.WriteHeader(Tag, UseOldFormat, false, Length);

        }

        #endregion

        #region BcpgOutputStream(OutputStream, Tag, Length)

        /// <summary>Create a new style partial input stream buffered into chunks.</summary>
        /// <param name="OutputStream">Output stream to write to.</param>
        /// <param name="Tag">Packet tag.</param>
        /// <param name="Length">Size of chunks making up the packet.</param>
        public BcpgOutputStream(Stream     OutputStream,
                                PacketTag  Tag,
                                UInt64     Length)
        {

            if (OutputStream == null)
                throw new ArgumentNullException("OutputStream");

            this.outStr = OutputStream;
            this.WriteHeader(Tag, false, false, Length);

        }

        #endregion

        #region BcpgOutputStream(OutputStream, Tag, Buffer)

        /// <summary>Create a new style partial input stream buffered into chunks.</summary>
        /// <param name="OutputStream">Output stream to write to.</param>
        /// <param name="Tag">Packet tag.</param>
        /// <param name="Buffer">Buffer to use for collecting chunks.</param>
        public BcpgOutputStream(Stream     OutputStream,
                                PacketTag  Tag,
                                Byte[]     Buffer)
        {

            if (OutputStream == null)
                throw new ArgumentNullException("OutputStream");

            this.outStr = OutputStream;
            this.WriteHeader(Tag, false, true, 0);

            this.partialBuffer = Buffer;

            uint length = (uint) partialBuffer.Length;

            for (partialPower = 0; length != 1; partialPower++)
            {
                length >>= 1;
            }

            if (partialPower > 30)
                throw new IOException("Buffer cannot be greater than 2^30 in length.");

            this.partialBufferLength  = 1 << partialPower;
            this.partialOffset        = 0;

        }

        #endregion

        #endregion


        #region (private) WriteNewPacketLength(BodyLength)

        private void WriteNewPacketLength(UInt64 BodyLength)
        {

            if (BodyLength < 192)
                outStr.WriteByte((byte) BodyLength);

            else if (BodyLength <= 8383)
            {
                BodyLength -= 192;
                outStr.WriteByte((byte) (((BodyLength >> 8) & 0xff) + 192));
                outStr.WriteByte((byte)    BodyLength);
            }

            else
            {
                outStr.WriteByte(0xff);
                outStr.WriteByte((byte) (BodyLength >> 24));
                outStr.WriteByte((byte) (BodyLength >> 16));
                outStr.WriteByte((byte) (BodyLength >>  8));
                outStr.WriteByte((byte)  BodyLength);
            }

        }

        #endregion

        #region (private) WriteHeader(Tag, oldPackets, Partial, BodyLength)

        private void WriteHeader(PacketTag  Tag,
                                 Boolean    oldPackets,
                                 Boolean    Partial,
                                 UInt64     BodyLength)
        {

            int hdr = 0x80;

            if (partialBuffer != null)
            {
                PartialFlush(true);
                partialBuffer = null;
            }

            if (oldPackets)
            {

                hdr |= ((int) Tag) << 2;

                if (Partial)
                    this.WriteByte((byte) (hdr | 0x03));

                else
                {

                    if (BodyLength <= 0xff)
                    {
                        this.WriteByte((byte) hdr);
                        this.WriteByte((byte) BodyLength);
                    }

                    else if (BodyLength <= 0xffff)
                    {
                        this.WriteByte((byte) (hdr | 0x01));
                        this.WriteByte((byte) (BodyLength >> 8));
                        this.WriteByte((byte) (BodyLength));
                    }

                    else
                    {
                        this.WriteByte((byte) (hdr | 0x02));
                        this.WriteByte((byte) (BodyLength >> 24));
                        this.WriteByte((byte) (BodyLength >> 16));
                        this.WriteByte((byte) (BodyLength >>  8));
                        this.WriteByte((byte)  BodyLength);
                    }

                }

            }

            else
            {

                hdr |= 0x40 | (int) Tag;
                this.WriteByte((byte) hdr);

                if (Partial)
                    partialOffset = 0;

                else
                    this.WriteNewPacketLength(BodyLength);

            }

        }

        #endregion

        #region (private) PartialFlush(IsLast)

        private void PartialFlush(Boolean IsLast)
        {

            if (IsLast)
            {
                WriteNewPacketLength((UInt64) partialOffset);
                outStr.Write(partialBuffer, 0, partialOffset);
            }

            else
            {
                outStr.WriteByte((byte)(0xE0 | partialPower));
                outStr.Write(partialBuffer, 0, partialBufferLength);
            }

            partialOffset = 0;

        }

        #endregion

        #region (private) WritePartial(ByteValue)

        private void WritePartial(Byte ByteValue)
        {

            if (partialOffset == partialBufferLength)
                PartialFlush(false);

            partialBuffer[partialOffset++] = ByteValue;

        }

        #endregion

        #region (private) WritePartial(Buffer, OFfset, Length)

        private void WritePartial(Byte[]  Buffer,
                                  Int32   Offset,
                                  Int32   Length)
        {

            if (partialOffset == partialBufferLength)
                PartialFlush(false);

            if (Length <= (partialBufferLength - partialOffset))
            {
                Array.Copy(Buffer, Offset, partialBuffer, partialOffset, Length);
                partialOffset += Length;
            }

            else
            {

                var diff = partialBufferLength - partialOffset;
                Array.Copy(Buffer, Offset, partialBuffer, partialOffset, diff);
                Offset += diff;
                Length -= diff;
                PartialFlush(false);

                while (Length > partialBufferLength)
                {
                    Array.Copy(Buffer, Offset, partialBuffer, 0, partialBufferLength);
                    Offset += partialBufferLength;
                    Length -= partialBufferLength;
                    PartialFlush(false);
                }

                Array.Copy(Buffer, Offset, partialBuffer, 0, Length);
                partialOffset += Length;

            }

        }

        #endregion


        #region WriteByte(ByteValue)

        public override void WriteByte(Byte ByteValue)
        {

            if (partialBuffer != null)
                WritePartial(ByteValue);

            else
                outStr.WriteByte(ByteValue);

        }

        #endregion

        #region Write(Buffer, Offset, Length)

        public override void Write(Byte[]  Buffer,
                                   Int32   Offset,
                                   Int32   Length)
        {

            if (partialBuffer != null)
                WritePartial(Buffer, Offset, Length);

            else
                outStr.Write(Buffer, Offset, Length);

        }

        #endregion

        #region (internal) WriteShort(n)

        internal virtual void WriteShort(Int16 n)
        {

            this.Write((byte) (n >> 8),
                       (byte)  n);

        }

        #endregion

        #region (internal) WriteInt(n)

        internal virtual void WriteInt(Int32 n)
        {

            this.Write((byte) (n >> 24),
                       (byte) (n >> 16),
                       (byte) (n >>  8),
                       (byte)  n);

        }

        #endregion

        #region (internal) WriteLong(n)

        internal virtual void WriteLong(long n)
        {

            this.Write((byte) (n >> 56),
                       (byte) (n >> 48),
                       (byte) (n >> 40),
                       (byte) (n >> 32),
                       (byte) (n >> 24),
                       (byte) (n >> 16),
                       (byte) (n >>  8),
                       (byte)  n);

        }

        #endregion

        #region (internal) WriteULong(n)

        internal virtual void WriteULong(UInt64 n)
        {

            this.Write((byte) (n >> 56),
                       (byte) (n >> 48),
                       (byte) (n >> 40),
                       (byte) (n >> 32),
                       (byte) (n >> 24),
                       (byte) (n >> 16),
                       (byte) (n >>  8),
                       (byte)  n);

        }

        #endregion


        #region WritePacket(ContainedPacket)

        public void WritePacket(ContainedPacket ContainedPacket)
        {
            ContainedPacket.Encode(this);
        }

        #endregion

        #region (internal) WritePacket(Tag, Body, UseOldFormat)

        internal void WritePacket(PacketTag  Tag,
                                  Byte[]     Body,
                                  Boolean    UseOldFormat)
        {
            this.WriteHeader(Tag, UseOldFormat, false, (UInt64) Body.Length);
            this.Write(Body);
        }

        #endregion

        #region WriteObject(BCPGObject)

        public void WriteObject(BcpgObject BCPGObject)
        {
            BCPGObject.Encode(this);
        }

        #endregion

        #region WriteObjects(params BCPGObjects)

        public void WriteObjects(params BcpgObject[] BCPGObjects)
        {

            foreach (var BCPGObject in BCPGObjects)
                BCPGObject.Encode(this);

        }

        #endregion


        #region (internal, static) Wrap(OutputStream)

        internal static BcpgOutputStream Wrap(Stream OutputStream)
        {

            if (OutputStream is BcpgOutputStream)
                return OutputStream as BcpgOutputStream;

            return new BcpgOutputStream(OutputStream);

        }

        #endregion


        #region Flush()

        /// <summary>
        /// Flush the underlying stream.
        /// </summary>
        public override void Flush()
        {
            outStr.Flush();
        }

        #endregion

        #region Finish()

        /// <summary>
        /// Finish writing out the current packet without closing the underlying stream.
        /// </summary>
        public void Finish()
        {
            if (partialBuffer != null)
            {
                PartialFlush(true);
                partialBuffer = null;
            }
        }

        #endregion

        #region Close()

        public override void Close()
        {
            this.Finish();
            outStr.Flush();
            outStr.Close();
            base.Close();
        }

        #endregion

    }

}
