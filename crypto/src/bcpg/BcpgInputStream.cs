using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{

    /// <summary>
    /// Reader for PGP objects.
    /// </summary>
    public class BcpgInputStream : BaseInputStream
    {

        #region (private, class) PartialInputStream

        /// <summary>
        /// A stream that overlays our input stream, allowing the user to only read a segment of it.
        /// NB: dataLength will be negative if the segment length is in the upper range above 2**31.
        /// </summary>
        private class PartialInputStream : BaseInputStream
        {

            #region Data

            private readonly BcpgInputStream  BCPGInputStream;
            private          Boolean          Partial;
            private          UInt64           DataLength;

            #endregion

            #region (internal) Constructor(s)

            internal PartialInputStream(BcpgInputStream  BCPGInputStream,
                                        Boolean          Partial,
                                        UInt64           DataLength)
            {

                this.BCPGInputStream  = BCPGInputStream;
                this.Partial          = Partial;
                this.DataLength       = DataLength;

            }

            #endregion


            #region ReadByte()

            public override Int32 ReadByte()
            {

                do
                {
                    if (DataLength != 0)
                    {

                        var ch = BCPGInputStream.ReadByte();
                        if (ch < 0)
                            throw new EndOfStreamException("Premature end of stream in PartialInputStream");

                        DataLength--;

                        return ch;

                    }
                }
                while (Partial && ReadPartialDataLength() >= 0);

                return -1;

            }

            #endregion

            #region Read(Buffer, Offset, Count)

            public override Int32 Read(Byte[] Buffer, Int32 Offset, Int32 Count)
            {

                do
                {
                    if (DataLength != 0)
                    {

                        var readLen  = ((Int32) DataLength > Count || (Int32) DataLength < 0) ? Count : (Int32) DataLength;
                        var len      = BCPGInputStream.Read(Buffer, Offset, readLen);
                        if (len < 1)
                            throw new EndOfStreamException("Premature end of stream in PartialInputStream");

                        DataLength -= (UInt64) len;
                        return len;

                    }
                }
                while (Partial && ReadPartialDataLength() >= 0);

                return 0;

            }

            #endregion

            #region ReadPartialDataLength()

            private Int32 ReadPartialDataLength()
            {

                var l = BCPGInputStream.ReadByte();

                if (l < 0)
                    return -1;

                Partial = false;

                if (l < 192)
                    DataLength  = (UInt64) l;

                else if (l <= 223)
                    DataLength  = (UInt64) (((l - 192) << 8) + (BCPGInputStream.ReadByte()) + 192);

                else if (l == 255)
                    DataLength  = (UInt64) ((BCPGInputStream.ReadByte() << 24) |
                                            (BCPGInputStream.ReadByte() << 16) |
                                            (BCPGInputStream.ReadByte() <<  8) |
                                             BCPGInputStream.ReadByte());

                else
                {
                    Partial     = true;
                    DataLength  = (UInt64) (1 << (l & 0x1f));
                }

                return 0;

            }

            #endregion

        }

        #endregion

        #region Data

        private readonly Stream   InputStream;
        private          Boolean  next = false;
        private          Int32    nextB;

        #endregion

        #region (internal) Constructor(s)

        private BcpgInputStream(Stream InputStream)
        {
            this.InputStream = InputStream;
        }

        #endregion


        #region (internal, static) Wrap(InputStream)

        internal static BcpgInputStream Wrap(Stream InputStream)
        {

            if (InputStream is BcpgInputStream)
                return (BcpgInputStream) InputStream;

            return new BcpgInputStream(InputStream);

        }

        #endregion


        #region ReadByte()

        public override Int32 ReadByte()
        {

            if (next)
            {
                next = false;
                return nextB;
            }

            return InputStream.ReadByte();

        }

        #endregion

        #region Read(Buffer, Offset, Count)

        public override Int32 Read(Byte[]  Buffer,
                                   Int32   Offset,
                                   Int32   Count)
        {

            // Strangely, when count == 0, we should still attempt to read a byte
//            if (count == 0)
//                return 0;

            if (!next)
                return InputStream.Read(Buffer, Offset, Count);

            // We have next byte waiting, so return it

            if (nextB < 0)
                return 0; // EndOfStream

            if (Buffer == null)
                throw new ArgumentNullException("buffer");

            Buffer[Offset] = (byte) nextB;
            next = false;

            return 1;

        }

        #endregion

        #region ReadAll()

        public Byte[] ReadAll()
        {
            return Streams.ReadAll(this);
        }

        #endregion

        #region ReadFully(Buffer, Offset, Length)

        public void ReadFully(Byte[]  Buffer,
                              Int32   Offset,
                              Int32   Length)
        {
            if (Streams.ReadFully(this, Buffer, Offset, Length) < Length)
                throw new EndOfStreamException();
        }

        #endregion

        #region ReadFully(buffer)

        public void ReadFully(Byte[] buffer)
        {
            ReadFully(buffer, 0, buffer.Length);
        }

        #endregion

        #region NextPacketTag()

        /// <summary>
        /// Returns the next packet tag in the stream.
        /// </summary>
        public PacketTag NextPacketTag()
        {

            if (!next)
            {

                try
                {
                    nextB = InputStream.ReadByte();
                }
                catch (EndOfStreamException)
                {
                    nextB = -1;
                }

                next = true;

            }

            if (nextB >= 0)
            {

                // new
                if ((nextB & 0x40) != 0)
                    return (PacketTag) (nextB & 0x3f);

                // old
                else
                    return (PacketTag) ((nextB & 0x3f) >> 2);

            }

            return (PacketTag) nextB;

        }

        #endregion

        #region ReadPacket<T>()

        public T ReadPacket<T>()
            where T : Packet
        {
            return ReadPacket() as T;
        }

        #endregion

        #region ReadPacket()

        public Packet ReadPacket()
        {

            var hdr = this.ReadByte();

            if (hdr < 0)
                return null;

            if ((hdr & 0x80) == 0)
                throw new IOException("invalid header encountered");

            bool newPacket = (hdr & 0x40) != 0;
            PacketTag tag = 0;
            int bodyLen = 0;
            bool partial = false;

            if (newPacket)
            {
                tag = (PacketTag)(hdr & 0x3f);

                int l = this.ReadByte();

                if (l < 192)
                {
                    bodyLen = l;
                }
                else if (l <= 223)
                {
                    int b = InputStream.ReadByte();
                    bodyLen = ((l - 192) << 8) + (b) + 192;
                }
                else if (l == 255)
                {
                    bodyLen = (InputStream.ReadByte() << 24) | (InputStream.ReadByte() << 16)
                        |  (InputStream.ReadByte() << 8)  | InputStream.ReadByte();
                }
                else
                {
                    partial = true;
                    bodyLen = 1 << (l & 0x1f);
                }
            }
            else
            {
                int lengthType = hdr & 0x3;

                tag = (PacketTag)((hdr & 0x3f) >> 2);

                switch (lengthType)
                {
                    case 0:
                        bodyLen = this.ReadByte();
                        break;
                    case 1:
                        bodyLen = (this.ReadByte() << 8) | this.ReadByte();
                        break;
                    case 2:
                        bodyLen = (this.ReadByte() << 24) | (this.ReadByte() << 16)
                            | (this.ReadByte() << 8) | this.ReadByte();
                        break;
                    case 3:
                        partial = true;
                        break;
                    default:
                        throw new IOException("unknown length type encountered");
                }
            }

            BcpgInputStream objStream;

            if (bodyLen == 0 && partial)
                objStream = this;

            else
            {
                var pis = new PartialInputStream(this, partial, (UInt64) bodyLen);
                objStream = new BcpgInputStream(pis);
            }

            switch (tag)
            {
                case PacketTag.Reserved:
                    return new InputStreamPacket(objStream);
                case PacketTag.PublicKeyEncryptedSession:
                    return new PublicKeyEncSessionPacket(objStream);
                case PacketTag.Signature:
                    return new SignaturePacket(objStream);
                case PacketTag.SymmetricKeyEncryptedSessionKey:
                    return new SymmetricKeyEncSessionPacket(objStream);
                case PacketTag.OnePassSignature:
                    return new OnePassSignaturePacket(objStream);
                case PacketTag.SecretKey:
                    return new SecretKeyPacket(objStream);
                case PacketTag.PublicKey:
                    return new PublicKeyPacket(objStream);
                case PacketTag.SecretSubkey:
                    return new SecretSubkeyPacket(objStream);
                case PacketTag.CompressedData:
                    return new CompressedDataPacket(objStream);
                case PacketTag.SymmetricKeyEncrypted:
                    return new SymmetricEncDataPacket(objStream);
                case PacketTag.Marker:
                    return new MarkerPacket(objStream);
                case PacketTag.LiteralData:
                    return new LiteralDataPacket(objStream);
                case PacketTag.Trust:
                    return new TrustPacket(objStream);
                case PacketTag.UserId:
                    return new UserIdPacket(objStream);
                case PacketTag.UserAttribute:
                    return new UserAttributePacket(objStream);
                case PacketTag.PublicSubkey:
                    return new PublicSubkeyPacket(objStream);
                case PacketTag.SymmetricEncryptedIntegrityProtected:
                    return new SymmetricEncIntegrityPacket(objStream);
                case PacketTag.ModificationDetectionCode:
                    return new ModDetectionCodePacket(objStream);
                case PacketTag.Experimental1:
                case PacketTag.Experimental2:
                case PacketTag.Experimental3:
                case PacketTag.Experimental4:
                    return new ExperimentalPacket(tag, objStream);
                default:
                    throw new IOException("unknown packet type encountered: " + tag);
            }
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
