using System;
using System.IO;

namespace Org.BouncyCastle.Asn1.Utilities
{

    public class FilterStream : Stream
    {

        #region Data

        protected readonly Stream _Stream;

        #endregion

        #region Properties

        #region CanRead

        public override Boolean CanRead
        {
            get
            {
                return _Stream.CanRead;
            }
        }

        #endregion

        #region CanSeek

        public override Boolean CanSeek
        {
            get
            {
                return _Stream.CanSeek;
            }
        }

        #endregion

        #region CanWrite

        public override Boolean CanWrite
        {
            get
            {
                return _Stream.CanWrite;
            }
        }

        #endregion

        #region Length

        public override Int64 Length
        {
            get
            {
                return _Stream.Length;
            }
        }

        #endregion

        #region Position

        public override Int64 Position
        {

            get
            {
                return _Stream.Position;
            }

            set
            {
                _Stream.Position = value;
            }

        }

        #endregion

        #endregion

        #region Constructor(s)

        public FilterStream(Stream InputStream)
        {
            this._Stream = InputStream;
        }

        #endregion


        public override long Seek(long offset, SeekOrigin origin)
        {
            return _Stream.Seek(offset, origin);
        }

        public override void SetLength(long value)
        {
            _Stream.SetLength(value);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return _Stream.Read(buffer, offset, count);
        }

        public override int ReadByte()
        {
            return _Stream.ReadByte();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            _Stream.Write(buffer, offset, count);
        }

        public override void WriteByte(byte value)
        {
            _Stream.WriteByte(value);
        }


        #region Flush()

        public override void Flush()
        {
            _Stream.Flush();
        }

        #endregion

        #region Close()

        public override void Close()
        {
            _Stream.Close();
        }

        #endregion

    }

}
