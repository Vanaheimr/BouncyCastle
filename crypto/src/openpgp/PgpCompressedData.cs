using System.IO;

using Org.BouncyCastle.Apache.Bzip2;
using Org.BouncyCastle.Utilities.Zlib;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    /// <summary>
    /// Compressed data objects
    /// </summary>
    public class PgpCompressedData : PgpObject
    {

        private readonly CompressedDataPacket data;

        public PgpCompressedData(BcpgInputStream bcpgInput)
        {
            data = bcpgInput.ReadPacket<CompressedDataPacket>();
        }

        /// <summary>
        /// The algorithm used for compression
        /// </summary>
        public CompressionAlgorithms Algorithm
        {
            get { return data.Algorithm; }
        }

        /// <summary>
        /// Get the raw input stream contained in the object.
        /// </summary>
        public Stream GetInputStream()
        {
            return data.GetInputStream();
        }

        /// <summary>
        /// Return an uncompressed input stream which allows reading of the compressed data.
        /// </summary>
        public Stream GetDataStream()
        {
            switch (Algorithm)
            {

                case CompressionAlgorithms.Uncompressed:
                    return GetInputStream();

                case CompressionAlgorithms.Zip:
                    return new ZInputStream(GetInputStream(), true);

                case CompressionAlgorithms.ZLib:
                    return new ZInputStream(GetInputStream());

                case CompressionAlgorithms.BZip2:
                    return new CBZip2InputStream(GetInputStream());

                default:
                    throw new PgpException("can't recognise compression algorithm: " + Algorithm);

            }
        }

    }
}
