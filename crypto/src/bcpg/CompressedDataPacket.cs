using System.IO;

namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>Generic compressed data object.</remarks>
    public class CompressedDataPacket
        : InputStreamPacket
    {
        private readonly CompressionAlgorithms algorithm;

		internal CompressedDataPacket(
            BcpgInputStream bcpgIn)
			: base(bcpgIn)
        {
            this.algorithm = (CompressionAlgorithms) bcpgIn.ReadByte();
        }

		/// <summary>The algorithm tag value.</summary>
        public CompressionAlgorithms Algorithm
		{
			get { return algorithm; }
		}
    }
}
