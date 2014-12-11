using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{

    /// <summary>
    /// Basic type for a PGP packet.
    /// </summary>
    public abstract class ContainedPacket : Packet
    {

        public Byte[] GetEncoded()
        {

            var OutputStream         = new MemoryStream();
            var WrappedOutputStream  = new BcpgOutputStream(OutputStream);

            // Calls -> Encode(BcpgOutputStream bcpgOut)
            WrappedOutputStream.WritePacket(this);

            return OutputStream.ToArray();

        }

        public abstract void Encode(BcpgOutputStream bcpgOut);

    }

}
