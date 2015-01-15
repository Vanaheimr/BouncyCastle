using System;

namespace Org.BouncyCastle.Bcpg.Sig
{

    /// <summary>
    /// Packet embedded signature
    /// </summary>
    public class EmbeddedSignature : SignatureSubpacket
    {

        public EmbeddedSignature(Boolean  IsCritical,
                                 Byte[]   Data)

            : base(SignatureSubpackets.EmbeddedSignature, IsCritical, Data)

        { }

    }

}
