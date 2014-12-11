using System;

namespace Org.BouncyCastle.Bcpg.Sig
{
	/**
	 * Packet embedded signature
	 */
	public class EmbeddedSignature
		: SignatureSubpacket
	{
		public EmbeddedSignature(
			bool	critical,
			byte[]	data)
			: base(SignatureSubpackets.EmbeddedSignature, critical, data)
		{
		}
	}
}
