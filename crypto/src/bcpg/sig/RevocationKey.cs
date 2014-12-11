using System;
using System.Text;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>
    /// Represents revocation key OpenPGP signature sub packet.
    /// </summary>
    public class RevocationKey
		: SignatureSubpacket
    {
		// 1 octet of class, 
		// 1 octet of public-key algorithm ID, 
		// 20 octets of fingerprint
		public RevocationKey(
			bool	isCritical,
			byte[]	data)
			: base(SignatureSubpackets.RevocationKey, isCritical, data)
		{
		}

		public RevocationKey(
			bool					isCritical,
			RevocationKeyTag		signatureClass,
			PublicKeyAlgorithms	keyAlgorithm,
			byte[]					fingerprint)
			: base(SignatureSubpackets.RevocationKey, isCritical,
				CreateData(signatureClass, keyAlgorithm, fingerprint))
		{
		}

		private static byte[] CreateData(
			RevocationKeyTag		signatureClass,
			PublicKeyAlgorithms	keyAlgorithm,
			byte[]					fingerprint)
		{
			byte[] data = new byte[2 + fingerprint.Length];
			data[0] = (byte)signatureClass;
			data[1] = (byte)keyAlgorithm;
			Array.Copy(fingerprint, 0, data, 2, fingerprint.Length);
			return data;
		}

		public virtual RevocationKeyTag SignatureClass
		{
			get { return (RevocationKeyTag)this.GetData()[0]; }
		}

		public virtual PublicKeyAlgorithms Algorithm
		{
			get { return (PublicKeyAlgorithms)this.GetData()[1]; }
		}

        public virtual byte[] GetFingerprint()
		{
			byte[] data = this.GetData();
			byte[] fingerprint = new byte[data.Length - 2];
			Array.Copy(data, 2, fingerprint, 0, fingerprint.Length);
			return fingerprint;
		}
    }
}
