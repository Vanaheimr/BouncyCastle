using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Generic signature object</remarks>
    public class OnePassSignaturePacket : ContainedPacket
    {

        private Int32                   version;
        private Int32                   sigType;
        private HashAlgorithmTag        hashAlgorithm;
        private PublicKeyAlgorithmTag   keyAlgorithm;
        private UInt64                  keyId;
        private Int32                   nested;

        internal OnePassSignaturePacket(BcpgInputStream  bcpgIn)
        {

            version        = bcpgIn.ReadByte();
            sigType        = bcpgIn.ReadByte();
            hashAlgorithm  = (HashAlgorithmTag)      bcpgIn.ReadByte();
            keyAlgorithm   = (PublicKeyAlgorithmTag) bcpgIn.ReadByte();

            keyId |= (UInt64) bcpgIn.ReadByte() << 56;
            keyId |= (UInt64) bcpgIn.ReadByte() << 48;
            keyId |= (UInt64) bcpgIn.ReadByte() << 40;
            keyId |= (UInt64) bcpgIn.ReadByte() << 32;
            keyId |= (UInt64) bcpgIn.ReadByte() << 24;
            keyId |= (UInt64) bcpgIn.ReadByte() << 16;
            keyId |= (UInt64) bcpgIn.ReadByte() << 8;
            keyId |= (uint)   bcpgIn.ReadByte();

            nested = bcpgIn.ReadByte();

        }

        public OnePassSignaturePacket(
            int                     sigType,
            HashAlgorithmTag        hashAlgorithm,
            PublicKeyAlgorithmTag   keyAlgorithm,
            UInt64                  keyId,
            bool                    isNested)
        {
            this.version = 3;
            this.sigType = sigType;
            this.hashAlgorithm = hashAlgorithm;
            this.keyAlgorithm = keyAlgorithm;
            this.keyId = keyId;
            this.nested = (isNested) ? 0 : 1;
        }

        public int SignatureType
        {
            get { return sigType; }
        }

        /// <summary>The encryption algorithm tag.</summary>
        public PublicKeyAlgorithmTag KeyAlgorithm
        {
            get { return keyAlgorithm; }
        }

        /// <summary>The hash algorithm tag.</summary>
        public HashAlgorithmTag HashAlgorithm
        {
            get { return hashAlgorithm; }
        }

        public UInt64 KeyId
        {
            get { return keyId; }
        }

        public override void Encode(
            BcpgOutputStream bcpgOut)
        {
            MemoryStream bOut = new MemoryStream();
            BcpgOutputStream pOut = new BcpgOutputStream(bOut);

            pOut.Write(
                (byte) version,
                (byte) sigType,
                (byte) hashAlgorithm,
                (byte) keyAlgorithm);

            pOut.WriteLong((Int64) keyId);

            pOut.WriteByte((byte) nested);

            bcpgOut.WritePacket(PacketTag.OnePassSignature, bOut.ToArray(), true);
        }
    }
}
