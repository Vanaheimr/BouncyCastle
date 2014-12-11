using System;
using System.IO;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Basic packet for a PGP public key.</remarks>
    public class PublicKeyEncSessionPacket
        : ContainedPacket //, PublicKeyAlgorithmTag
    {
        private int version;
        private UInt64 keyId;
        private PublicKeyAlgorithms algorithm;
        private BigInteger[] data;

        internal PublicKeyEncSessionPacket(BcpgInputStream bcpgIn)
        {

            version = bcpgIn.ReadByte();

            keyId |= (UInt64) bcpgIn.ReadByte() << 56;
            keyId |= (UInt64) bcpgIn.ReadByte() << 48;
            keyId |= (UInt64) bcpgIn.ReadByte() << 40;
            keyId |= (UInt64) bcpgIn.ReadByte() << 32;
            keyId |= (UInt64) bcpgIn.ReadByte() << 24;
            keyId |= (UInt64) bcpgIn.ReadByte() << 16;
            keyId |= (UInt64) bcpgIn.ReadByte() << 8;
            keyId |= (uint)   bcpgIn.ReadByte();

            algorithm = (PublicKeyAlgorithms) bcpgIn.ReadByte();

            switch ((PublicKeyAlgorithms) algorithm)
            {
                case PublicKeyAlgorithms.RsaEncrypt:
                case PublicKeyAlgorithms.RsaGeneral:
                    data = new BigInteger[]{ new MPInteger(bcpgIn).Value };
                    break;
                case PublicKeyAlgorithms.ElGamalEncrypt:
                case PublicKeyAlgorithms.ElGamalGeneral:
                    data = new BigInteger[]
                    {
                        new MPInteger(bcpgIn).Value,
                        new MPInteger(bcpgIn).Value
                    };
                    break;
                default:
                    throw new IOException("unknown PGP public key algorithm encountered");
            }

        }

        public PublicKeyEncSessionPacket(
            UInt64                    keyId,
            PublicKeyAlgorithms    algorithm,
            BigInteger[]            data)
        {
            this.version = 3;
            this.keyId = keyId;
            this.algorithm = algorithm;
            this.data = (BigInteger[]) data.Clone();
        }

        public int Version
        {
            get { return version; }
        }

        public UInt64 KeyId
        {
            get { return keyId; }
        }

        public PublicKeyAlgorithms Algorithm
        {
            get { return algorithm; }
        }

        public BigInteger[] GetEncSessionKey()
        {
            return (BigInteger[]) data.Clone();
        }

        public override void Encode(BcpgOutputStream bcpgOut)
        {

            var bOut = new MemoryStream();
            var pOut = new BcpgOutputStream(bOut);

            pOut.WriteByte((byte) version);

            pOut.WriteULong(keyId);

            pOut.WriteByte((byte)algorithm);

            for (int i = 0; i != data.Length; i++)
            {
                MPInteger.Encode(pOut, data[i]);
            }

            bcpgOut.WritePacket(PacketTag.PublicKeyEncryptedSession , bOut.ToArray(), true);

        }

    }

}
