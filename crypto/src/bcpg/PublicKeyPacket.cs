using System;
using System.IO;

using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Basic packet for a PGP public key.</remarks>
    public class PublicKeyPacket
        : ContainedPacket //, PublicKeyAlgorithmTag
    {
        private int version;
        private long time;
        private int validDays;
        private PublicKeyAlgorithms algorithm;
        private IBcpgKey key;

        internal PublicKeyPacket(
            BcpgInputStream bcpgIn)
        {
            version = bcpgIn.ReadByte();

            time = ((uint)bcpgIn.ReadByte() << 24) | ((uint)bcpgIn.ReadByte() << 16)
                | ((uint)bcpgIn.ReadByte() << 8) | (uint)bcpgIn.ReadByte();

            if (version <= 3)
            {
                validDays = (bcpgIn.ReadByte() << 8) | bcpgIn.ReadByte();
            }

            algorithm = (PublicKeyAlgorithms) bcpgIn.ReadByte();

            switch ((PublicKeyAlgorithms) algorithm)
            {
                case PublicKeyAlgorithms.RsaEncrypt:
                case PublicKeyAlgorithms.RsaGeneral:
                case PublicKeyAlgorithms.RsaSign:
                    key = new RsaPublicBcpgKey(bcpgIn);
                    break;
                case PublicKeyAlgorithms.Dsa:
                    key = new DsaPublicBcpgKey(bcpgIn);
                    break;
                case PublicKeyAlgorithms.ElGamalEncrypt:
                case PublicKeyAlgorithms.ElGamalGeneral:
                    key = new ElGamalPublicBcpgKey(bcpgIn);
                    break;
                default:
                    throw new IOException("unknown PGP public key algorithm encountered");
            }
        }

        /// <summary>Construct a version 4 public key packet.</summary>
        public PublicKeyPacket(
            PublicKeyAlgorithms	algorithm,
            DateTime				time,
            IBcpgKey				key)
        {
            this.version = 4;
            this.time = DateTimeUtilities.DateTimeToUnixMs(time) / 1000L;
            this.algorithm = algorithm;
            this.key = key;
        }

        public virtual int Version
        {
            get { return version; }
        }

        public virtual PublicKeyAlgorithms Algorithm
        {
            get { return algorithm; }
        }

        public virtual int ValidDays
        {
            get { return validDays; }
        }

        public virtual DateTime GetTime()
        {
            return DateTimeUtilities.UnixMsToDateTime(time * 1000L);
        }

        public virtual IBcpgKey Key
        {
            get { return key; }
        }

        public virtual byte[] GetEncodedContents()
        {
            MemoryStream bOut = new MemoryStream();
            BcpgOutputStream pOut = new BcpgOutputStream(bOut);

            pOut.WriteByte((byte) version);
            pOut.WriteInt((int) time);

            if (version <= 3)
            {
                pOut.WriteShort((short) validDays);
            }

            pOut.WriteByte((byte) algorithm);

            pOut.WriteObject((BcpgObject)key);

            return bOut.ToArray();
        }

        public override void Encode(
            BcpgOutputStream bcpgOut)
        {
            bcpgOut.WritePacket(PacketTag.PublicKey, GetEncodedContents(), true);
        }
    }
}
