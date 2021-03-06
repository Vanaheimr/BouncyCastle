using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Basic packet for a PGP secret key.</remarks>
    public class SecretKeyPacket : ContainedPacket //, PublicKeyAlgorithmTag
    {

        #region Data

        public const Int32 UsageNone      = 0x00;
        public const Int32 UsageChecksum  = 0xff;
        public const Int32 UsageSha1      = 0xfe;

        private PublicKeyPacket           pubKeyPacket;
        private readonly Byte[]           secKeyData;
        private Int32                     s2kUsage;
        private SymmetricKeyAlgorithms  encAlgorithm;
        private S2k                       s2k;
        private Byte[]                    iv;

        #endregion

        #region Constructor(s)

        internal SecretKeyPacket(BcpgInputStream bcpgIn)
        {

            if (this is SecretSubkeyPacket)
            {
                pubKeyPacket = new PublicSubkeyPacket(bcpgIn);
            }
            else
            {
                pubKeyPacket = new PublicKeyPacket(bcpgIn);
            }

            s2kUsage = bcpgIn.ReadByte();

            if (s2kUsage == UsageChecksum || s2kUsage == UsageSha1)
            {
                encAlgorithm = (SymmetricKeyAlgorithms) bcpgIn.ReadByte();
                s2k = new S2k(bcpgIn);
            }
            else
            {
                encAlgorithm = (SymmetricKeyAlgorithms) s2kUsage;
            }

            if (!(s2k != null && s2k.Type == S2k.GnuDummyS2K && s2k.ProtectionMode == 0x01))
            {
                if (s2kUsage != 0)
                {
                    if (((int) encAlgorithm) < 7)
                    {
                        iv = new byte[8];
                    }
                    else
                    {
                        iv = new byte[16];
                    }
                    bcpgIn.ReadFully(iv);
                }
            }

            secKeyData = bcpgIn.ReadAll();
        }

        public SecretKeyPacket(PublicKeyPacket           pubKeyPacket,
                               SymmetricKeyAlgorithms  encAlgorithm,
                               S2k                       s2k,
                               Byte[]                    iv,
                               Byte[]                    secKeyData)

        {

            this.pubKeyPacket = pubKeyPacket;
            this.encAlgorithm = encAlgorithm;

            if (encAlgorithm != SymmetricKeyAlgorithms.Null)
            {
                this.s2kUsage = UsageChecksum;
            }
            else
            {
                this.s2kUsage = UsageNone;
            }

            this.s2k = s2k;
            this.iv = Arrays.Clone(iv);
            this.secKeyData = secKeyData;

        }

        public SecretKeyPacket(PublicKeyPacket           pubKeyPacket,
                               SymmetricKeyAlgorithms  encAlgorithm,
                               Int32                     s2kUsage,
                               S2k                       s2k,
                               Byte[]                    iv,
                               Byte[]                    secKeyData)

        {

            this.pubKeyPacket  = pubKeyPacket;
            this.encAlgorithm  = encAlgorithm;
            this.s2kUsage      = s2kUsage;
            this.s2k           = s2k;
            this.iv            = Arrays.Clone(iv);
            this.secKeyData    = secKeyData;

        }

        #endregion

        public SymmetricKeyAlgorithms EncAlgorithm
        {
            get { return encAlgorithm; }
        }

        public int S2kUsage
        {
            get { return s2kUsage; }
        }

        public byte[] GetIV()
        {
            return Arrays.Clone(iv);
        }

        public S2k S2k
        {
            get { return s2k; }
        }

        public PublicKeyPacket PublicKeyPacket
        {
            get { return pubKeyPacket; }
        }

        public Byte[] GetSecretKeyData()
        {
            return secKeyData;
        }

        public Byte[] GetEncodedContents()
        {

            var bOut  = new MemoryStream();
            var pOut  = new BcpgOutputStream(bOut);

            pOut.Write(pubKeyPacket.GetEncodedContents());
            pOut.WriteByte((byte) s2kUsage);

            if (s2kUsage == UsageChecksum || s2kUsage == UsageSha1)
            {
                pOut.WriteByte((byte) encAlgorithm);
                pOut.WriteObject(s2k);
            }

            if (iv != null)
            {
                pOut.Write(iv);
            }

            if (secKeyData != null && secKeyData.Length > 0)
            {
                pOut.Write(secKeyData);
            }

            return bOut.ToArray();
        }

        public override void Encode(BcpgOutputStream bcpgOut)
        {
            bcpgOut.WritePacket(PacketTag.SecretKey, GetEncodedContents(), true);
        }

    }

}
