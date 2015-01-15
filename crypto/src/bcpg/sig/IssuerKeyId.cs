using System;

namespace Org.BouncyCastle.Bcpg.Sig
{

    /// <summary>
    /// Packet giving signature creation time.
    /// </summary>
    public class IssuerKeyId : SignatureSubpacket
    {

        #region Properties

        #region KeyId

        public UInt64 KeyId
        {
            get
            {

                return ((UInt64) (_Data[0] & 0xff) << 56) |
                       ((UInt64) (_Data[1] & 0xff) << 48) |
                       ((UInt64) (_Data[2] & 0xff) << 40) |
                       ((UInt64) (_Data[3] & 0xff) << 32) |
                       ((UInt64) (_Data[4] & 0xff) << 24) |
                       ((UInt64) (_Data[5] & 0xff) << 16) |
                       ((UInt64) (_Data[6] & 0xff) <<  8) |
                       ((UInt64)  _Data[7] & 0xff);

            }
        }

        #endregion

        #endregion

        #region Constructor(s)

        #region IssuerKeyId(IsCritical, Data)

        public IssuerKeyId(Boolean  IsCritical,
                           Byte[]   Data)

            : base(SignatureSubpackets.IssuerKeyId, IsCritical, Data)

        { }

        #endregion

        #region IssuerKeyId(IsCritical, KeyId)

        public IssuerKeyId(Boolean  IsCritical,
                           UInt64   KeyId)

            : base(SignatureSubpackets.IssuerKeyId, IsCritical, KeyIdToBytes(KeyId))

        { }

        #endregion

        #endregion


        protected static Byte[] KeyIdToBytes(UInt64 keyId)
        {

            return new Byte[] {
                (byte) (keyId >> 56),
                (byte) (keyId >> 48),
                (byte) (keyId >> 40),
                (byte) (keyId >> 32),
                (byte) (keyId >> 24),
                (byte) (keyId >> 16),
                (byte) (keyId >>  8),
                (byte)  keyId
            };

        }

    }

}
