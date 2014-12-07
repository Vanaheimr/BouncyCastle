using System;

namespace Org.BouncyCastle.Bcpg.Sig
{

    /**
    * packet giving signature creation time.
    */
    public class IssuerKeyId : SignatureSubpacket
    {

        protected static byte[] KeyIdToBytes(UInt64 keyId)
        {

            var data = new byte[8];

            data[0] = (byte) (keyId >> 56);
            data[1] = (byte) (keyId >> 48);
            data[2] = (byte) (keyId >> 40);
            data[3] = (byte) (keyId >> 32);
            data[4] = (byte) (keyId >> 24);
            data[5] = (byte) (keyId >> 16);
            data[6] = (byte) (keyId >> 8);
            data[7] = (byte) keyId;

            return data;

        }

        public IssuerKeyId(Boolean  critical,
                           Byte[]   data)
            : base(SignatureSubpacketTag.IssuerKeyId, critical, data)
        { }

        public IssuerKeyId(Boolean  critical,
                           UInt64   keyId)
            : base(SignatureSubpacketTag.IssuerKeyId, critical, KeyIdToBytes(keyId))
        { }

        public UInt64 KeyId
        {
            get
            {
                return ((UInt64) (data[0] & 0xff) << 56)
                     | ((UInt64) (data[1] & 0xff) << 48)
                     | ((UInt64) (data[2] & 0xff) << 40)
                     | ((UInt64) (data[3] & 0xff) << 32)
                     | ((UInt64) (data[4] & 0xff) << 24)
                     | ((UInt64) (data[5] & 0xff) << 16)
                     | ((UInt64) (data[6] & 0xff) << 8)
                     | ((UInt64) data[7] & 0xff);
            }
        }

    }

}
