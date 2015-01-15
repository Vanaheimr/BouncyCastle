using System;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /**
    * packet giving trust.
    */
    public class TrustSignature : SignatureSubpacket
    {

        #region Properties

        #region Depth

        public Int32 Depth
        {
            get
            {
                return _Data[0] & 0xff;
            }
        }

        #endregion

        #region TrustAmount

        public Int32 TrustAmount
        {
            get
            {
                return _Data[1] & 0xff;
            }
        }

        #endregion

        #endregion

        #region Constructor(s)

        #region TrustSignature(IsCritical, Data)

        public TrustSignature(Boolean  IsCritical,
                              Byte[]   Data)

            : base(SignatureSubpackets.TrustSig, IsCritical, Data)

        { }

        #endregion

        #region TrustSignature(IsCritical, Depth, TrustAmount)

        public TrustSignature(Boolean  IsCritical,
                              Int32    Depth,
                              Int32    TrustAmount)

            : base(SignatureSubpackets.TrustSig, IsCritical, IntToByteArray(Depth, TrustAmount))

        { }

        #endregion

        #endregion


        private static Byte[] IntToByteArray(int v1, int v2)
        {
            return new Byte[] { (byte)v1, (byte)v2 };
        }

    }

}
