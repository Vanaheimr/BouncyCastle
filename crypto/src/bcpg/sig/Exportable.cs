using System;



namespace Org.BouncyCastle.Bcpg.Sig
{

    /// <summary>
    /// Packet giving signature creation time.
    /// </summary>
    public class Exportable : SignatureSubpacket
    {

        #region Properties

        #region IsExportable

        public Boolean IsExportable
        {
            get
            {
                return _Data[0] != 0;
            }
        }

        #endregion

        #endregion

        #region Constructor(s)

        #region Exportable(IsCritical, Data)

        public Exportable(Boolean  IsCritical,
                          Byte[]   Data)

            : base(SignatureSubpackets.Exportable, IsCritical, Data)

        { }

        #endregion

        #region Exportable(IsCritical, IsExportable)

        public Exportable(Boolean  IsCritical,
                          Boolean  IsExportable)

            : base(SignatureSubpackets.Exportable, IsCritical, BooleanToByteArray(IsExportable))

        { }

        #endregion

        #endregion


        private static Byte[] BooleanToByteArray(Boolean val)
        {

            var data = new byte[1];

            if (val)
            {
                data[0] = 1;
                return data;
            }

            else

                return data;

        }

    }

}
