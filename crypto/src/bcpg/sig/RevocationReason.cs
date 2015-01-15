using System;
using System.Text;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{

    /// <summary>
    /// Represents revocation reason OpenPGP signature sub packet.
    /// </summary>
    public class RevocationReason : SignatureSubpacket
    {

        #region Properties

        #region Reason

        public RevocationReasonType Reason
        {
            get
            {
                return (RevocationReasonType) GetData()[0];
            }
        }

        #endregion

        #region Description

        public String Description
        {

            get
            {

                var data = GetData();

                if (data.Length == 1)
                    return String.Empty;

                return Encoding.UTF8.GetString(data, 1, data.Length - 1);

            }

        }

        #endregion

        #endregion

        #region Constructor(s)

        #region RevocationReason(IsCritical, Data)

        public RevocationReason(Boolean  IsCritical,
                                Byte[]   Data)

            : base(SignatureSubpackets.RevocationReason, IsCritical, Data)

        { }

        #endregion

        #region RevocationReason(IsCritical, Reason, Description)

        public RevocationReason(Boolean               IsCritical,
                                RevocationReasonType  Reason,
                                String                Description)

            : base(SignatureSubpackets.RevocationReason, IsCritical, CreateData(Reason, Description))

        { }

        #endregion

        #endregion


        private static Byte[] CreateData(RevocationReasonType  Reason,
                                         String                Description)
        {

            var descriptionBytes  = Encoding.UTF8.GetBytes(Description);
            var data              = new Byte[1 + descriptionBytes.Length];

            data[0] = (byte) Reason;
            Array.Copy(descriptionBytes, 0, data, 1, descriptionBytes.Length);

            return data;

        }

    }

}
