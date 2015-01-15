using System;

namespace Org.BouncyCastle.Bcpg.Sig
{

    /// <summary>
    /// packet giving the User ID of the signer.
    /// </summary>
    public class SignerUserId : SignatureSubpacket
    {

        #region Properties

        #region Id

        public String Id
        {
            get
            {

                var chars = new Char[_Data.Length];

                for (var i = 0; i != chars.Length; i++)
                    chars[i] = (Char) (_Data[i] & 0xff);

                return new String(chars);

            }
        }

        #endregion

        #endregion

        #region Constructor(s)

        #region SignerUserId(IsCritical, Data)

        public SignerUserId(Boolean  IsCritical,
                            Byte[]   Data)

            : base(SignatureSubpackets.SignerUserId, IsCritical, Data)

        { }

        #endregion

        #region SignerUserId(IsCritical, UserId)

        public SignerUserId(Boolean  IsCritical,
                            String   UserId)

            : base(SignatureSubpackets.SignerUserId, IsCritical, UserIdToBytes(UserId))

        { }

        #endregion

        #endregion


        private static Byte[] UserIdToBytes(String UserId)
        {

            var idData = new Byte[UserId.Length];

            for (int i = 0; i != UserId.Length; i++)
                idData[i] = (Byte) UserId[i];

            return idData;

        }

    }

}
