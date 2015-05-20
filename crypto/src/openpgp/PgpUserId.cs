
using System;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    /// <summary>
    /// A PGP UserId.
    /// </summary>
    /// <remarks>Added by ahzf, as it seemed to be missing!</remarks>
    public class PgpUserId : PgpObject
    {

        #region Data

        private readonly UserIdPacket _UserIdPacket;

        #endregion

        #region Properties

        #region Value

        private readonly String _Value;

        /// <summary>
        /// The Id.
        /// </summary>
        public String Value
        {
            get
            {
                return _Value;
            }
        }

        #endregion

        #endregion

        #region Constructor(s)

        public PgpUserId(BcpgInputStream BCPGInputStream)
        {
            _UserIdPacket  = BCPGInputStream.ReadPacket<UserIdPacket>();
            _Value         = _UserIdPacket.Id;
        }

        #endregion

    }

}
