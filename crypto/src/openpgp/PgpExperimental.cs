using System;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    public class PgpExperimental : PgpObject
    {

        #region Data

        private readonly ExperimentalPacket _ExperimentalPacket;

        #endregion

        #region Constructor(s)

        public PgpExperimental(BcpgInputStream BCPGInputStream)
        {
            _ExperimentalPacket = BCPGInputStream.ReadPacket<ExperimentalPacket>();
        }

        #endregion

    }

}
