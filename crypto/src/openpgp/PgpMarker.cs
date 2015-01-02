namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    /// <remarks>
    /// A PGP marker packet - in general these should be ignored other than where
    /// the idea is to preserve the original input stream.
    /// </remarks>
    public class PgpMarker : PgpObject
    {

        #region Data

        private readonly MarkerPacket _MarkerPacket;

        #endregion

        #region Constructor(s)

        public PgpMarker(BcpgInputStream BCPGInputStream)
        {
            _MarkerPacket = BCPGInputStream.ReadPacket<MarkerPacket>();
        }

        #endregion

    }

}
