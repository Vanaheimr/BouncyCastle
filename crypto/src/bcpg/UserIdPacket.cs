using System;
using System.Text;

namespace Org.BouncyCastle.Bcpg
{

    /// <summary>
    /// Basic type for a user ID packet.
    /// </summary>
    public class UserIdPacket : ContainedPacket
    {

        #region Data

        private readonly Byte[] _IdData;

        #endregion

        #region Properties

        #region Id

        private readonly String _Id;

        /// <summary>
        /// The Id.
        /// </summary>
        public String Id
        {
            get
            {
                return _Id;
            }
        }

        #endregion

        #endregion

        #region Constructor(s)

        #region UserIdPacket(BCPGInputStream)

        /// <summary>
        /// Read a UserId packet from the given stream.
        /// </summary>
        /// <param name="BCPGInputStream">An input stream.</param>
        public UserIdPacket(BcpgInputStream BCPGInputStream)
        {

            this._IdData  = BCPGInputStream.ReadAll();
            this._Id      = Encoding.UTF8.GetString(_IdData, 0, _IdData.Length);

        }

        #endregion

        #region UserIdPacket(Id)

        /// <summary>
        /// Create a new UserId packet from the given string.
        /// </summary>
        /// <param name="Id">A UserId.</param>
        public UserIdPacket(String Id)
        {

            this._Id      = Id;
            this._IdData  = Encoding.UTF8.GetBytes(Id);

        }

        #endregion

        #endregion


        #region Encode(BCPGOutputStream)

        public override void Encode(BcpgOutputStream BCPGOutputStream)
        {
            BCPGOutputStream.WritePacket(PacketTag.UserId, _IdData, true);
        }

        #endregion

    }

}
