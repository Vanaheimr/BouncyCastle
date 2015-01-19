using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    /// <remarks>
    /// A holder for a list of PGP encryption method packets.
    /// </remarks>
    public class PgpEncryptedDataList : PgpObject,
                                        IEnumerable<PgpEncryptedData>
    {

        #region Data

        private readonly List<PgpEncryptedData>  _EncryptedDataList;
        private readonly InputStreamPacket       _Data;

        #endregion

        #region Properties

        #region Count

        public UInt64 Count
        {
            get
            {
                return (UInt64) _EncryptedDataList.Count;
            }
        }

        #endregion

        #region IsEmpty

        public Boolean IsEmpty
        {
            get
            {
                return !_EncryptedDataList.Any();
            }
        }

        #endregion

        #endregion

        #region Constructor(s)

        public PgpEncryptedDataList(BcpgInputStream BCPGInputStream)
        {

            _EncryptedDataList = new List<PgpEncryptedData>();
            var _list = new List<Packet>();

            while (BCPGInputStream.NextPacketTag() == PacketTag.PublicKeyEncryptedSession ||
                   BCPGInputStream.NextPacketTag() == PacketTag.SymmetricKeyEncryptedSessionKey)
            {
                _list.Add(BCPGInputStream.ReadPacket());
            }

            _Data = BCPGInputStream.ReadPacket<InputStreamPacket>();

            foreach (var p in _list)
            {

                if (p is SymmetricKeyEncSessionPacket)
                    _EncryptedDataList.Add(new PgpPbeEncryptedData((SymmetricKeyEncSessionPacket) p, _Data));

                else
                    _EncryptedDataList.Add(new PgpPublicKeyEncryptedData((PublicKeyEncSessionPacket) p, _Data));

            }

        }

        #endregion


        #region this[Index]

        public PgpEncryptedData this[Int32 Index]
        {
            get
            {
                return _EncryptedDataList[Index];
            }
        }

        #endregion


        #region GetEnumerator()

        public IEnumerator<PgpEncryptedData> GetEnumerator()
        {
            return _EncryptedDataList.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return _EncryptedDataList.GetEnumerator();
        }

        #endregion

    }

}
