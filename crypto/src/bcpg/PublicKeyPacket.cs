using System;
using System.IO;

using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Bcpg
{

    /// <remarks>
    /// Basic packet for a PGP public key.
    /// </remarks>
    public class PublicKeyPacket : ContainedPacket //, PublicKeyAlgorithmTag
    {

        #region Properties

        #region Version

        private readonly Int32 _Version;

        public Int32 Version
        {
            get
            {
                return _Version;
            }
        }

        #endregion

        #region Algorithm

        private readonly PublicKeyAlgorithms _Algorithm;

        public PublicKeyAlgorithms Algorithm
        {
            get
            {
                return _Algorithm;
            }
        }

        #endregion

        #region ValidDays

        private readonly UInt64 _ValidDays;

        public UInt64 ValidDays
        {
            get
            {
                return _ValidDays;
            }
        }

        #endregion

        #region Time

        private readonly Int64 time;

        public DateTime Time
        {
            get
            {
                return DateTimeUtilities.UnixMsToDateTime((UInt64) time * 1000L);
            }
        }

        #endregion

        #region Key

        private IBcpgKey key;

        public IBcpgKey Key
        {
            get
            {
                return key;
            }
        }

        #endregion

        #endregion

        #region Constructor(s)

        #region (internal) PublicKeyPacket(BCPGInputStream)

        internal PublicKeyPacket(BcpgInputStream BCPGInputStream)
        {

            _Version = BCPGInputStream.ReadByte();

            time = ((uint) BCPGInputStream.ReadByte() << 24) |
                   ((uint) BCPGInputStream.ReadByte() << 16) |
                   ((uint) BCPGInputStream.ReadByte() <<  8) |
                    (uint) BCPGInputStream.ReadByte();

            if (_Version <= 3)
                _ValidDays = (UInt64) ((BCPGInputStream.ReadByte() << 8) |
                                        BCPGInputStream.ReadByte());

            _Algorithm = (PublicKeyAlgorithms) BCPGInputStream.ReadByte();

            switch ((PublicKeyAlgorithms) _Algorithm)
            {

                case PublicKeyAlgorithms.RsaEncrypt:
                case PublicKeyAlgorithms.RsaGeneral:
                case PublicKeyAlgorithms.RsaSign:
                    key = new RsaPublicBcpgKey(BCPGInputStream);
                    break;

                case PublicKeyAlgorithms.Dsa:
                    key = new DsaPublicBcpgKey(BCPGInputStream);
                    break;

                case PublicKeyAlgorithms.ElGamalEncrypt:
                case PublicKeyAlgorithms.ElGamalGeneral:
                    key = new ElGamalPublicBcpgKey(BCPGInputStream);
                    break;

                default:
                    throw new IOException("unknown PGP public key algorithm encountered");

            }

        }

        #endregion

        #region PublicKeyPacket(PublicKeyPacket, Time, Key)

        /// <summary>
        /// Construct a version 4 public key packet.
        /// </summary>
        public PublicKeyPacket(PublicKeyAlgorithms  Algorithm,
                               DateTime             Time,
                               IBcpgKey             Key)
        {

            this._Version    = 4;
            this.time        = (Int64) DateTimeUtilities.DateTimeToUnixMs(Time) / 1000L;
            this._Algorithm  = Algorithm;
            this.key         = Key;

        }

        #endregion

        #endregion


        #region GetEncodedContents()

        public virtual Byte[] GetEncodedContents()
        {

            var _MemoryStream      = new MemoryStream();
            var _BCPGOutputStream  = new BcpgOutputStream(_MemoryStream);

            _BCPGOutputStream.WriteByte((byte) _Version);
            _BCPGOutputStream.WriteInt((int) time);

            if (_Version <= 3)
                _BCPGOutputStream.WriteShort((short) _ValidDays);

            _BCPGOutputStream.WriteByte((byte) _Algorithm);
            _BCPGOutputStream.WriteObject((BcpgObject)key);

            return _MemoryStream.ToArray();

        }

        #endregion

        #region Encode

        public override void Encode(BcpgOutputStream bcpgOut)
        {
            bcpgOut.WritePacket(PacketTag.PublicKey, GetEncodedContents(), true);
        }

        #endregion

    }

}
