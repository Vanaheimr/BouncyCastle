using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;

using Org.BouncyCastle.Bcpg.Sig;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    /// <summary>
    /// Container for a list of signature subpackets.
    /// </summary>
    public class PgpSignatureSubpacketVector : IEnumerable<SignatureSubpacket>
    {

        #region Data

        private readonly List<SignatureSubpacket> SignatureSubpacketList;

        #endregion

        #region Properties

        #region Count

        /// <summary>
        /// The number of packets this vector contains.
        /// </summary>
        public UInt64 Count
        {
            get
            {
                return (UInt64) SignatureSubpacketList.Count;
            }
        }

        #endregion

        #region CriticalTags

        public IEnumerable<SignatureSubpackets> CriticalTags
        {
            get
            {
                return SignatureSubpacketList.Where (packet => packet.IsCritical).
                                              Select(packet => packet.SubpacketType);
            }
        }

        #endregion


        #region KeyExpirationTime

        /// <summary>
        /// Return the number of seconds a key is valid for after its creation date.
        /// A value of zero means the key never expires.
        /// </summary>
        /// <returns>Seconds a signature is valid for.</returns>
        public UInt64 KeyExpirationTime
        {
            get
            {
                return GetAndMapSubpacket<KeyExpirationTime, UInt64>(SignatureSubpackets.KeyExpireTime,
                                                                     item => item.Time);
            }
        }

        #endregion

        #region IssuerKeyId

        public UInt64 IssuerKeyId
        {
            get
            {
                return GetAndMapSubpacket<IssuerKeyId, UInt64>(SignatureSubpackets.IssuerKeyId,
                                                               item => item.KeyId);
            }
        }

        #endregion

        #region HasSignatureCreationTime

        public Boolean HasSignatureCreationTime
        {
            get
            {
                return GetAndMapSubpacket<SignatureCreationTime, Boolean>(SignatureSubpackets.CreationTime,
                                                                          item => item != null);
            }
        }

        #endregion

        #region SignatureCreationTime

        public DateTime SignatureCreationTime
        {
            get
            {
                return GetAndMapSubpacket<SignatureCreationTime, DateTime>(SignatureSubpackets.CreationTime,
                                                                           item => item.Time);
            }
        }

        #endregion

        #region SignatureExpirationTime

        /// <summary>
        /// Return the number of seconds a signature is valid for after its creation date.
        /// A value of zero means the signature never expires.
        /// </summary>
        /// <returns>Seconds a signature is valid for.</returns>
        public UInt64 SignatureExpirationTime
        {
            get
            {
                return GetAndMapSubpacket<SignatureExpirationTime, UInt64>(SignatureSubpackets.ExpireTime,
                                                                           item => item.Time);
            }
        }

        #endregion

        #region KeyFlags

        public Int32 GetKeyFlags
        {

            get
            {

                var p = GetSubpacket(SignatureSubpackets.KeyFlags);

                return p == null
                    ? 0
                    : ((KeyFlags) p).Flags;

            }

        }

        #endregion

        #region SignerUserId

        public String SignerUserId
        {

            get
            {

                var Subpacket = GetSubpacket(SignatureSubpackets.SignerUserId);

                return Subpacket == null
                    ? null
                    : ((SignerUserId) Subpacket).Id;

            }

        }

        #endregion

        #region IsPrimaryUserId

        public Boolean IsPrimaryUserId
        {

            get
            {

                var primaryId = (PrimaryUserId) this.GetSubpacket(SignatureSubpackets.PrimaryUserId);

                if (primaryId != null)
                    return primaryId.IsPrimaryUserId;

                return false;

            }

        }

        #endregion

        #region PreferredHashAlgorithms

        public Int32[] PreferredHashAlgorithms
        {
            get
            {
                return GetAndMapSubpacket<PreferredAlgorithms, Int32[]>(SignatureSubpackets.PreferredHashAlgorithms,
                                                                        item => item.Preferences);
            }
        }

        #endregion

        #region PreferredSymmetricAlgorithms

        public Int32[] PreferredSymmetricAlgorithms
        {
            get
            {

                var p = GetSubpacket(SignatureSubpackets.PreferredSymmetricAlgorithms);

                return p == null
                    ? null
                    : ((PreferredAlgorithms) p).Preferences;

            }
        }

        #endregion

        #region PreferredCompressionAlgorithms

        public Int32[] PreferredCompressionAlgorithms
        {
            get
            {

                var p = GetSubpacket(SignatureSubpackets.PreferredCompressionAlgorithms);

                return p == null
                    ? null
                    : ((PreferredAlgorithms) p).Preferences;

            }
        }

        #endregion

        #region NotationDataOccurences

        public IEnumerable<NotationData> NotationDataOccurences
        {
            get
            {
                return SignatureSubpacketList.
                           Where(packet => packet.SubpacketType == SignatureSubpackets.NotationData).
                           Cast<NotationData>();
            }
        }

        #endregion

        #endregion

        #region Constructor(s)

        internal PgpSignatureSubpacketVector(IEnumerable<SignatureSubpacket> packets)
        {
            this.SignatureSubpacketList = new List<SignatureSubpacket>(packets);
        }

        #endregion




        public T2 GetAndMapSubpacket<T1, T2>(SignatureSubpackets  SubpacketType,
                                             Func<T1, T2>         Mapper)
        {

            var Item = SignatureSubpacketList.
                           Where(packet => packet.SubpacketType == SubpacketType).
                           Cast<T1>().
                           FirstOrDefault();

            if (Item != null)
                return Mapper(Item);

            return default(T2);

        }

        #region HasSubpacket(SubpacketType)

        /// <summary>
        /// Checks if a signature subpacket of the given type exists.
        /// </summary>
        /// <param name="SubpacketType">The type of the subpacket.</param>
        public Boolean HasSubpacket(SignatureSubpackets SubpacketType)
        {
            return GetSubpacket(SubpacketType) != null;
        }

        #endregion

        #region GetSubpackets(SubpacketType)

        /// <summary>
        /// The first signature subpacket of the given type.
        /// </summary>
        /// <param name="SubpacketType">The type of the subpacket.</param>
        public SignatureSubpacket GetSubpacket(SignatureSubpackets SubpacketType)
        {

            return SignatureSubpacketList.
                       Where(packet => packet.SubpacketType == SubpacketType).
                       FirstOrDefault();

        }

        #endregion

        #region GetSubpackets(SubpacketType)

        /// <summary>
        /// All signature subpackets of the given type.
        /// </summary>
        /// <param name="SubpacketType">The type of the subpacket.</param>
        public IEnumerable<SignatureSubpacket> GetSubpackets(SignatureSubpackets SubpacketType)
        {
            return SignatureSubpacketList.Where(packet => packet.SubpacketType == SubpacketType);
        }

        #endregion


        #region IEnumerable Members

        public IEnumerator<SignatureSubpacket> GetEnumerator()
        {
            return SignatureSubpacketList.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return SignatureSubpacketList.GetEnumerator();
        }

        #endregion

    }

}
