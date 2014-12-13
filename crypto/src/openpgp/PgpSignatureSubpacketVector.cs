using System;
using System.Linq;
using System.Collections;

using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Utilities;
using System.Collections.Generic;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    /// <summary>
    /// Container for a list of signature subpackets.
    /// </summary>
    public class PgpSignatureSubpacketVector : IEnumerable<SignatureSubpacket>
    {

        #region Data

        private readonly List<SignatureSubpacket> packets;

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
                return (UInt64)packets.Count;
            }
        }

        #endregion

        #region CriticalTags

        public IEnumerable<SignatureSubpackets> CriticalTags
        {
            get
            {
                return packets.Where (packet => packet.IsCritical()).
                               Select(packet => packet.SubpacketType);
            }
        }

        #endregion

        #endregion

        #region Constructor(s)

        internal PgpSignatureSubpacketVector(IEnumerable<SignatureSubpacket> packets)
        {
            this.packets = new List<SignatureSubpacket>(packets);
        }

        #endregion


        public SignatureSubpacket GetSubpacket(SignatureSubpackets type)
        {

            return packets.
                       Where(packet => packet.SubpacketType == type).
                       FirstOrDefault();

        }

        public T2 GetSubpacket2<T, T2>(SignatureSubpackets type, Func<T, T2> Delegate)
        {

            var Item = packets.
                           Where(packet => packet.SubpacketType == type).
                           Cast<T>().
                           FirstOrDefault();

            if (Item != null)
                return Delegate(Item);

            return default(T2);

        }

        /**
         * Return true if a particular subpacket type exists.
         *
         * @param type type to look for.
         * @return true if present, false otherwise.
         */
        public Boolean HasSubpacket(SignatureSubpackets type)
        {
            return GetSubpacket(type) != null;
        }

        /**
         * Return all signature subpackets of the passed in type.
         * @param type subpacket type code
         * @return an array of zero or more matching subpackets.
         */
        public IEnumerable<SignatureSubpacket> GetSubpackets(SignatureSubpackets type)
        {

            return packets.
                       Where(packet => packet.SubpacketType == type);

        }

        public IEnumerable<NotationData> GetNotationDataOccurences()
        {

            return packets.
                       Where(packet => packet.SubpacketType == SignatureSubpackets.NotationData).
                       Cast<NotationData>();

        }

        public UInt64 GetIssuerKeyId()
        {
            return GetSubpacket2<IssuerKeyId, UInt64>(SignatureSubpackets.IssuerKeyId, item => item.KeyId);
        }

        public Boolean HasSignatureCreationTime()
        {
            return GetSubpacket2<SignatureCreationTime, Boolean>(SignatureSubpackets.CreationTime, item => item != null);
            //return GetSubpacket(SignatureSubpackets.CreationTime) != null;
        }

        public DateTime GetSignatureCreationTime()
        {
            return GetSubpacket2<SignatureCreationTime, DateTime>(SignatureSubpackets.CreationTime, item => item.GetTime());
        }

        /// <summary>
        /// Return the number of seconds a signature is valid for after its creation date.
        /// A value of zero means the signature never expires.
        /// </summary>
        /// <returns>Seconds a signature is valid for.</returns>
        public Int64 GetSignatureExpirationTime()
        {
            return GetSubpacket2<SignatureExpirationTime, Int64>(SignatureSubpackets.ExpireTime, item => item.Time);
            //SignatureSubpacket p = GetSubpacket(SignatureSubpackets.ExpireTime);
            //return p == null ? 0 : ((SignatureExpirationTime) p).Time;
        }

        /// <summary>
        /// Return the number of seconds a key is valid for after its creation date.
        /// A value of zero means the key never expires.
        /// </summary>
        /// <returns>Seconds a signature is valid for.</returns>
        public Int64 GetKeyExpirationTime()
        {
            return GetSubpacket2<KeyExpirationTime, Int64>(SignatureSubpackets.KeyExpireTime, item => item.Time);
            //SignatureSubpacket p = GetSubpacket(SignatureSubpackets.KeyExpireTime);
            //return p == null ? 0 : ((KeyExpirationTime) p).Time;
        }

        public Int32[] GetPreferredHashAlgorithms()
        {
            return GetSubpacket2<PreferredAlgorithms, Int32[]>(SignatureSubpackets.PreferredHashAlgorithms, item => item.GetPreferences());
            //SignatureSubpacket p = GetSubpacket(SignatureSubpackets.PreferredHashAlgorithms);
            //return p == null ? null : ((PreferredAlgorithms) p).GetPreferences();
        }

        public int[] GetPreferredSymmetricAlgorithms()
        {

            var p = GetSubpacket(SignatureSubpackets.PreferredSymmetricAlgorithms);

            return p == null
                ? null
                : ((PreferredAlgorithms) p).GetPreferences();

        }

        public int[] GetPreferredCompressionAlgorithms()
        {

            var p = GetSubpacket(SignatureSubpackets.PreferredCompressionAlgorithms);

            return p == null
                ? null
                : ((PreferredAlgorithms) p).GetPreferences();

        }

        public int GetKeyFlags()
        {

            var p = GetSubpacket(SignatureSubpackets.KeyFlags);

            return p == null
                ? 0
                : ((KeyFlags) p).Flags;

        }

        public String GetSignerUserId()
        {

            var p = GetSubpacket(SignatureSubpackets.SignerUserId);

            return p == null
                ? null
                : ((SignerUserId) p).GetId();

        }

        public bool IsPrimaryUserId()
        {

            var primaryId = (PrimaryUserId) this.GetSubpacket(SignatureSubpackets.PrimaryUserId);

            if (primaryId != null)
                return primaryId.IsPrimaryUserId();

            return false;

        }

        




        #region IEnumerable Members

        public IEnumerator<SignatureSubpacket> GetEnumerator()
        {
            return packets.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return packets.GetEnumerator();
        }

        #endregion

    }

}
