using System;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    /// <summary>
    /// Key flag values for the KeyFlags subpacket.
    /// </summary>
    public abstract class PgpKeyFlags
    {
        /// <summary>
        /// This key may be used to certify other keys.
        /// </summary>
        public const Int32 CanCertify                 = 0x01;

        /// <summary>
        /// This key may be used to sign data.
        /// </summary>
        public const Int32 CanSign                    = 0x02;

        /// <summary>
        /// This key may be used to encrypt communications.
        /// </summary>
        public const Int32 CanEncryptCommunications   = 0x04;

        /// <summary>
        /// This key may be used to encrypt storage.
        /// </summary>
        public const Int32 CanEncryptStorage          = 0x08;

        /// <summary>
        /// The private component of this key may have been split by a secret-sharing mechanism.
        /// </summary>
        public const Int32 MaybeSplit                 = 0x10;

        /// <summary>
        /// The private component of this key may be in the possession of more than one person.
        /// </summary>
        public const Int32 MaybeShared                = 0x80;

    }

}
