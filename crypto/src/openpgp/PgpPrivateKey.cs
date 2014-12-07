using System;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    /// <summary>
    /// General class to contain a private key for use with other OpenPGP objects.
    /// </summary>
    public class PgpPrivateKey
    {

        #region Properties

        #region KeyId

        private readonly UInt64 keyId;

        /// <summary>
        /// The keyId associated with the contained private key.
        /// </summary>
        public UInt64 KeyId
        {
            get
            {
                return keyId;
            }
        }

        #endregion

        #region Key

        private readonly AsymmetricKeyParameter privateKey;

        /// <summary>
        /// The contained private key.
        /// </summary>
        public AsymmetricKeyParameter Key
        {
            get
            {
                return privateKey;
            }
        }

        #endregion

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a PgpPrivateKey from a regular private key and the ID of its
        /// associated public key.
        /// </summary>
        /// <param name="PrivateKey">Private key to use.</param>
        /// <param name="KeyId">ID of the corresponding public key.</param>
        public PgpPrivateKey(AsymmetricKeyParameter  PrivateKey,
                             UInt64                  KeyId)
        {

            if (!PrivateKey.IsPrivate)
                throw new ArgumentException("Expected a private key", "privateKey");

            this.privateKey  = PrivateKey;
            this.keyId       = KeyId;

        }

        #endregion

    }

}
