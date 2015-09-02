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

        private readonly UInt64 _KeyId;

        /// <summary>
        /// The KeyId associated with the contained private key.
        /// </summary>
        public UInt64 KeyId
        {
            get
            {
                return _KeyId;
            }
        }

        #endregion

        #region PrivateKey

        private readonly AsymmetricKeyParameter _PrivateKey;

        /// <summary>
        /// The contained private key.
        /// </summary>
        public AsymmetricKeyParameter PrivateKey
        {
            get
            {
                return _PrivateKey;
            }
        }

        #endregion

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a PgpPrivateKey from a regular private key and the KeyId
        /// of its associated public key.
        /// </summary>
        /// <param name="PrivateKey">Private key to use.</param>
        /// <param name="KeyId">The Id of the corresponding public key.</param>
        public PgpPrivateKey(AsymmetricKeyParameter  PrivateKey,
                             UInt64                  KeyId)
        {

            if (!PrivateKey.IsPrivateKey)
                throw new ArgumentException("Expected a private key", "privateKey");

            this._PrivateKey  = PrivateKey;
            this._KeyId       = KeyId;

        }

        #endregion

    }

}
