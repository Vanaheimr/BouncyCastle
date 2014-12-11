using System;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    /// <remarks>
    /// General class to handle JCA key pairs and convert them into OpenPGP ones.
    /// <p>
    /// A word for the unwary, the KeyId for an OpenPGP public key is calculated from
    /// a hash that includes the time of creation, if you pass a different date to the
    /// constructor below with the same public private key pair the KeyIs will not be the
    /// same as for previous generations of the key, so ideally you only want to do
    /// this once.
    /// </p>
    /// </remarks>
    public class PgpKeyPair
    {

        #region Properties

        #region KeyId

        /// <summary>
        /// The keyId associated with this key pair.
        /// </summary>
        public UInt64 KeyId
        {
            get
            {
                return _PublicKey.KeyId;
            }
        }

        #endregion

        #region PublicKey

        private readonly PgpPublicKey _PublicKey;

        /// <summary>
        /// The public key associated with this key pair.
        /// </summary>
        public PgpPublicKey PublicKey
        {
            get
            {
                return _PublicKey;
            }
        }

        #endregion

        #region PrivateKey

        private readonly PgpPrivateKey _PrivateKey;

        /// <summary>
        /// The private key associated with this key pair.
        /// </summary>
        public PgpPrivateKey PrivateKey
        {
            get
            {
                return _PrivateKey;
            }
        }

        #endregion

        #endregion

        #region Constructor(s)

        public PgpKeyPair(PublicKeyAlgorithms    algorithm,
                          AsymmetricCipherKeyPair  keyPair,
                          DateTime                 time)

            : this(algorithm, keyPair.Public, keyPair.Private, time)

        { }

        public PgpKeyPair(PublicKeyAlgorithms   algorithm,
                          AsymmetricKeyParameter  pubKey,
                          AsymmetricKeyParameter  privKey,
                          DateTime                time)
        {
            this._PublicKey   = new PgpPublicKey(algorithm, pubKey, time);
            this._PrivateKey  = new PgpPrivateKey(privKey, _PublicKey.KeyId);
        }

        /// <summary>
        /// Create a key pair from a PgpPrivateKey and a PgpPublicKey.
        /// </summary>
        /// <param name="pub">The public key.</param>
        /// <param name="priv">The private key.</param>
        public PgpKeyPair(PgpPublicKey   pub,
                          PgpPrivateKey  priv)
        {
            this._PublicKey  = pub;
            this._PrivateKey = priv;
        }

        #endregion

    }

}
