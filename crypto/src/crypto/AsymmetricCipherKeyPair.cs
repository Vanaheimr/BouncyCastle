using System;

namespace Org.BouncyCastle.Crypto
{

    /// <summary>
    /// A holding class for public/private parameter pairs.
    /// </summary>
    public class AsymmetricCipherKeyPair
    {

        #region Properties

        /// <summary>
        /// The private key parameter.
        /// </summary>
        public AsymmetricKeyParameter  Private   { get; }


        /// <summary>
        /// The public key parameter.
        /// </summary>
        public AsymmetricKeyParameter  Public    { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new asymmetric cipher key pair.
        /// </summary>
        /// <param name="publicParameter">A public key parameter.</param>
        /// <param name="privateParameter">The corresponding private key.</param>
        public AsymmetricCipherKeyPair(AsymmetricKeyParameter  publicParameter,
                                       AsymmetricKeyParameter  privateParameter)
        {

            #region Initial checks

            if (publicParameter  == null)
                throw new ArgumentNullException(nameof(publicParameter),  "The given public key parameter must not be null!");

            if (privateParameter == null)
                throw new ArgumentNullException(nameof(privateParameter), "The given private key parameter must not be null!");

            if (publicParameter.IsPrivateKey)
                throw new ArgumentException("Expected a public key",  nameof(publicParameter));

            if (!privateParameter.IsPrivateKey)
                throw new ArgumentException("Expected a private key", nameof(privateParameter));

            #endregion

            this.Public   = publicParameter;
            this.Private  = privateParameter;

        }

        #endregion

    }

}
