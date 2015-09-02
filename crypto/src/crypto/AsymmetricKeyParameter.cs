using System;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Crypto
{

    public abstract class AsymmetricKeyParameter : ICipherParameters //, Add IEquatable<AsymmetricKeyParameter>?
    {

        #region Properties

        #region IsPrivateKey

        private readonly Boolean _IsPrivateKey;

        public Boolean IsPrivateKey
        {
            get
            {
                return _IsPrivateKey;
            }
        }

        #endregion

        #endregion

        #region Constructor(s)

        protected AsymmetricKeyParameter(Boolean IsPrivateKey)
        {
            this._IsPrivateKey = IsPrivateKey;
        }

        #endregion


        #region IEquatable<AsymmetricKeyParameter> Members

        #region Equals(Object)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="Object">An object to compare with.</param>
        /// <returns>true|false</returns>
        public override Boolean Equals(Object Object)
        {

            if (Object == null)
                return false;

            // Check if the given object is an AsymmetricKeyParameter.
            var AsymmetricKeyParameter = Object as AsymmetricKeyParameter;
            if ((Object) AsymmetricKeyParameter == null)
                return false;

            return this.Equals(AsymmetricKeyParameter);

        }

        #endregion

        #region Equals(AsymmetricKeyParameter)

        /// <summary>
        /// Compares two AsymmetricKeyParameters for equality.
        /// </summary>
        /// <param name="AsymmetricKeyParameter">An AsymmetricKeyParameter to compare with.</param>
        /// <returns>True if both match; False otherwise.</returns>
        public Boolean Equals(AsymmetricKeyParameter AsymmetricKeyParameter)
        {

            if ((Object) AsymmetricKeyParameter == null)
                return false;

            return _IsPrivateKey.Equals(AsymmetricKeyParameter._IsPrivateKey);

        }

        #endregion

        #endregion

        #region GetHashCode()

        public override Int32 GetHashCode()
        {
            return _IsPrivateKey.GetHashCode();
        }

        #endregion

    }

}
