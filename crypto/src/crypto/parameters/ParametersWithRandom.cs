using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{

    public class ParametersWithRandom : ICipherParameters
    {

        #region Properties

        #region Random

        private readonly SecureRandom _Random;

        public SecureRandom Random
        {
            get
            {
                return _Random;
            }
        }

        #endregion

        #region Parameters

        private readonly ICipherParameters _Parameters;

        public ICipherParameters Parameters
        {
            get
            {
                return _Parameters;
            }
        }

        #endregion

        #endregion

        #region Constructor(s)

        public ParametersWithRandom(ICipherParameters  CipherParameters,
                                    SecureRandom       SecureRandom = null)
        {

            if (CipherParameters == null)
                throw new ArgumentNullException("random");

            this._Parameters  = CipherParameters;
            this._Random      = SecureRandom != null ? SecureRandom : new SecureRandom();

        }

        #endregion

    }

}
