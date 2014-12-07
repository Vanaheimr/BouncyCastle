using System;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    /// <summary>
    /// Generic exception class for PGP encoding/decoding problems.
    /// </summary>
    [Serializable]
    public class PgpException : Exception
    {

        public PgpException() : base() {}

        public PgpException(String message) : base(message) {}

        public PgpException(String message, Exception exception) : base(message, exception) { }

    }

}
