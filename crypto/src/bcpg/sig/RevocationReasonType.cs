namespace Org.BouncyCastle.Bcpg
{

    public enum RevocationReasonType : byte
    {

        /// <summary>
        /// No reason specified (key revocations or cert revocations)
        /// </summary>
        NoReason            =  0,

        /// <summary>
        /// Key is superseded (key revocations)
        /// </summary>
        KeySuperseded       =  1,

        /// <summary>
        /// Key material has been compromised (key revocations)
        /// </summary>
        KeyCompromised      =  2,

        /// <summary>
        /// Key is retired and no longer used (key revocations)
        /// </summary>
        KeyRetired          =  3,

        /// <summary>
        /// User ID information is no longer valid (cert revocations)
        /// </summary>
        UserNoLongerValid   = 32,

        // 100-110 - Private Use

    }

}
