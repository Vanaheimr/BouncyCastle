using System;
using System.Linq;
using System.Collections.Generic;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    /// <summary>
    /// A list of PGP signatures - normally in the signature block after literal data.
    /// </summary>
    public class PgpSignatureList : PgpObject,
                                    IEnumerable<PgpSignature>
    {

        #region Data

        private readonly List<PgpSignature> Signatures;

        #endregion

        #region Properties

        public UInt32 Count
        {
            get
            {
                return (UInt32) Signatures.Count;
            }
        }

        public Boolean IsEmpty
        {
            get
            {
                return (Signatures.Count == 0);
            }
        }

        #endregion

        #region Constructor(s)

        public PgpSignatureList(PgpSignature Signature)
        {
            this.Signatures = new List<PgpSignature>() { Signature };
        }

        public PgpSignatureList(IEnumerable<PgpSignature> Signatures)
        {
            this.Signatures = new List<PgpSignature>(Signatures);
        }

        #endregion


        #region this[Index]

        public PgpSignature this[UInt64 Index]
        {
            get
            {
                return Signatures[(Int32) Index];
            }
        }

        #endregion

        #region GetEnumerator()

        public IEnumerator<PgpSignature> GetEnumerator()
        {
            return Signatures.GetEnumerator();
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
        {
            return Signatures.GetEnumerator();
        }

        #endregion

    }

}
