using System;
using System.Linq;
using System.Collections.Generic;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    /// <summary>
    /// Holder for a list of PgpOnePassSignature objects.
    /// </summary>
    public class PgpOnePassSignatureList : PgpObject,
                                           IEnumerable<PgpOnePassSignature>
    {

        #region Data

        private readonly List<PgpOnePassSignature> OnePassSignatures;

        #endregion

        #region Properties

        public UInt64 Count
        {
            get
            {
                return (UInt64)OnePassSignatures.Count;
            }
        }

        public Boolean IsEmpty
        {
            get
            {
                return !OnePassSignatures.Any();
            }
        }

        #endregion

        #region Constructor(s)

        public PgpOnePassSignatureList(IEnumerable<PgpOnePassSignature> OnePassSignatures)
        {
            this.OnePassSignatures = new List<PgpOnePassSignature>(OnePassSignatures);
        }

        public PgpOnePassSignatureList(PgpOnePassSignature sig)
        {
            this.OnePassSignatures = new List<PgpOnePassSignature>() { sig };
        }

        #endregion


        #region this[Index]

        public PgpOnePassSignature this[UInt64 Index]
        {
            get
            {
                return OnePassSignatures[(Int32) Index];
            }
        }

        #endregion

        #region GetEnumerator()

        public IEnumerator<PgpOnePassSignature> GetEnumerator()
        {
            return OnePassSignatures.GetEnumerator();
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
        {
            return OnePassSignatures.GetEnumerator();
        }

        #endregion

    }

}
