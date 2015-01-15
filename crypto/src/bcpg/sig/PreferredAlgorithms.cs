using System;
using System.Linq;

namespace Org.BouncyCastle.Bcpg.Sig
{

    public class PreferredAlgorithms : SignatureSubpacket
    {

        #region Properties

        public Int32[] Preferences
        {
            get
            {

                var v = new Int32[_Data.Length];

                for (var i = 0; i != v.Length; i++)
                    v[i] = _Data[i] & 0xff;

                return v;

            }
        }

        #endregion

        #region Constructor(s)

        #region PreferredAlgorithms(SubpacketType, IsCritical, Data)

        public PreferredAlgorithms(SignatureSubpackets  SubpacketType,
                                   Boolean              IsCritical,
                                   Byte[]               Data)

            : base(SubpacketType, IsCritical, Data)

        { }

        #endregion

        #region PreferredAlgorithms(SubpacketType, IsCritical, Preferences)

        public PreferredAlgorithms(SignatureSubpackets  SubpacketType,
                                   Boolean              IsCritical,
                                   Int32[]              Preferences)

            : base(SubpacketType, IsCritical, Preferences.Select(value => (Byte) value).ToArray())

        { }

        #endregion

        #endregion

    }

}
