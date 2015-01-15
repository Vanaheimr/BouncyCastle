using System;
using System.Text;

namespace Org.BouncyCastle.Bcpg
{

    /// <summary>
    /// Represents revocation key OpenPGP signature sub packet.
    /// </summary>
    public class RevocationKey : SignatureSubpacket
    {

        #region Properties

        #region SignatureClass

        public RevocationKeyType SignatureClass
        {
            get
            {
                return (RevocationKeyType) this.GetData()[0];
            }
        }

        #endregion

        #region Algorithm

        public PublicKeyAlgorithms Algorithm
        {
            get
            {
                return (PublicKeyAlgorithms) this.GetData()[1];
            }
        }

        #endregion

        #region Fingerprint

        public Byte[] Fingerprint
        {
            get
            {

                var data         = this.GetData();
                var fingerprint  = new byte[data.Length - 2];
                Array.Copy(data, 2, fingerprint, 0, fingerprint.Length);

                return fingerprint;

            }
        }

        #endregion

        #endregion

        #region Constructor(s)

        #region RevocationKey(IsCritical, Data)

        public RevocationKey(Boolean  IsCritical,
                             Byte[]   Data)

            : base(SignatureSubpackets.RevocationKey, IsCritical, Data)

        { }

        #endregion

        #region RevocationKey(IsCritical, SignatureClass, KeyAlgorithm, Fingerprint)

        public RevocationKey(Boolean              IsCritical,
                             RevocationKeyType    SignatureClass,
                             PublicKeyAlgorithms  KeyAlgorithm,
                             Byte[]               Fingerprint)

            : base(SignatureSubpackets.RevocationKey, IsCritical, CreateData(SignatureClass, KeyAlgorithm, Fingerprint))

        { }

        #endregion

        #endregion


        private static Byte[] CreateData(RevocationKeyType    SignatureClass,
                                         PublicKeyAlgorithms  KeyAlgorithm,
                                         Byte[]               Fingerprint)
        {

            var data = new Byte[2 + Fingerprint.Length];
            data[0] = (Byte) SignatureClass;
            data[1] = (Byte) KeyAlgorithm;
            Array.Copy(Fingerprint, 0, data, 2, Fingerprint.Length);

            return data;

        }

    }

}
