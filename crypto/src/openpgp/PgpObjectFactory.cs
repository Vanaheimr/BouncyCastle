using System;
using System.IO;
using System.Collections;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    /// <remarks>
    /// General class for reading a PGP object stream.
    /// <p>
    /// Note: if this class finds a PgpPublicKey or a PgpSecretKey it
    /// will create a PgpPublicKeyRing, or a PgpSecretKeyRing for each
    /// key found. If all you are trying to do is read a key ring file use
    /// either PgpPublicKeyRingBundle or PgpSecretKeyRingBundle.</p>
    /// </remarks>
    public class PgpObjectFactory
    {

        #region Data

        private readonly BcpgInputStream _BCPGInputStream;

        #endregion

        #region Properties

        #region AllPgpObjects

        /// <summary>
        /// Return all available objects.
        /// </summary>
        public IEnumerable<PgpObject> AllPgpObjects
        {

            get
            {

                PgpObject pgpObject;

                while ((pgpObject = NextPgpObject()) != null)
                    yield return pgpObject;

            }

        }

        #endregion

        #endregion

        #region Constructor(s)

        #region PgpObjectFactory(InputStream)

        public PgpObjectFactory(Stream InputStream)
        {
            this._BCPGInputStream = BcpgInputStream.Wrap(InputStream);
        }

        #endregion

        #region PgpObjectFactory(Bytes)

        public PgpObjectFactory(Byte[] Bytes)
            : this(new MemoryStream(Bytes, writable: false))
        { }

        #endregion

        #endregion


        #region NextPgpObject()

        /// <summary>
        /// Return the next object in the stream, or null if the end is reached.
        /// </summary>
        /// <exception cref="IOException">On a parse error</exception>
        public PgpObject NextPgpObject()
        {

            var tag = _BCPGInputStream.NextPacketTag();

            if ((int) tag == -1)
                return null;

            switch (tag)
            {

                case PacketTag.Signature:
                {

                    var Signatures = new List<PgpSignature>();

                    while (_BCPGInputStream.NextPacketTag() == PacketTag.Signature)
                    {
                        try
                        {
                            Signatures.Add(new PgpSignature(_BCPGInputStream));
                        }
                        catch (PgpException e)
                        {
                            throw new IOException("can't create signature object: " + e);
                        }
                    }

                    return new PgpSignatureList(Signatures);

                }

                case PacketTag.SecretKey:
                    try
                    {
                        return new PgpSecretKeyRing(_BCPGInputStream);
                    }
                    catch (PgpException e)
                    {
                        throw new IOException("can't create secret key object: " + e);
                    }

                case PacketTag.PublicKey:
                    return new PgpPublicKeyRing(_BCPGInputStream);

                // TODO Make PgpPublicKey a PgpObject or return a PgpPublicKeyRing
                case PacketTag.PublicSubkey:
                    return new PgpPublicKeyRing(PgpPublicKeyRing.ReadSubkey(_BCPGInputStream));

                case PacketTag.CompressedData:
                    return new PgpCompressedData(_BCPGInputStream);

                case PacketTag.LiteralData:
                    return new PgpLiteralData(_BCPGInputStream);

                case PacketTag.PublicKeyEncryptedSession:
                case PacketTag.SymmetricKeyEncryptedSessionKey:
                    return new PgpEncryptedDataList(_BCPGInputStream);

                case PacketTag.OnePassSignature:
                {

                    var OnePassSignatures = new List<PgpOnePassSignature>();

                    while (_BCPGInputStream.NextPacketTag() == PacketTag.OnePassSignature)
                    {
                        try
                        {
                            OnePassSignatures.Add(new PgpOnePassSignature(_BCPGInputStream));
                        }
                        catch (PgpException e)
                        {
                            throw new IOException("can't create one pass signature object: " + e);
                        }
                    }

                    return new PgpOnePassSignatureList(OnePassSignatures);

                }

                case PacketTag.Marker:
                    return new PgpMarker(_BCPGInputStream);

                case PacketTag.Experimental1:
                case PacketTag.Experimental2:
                case PacketTag.Experimental3:
                case PacketTag.Experimental4:
                    return new PgpExperimental(_BCPGInputStream);

            }

            throw new IOException("unknown object in stream " + _BCPGInputStream.NextPacketTag());

        }

        #endregion

    }

}
