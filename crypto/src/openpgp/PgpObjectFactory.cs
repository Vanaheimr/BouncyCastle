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

        private readonly BcpgInputStream _BcpgInputStream;

        #endregion

        #region Constructor(s)

        public PgpObjectFactory(Stream inputStream)
        {
            this._BcpgInputStream = BcpgInputStream.Wrap(inputStream);
        }

        public PgpObjectFactory(Byte[] bytes)
            : this(new MemoryStream(bytes, false))
        { }

        #endregion


        /// <summary>Return the next object in the stream, or null if the end is reached.</summary>
        /// <exception cref="IOException">On a parse error</exception>
        public PgpObject NextPgpObject()
        {

            var tag = _BcpgInputStream.NextPacketTag();

            if ((int) tag == -1)
                return null;

            switch (tag)
            {

                case PacketTag.Signature:
                {

                    var Signatures = new List<PgpSignature>();

                    while (_BcpgInputStream.NextPacketTag() == PacketTag.Signature)
                    {
                        try
                        {
                            Signatures.Add(new PgpSignature(_BcpgInputStream));
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
                        return new PgpSecretKeyRing(_BcpgInputStream);
                    }
                    catch (PgpException e)
                    {
                        throw new IOException("can't create secret key object: " + e);
                    }

                case PacketTag.PublicKey:
                    return new PgpPublicKeyRing(_BcpgInputStream);
                // TODO Make PgpPublicKey a PgpObject or return a PgpPublicKeyRing
//                case PacketTag.PublicSubkey:
//                    return PgpPublicKeyRing.ReadSubkey(bcpgIn);

                case PacketTag.CompressedData:
                    return new PgpCompressedData(_BcpgInputStream);

                case PacketTag.LiteralData:
                    return new PgpLiteralData(_BcpgInputStream);

                case PacketTag.PublicKeyEncryptedSession:
                case PacketTag.SymmetricKeyEncryptedSessionKey:
                    return new PgpEncryptedDataList(_BcpgInputStream);

                case PacketTag.OnePassSignature:
                {

                    var OnePassSignatures = new List<PgpOnePassSignature>();

                    while (_BcpgInputStream.NextPacketTag() == PacketTag.OnePassSignature)
                    {
                        try
                        {
                            OnePassSignatures.Add(new PgpOnePassSignature(_BcpgInputStream));
                        }
                        catch (PgpException e)
                        {
                            throw new IOException("can't create one pass signature object: " + e);
                        }
                    }

                    return new PgpOnePassSignatureList(OnePassSignatures);

                }

                case PacketTag.Marker:
                    return new PgpMarker(_BcpgInputStream);

                case PacketTag.Experimental1:
                case PacketTag.Experimental2:
                case PacketTag.Experimental3:
                case PacketTag.Experimental4:
                    return new PgpExperimental(_BcpgInputStream);

            }

            throw new IOException("unknown object in stream " + _BcpgInputStream.NextPacketTag());

        }


        #region AllPgpObjects()

        /// <summary>
        /// Return all available objects.
        /// </summary>
        public IEnumerable<PgpObject> AllPgpObjects()
        {

            PgpObject pgpObject;

            while ((pgpObject = NextPgpObject()) != null)
            {
                yield return pgpObject;
            }

        }

        #endregion

    }

}
