using System;
using System.IO;
using System.Diagnostics;
using System.Collections.Generic;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    /// <summary>
    /// Generator for encrypted objects.
    /// </summary>
    public class PgpEncryptedDataGenerator : IStreamGenerator
    {

        #region Data

        private          BcpgOutputStream        _BCPGOutputStream;
        private          CipherStream            _CipherStream;
        private          IBufferedCipher         _Cipher;
        private          Boolean                 _WithIntegrityPacket;
        private          Boolean                 _UseOldFormat;
        private          DigestStream            _DigestOutputStream;

        private readonly List<EncMethod>         _Methods;
        private readonly SymmetricKeyAlgorithms  _EncryptionAlgorithm;
        private readonly SecureRandom            _SecureRandom;

        #endregion

        #region (private abstract class) EncMethod

        private abstract class EncMethod : ContainedPacket
        {

            protected Byte[]                  _SessionInfo;
            protected SymmetricKeyAlgorithms  _EncryptionAlgorithm;
            protected KeyParameter            _KeyParameter;

            public abstract void AddSessionInfo(Byte[] si, SecureRandom random);

        }

        #endregion

        #region (private class) PubMethod

        private class PbeMethod : EncMethod
        {

            #region Data

            private readonly S2k _S2k;

            #endregion

            #region Properties

            #region Key

            public KeyParameter Key
            {
                get
                {
                    return _KeyParameter;
                }
            }

            #endregion

            #endregion

            #region Constructor(s)

            internal PbeMethod(SymmetricKeyAlgorithms  EncryptionAlgorithm,
                               S2k                     s2k,
                               KeyParameter            KeyParameter)
            {
                this._EncryptionAlgorithm  = EncryptionAlgorithm;
                this._S2k                  = s2k;
                this._KeyParameter         = KeyParameter;
            }

            #endregion


            #region AddSessionInfo(BCPGOutputStream)

            public override void AddSessionInfo(Byte[]        SessionInfo,
                                                SecureRandom  SecureRandom)
            {

                var CipherName  = PgpUtilities.GetSymmetricCipherName(_EncryptionAlgorithm);
                var Cipher      = CipherUtilities.GetCipher(CipherName + "/CFB/NoPadding");
                var InitVector  = new Byte[Cipher.GetBlockSize()];

                Cipher.Init(ForEncryption: true,
                            Parameters:    new ParametersWithRandom(new ParametersWithIV(_KeyParameter, InitVector), SecureRandom));

                this._SessionInfo = Cipher.DoFinal(SessionInfo, 0, SessionInfo.Length - 2);

            }

            #endregion

            #region Encode(BCPGOutputStream)

            public override void Encode(BcpgOutputStream BCPGOutputStream)
            {
                BCPGOutputStream.WritePacket(new SymmetricKeyEncSessionPacket(_EncryptionAlgorithm, _S2k, _SessionInfo));
            }

            #endregion

        }

        #endregion

        #region (private class) PubMethod

        private class PubMethod : EncMethod
        {

            #region Data

            internal readonly PgpPublicKey  PublicKey;
            internal          BigInteger[]  SessionData;

            #endregion

            #region Constructor(s)

            internal PubMethod(PgpPublicKey PublicKey)
            {
                this.PublicKey = PublicKey;
            }

            #endregion

            #region AddSessionInfo(SessionInfo, SecureRandom)

            public override void AddSessionInfo(Byte[]        SessionInfo,
                                                SecureRandom  SecureRandom)
            {

                IBufferedCipher Cipher;

                switch (PublicKey.Algorithm)
                {

                    case PublicKeyAlgorithms.RsaEncrypt:
                    case PublicKeyAlgorithms.RsaGeneral:
                        Cipher = CipherUtilities.GetCipher("RSA//PKCS1Padding");
                        break;

                    case PublicKeyAlgorithms.ElGamalEncrypt:
                    case PublicKeyAlgorithms.ElGamalGeneral:
                        Cipher = CipherUtilities.GetCipher("ElGamal/ECB/PKCS1Padding");
                        break;

                    case PublicKeyAlgorithms.Dsa:
                        throw new PgpException("Can't use DSA for encryption.");

                    case PublicKeyAlgorithms.ECDsa:
                        throw new PgpException("Can't use ECDSA for encryption.");

                    default:
                        throw new PgpException("Unknown asymmetric algorithm: " + PublicKey.Algorithm);

                }

                Cipher.Init(ForEncryption: true,
                            Parameters:    new ParametersWithRandom(PublicKey.Key, SecureRandom));

                var EncryptionKey = Cipher.DoFinal(SessionInfo);

                switch (PublicKey.Algorithm)
                {

                    case PublicKeyAlgorithms.RsaEncrypt:
                    case PublicKeyAlgorithms.RsaGeneral:
                        SessionData = new BigInteger[]{ new BigInteger(1, EncryptionKey) };
                        break;

                    case PublicKeyAlgorithms.ElGamalEncrypt:
                    case PublicKeyAlgorithms.ElGamalGeneral:
                        var halfLength = EncryptionKey.Length / 2;
                        SessionData = new BigInteger[] {
                            new BigInteger(1, EncryptionKey, 0,          halfLength),
                            new BigInteger(1, EncryptionKey, halfLength, halfLength)
                        };
                        break;

                    default:
                        throw new PgpException("unknown asymmetric algorithm: " + _EncryptionAlgorithm);

                }

            }

            #endregion

            #region Encode(BCPGOutputStream)

            public override void Encode(BcpgOutputStream BCPGOutputStream)
            {
                BCPGOutputStream.WritePacket(new PublicKeyEncSessionPacket(PublicKey.KeyId, PublicKey.Algorithm, SessionData));
            }

            #endregion

        }

        #endregion


        #region Constructor(s)

        #region PgpEncryptedDataGenerator(EncryptionAlgorithm)

        public PgpEncryptedDataGenerator(SymmetricKeyAlgorithms EncryptionAlgorithm)
        {
            this._EncryptionAlgorithm  = EncryptionAlgorithm;
            this._SecureRandom         = new SecureRandom();
            this._Methods              = new List<EncMethod>();
        }

        #endregion

        #region PgpEncryptedDataGenerator(EncryptionAlgorithm, SecureRandom)

        /// <summary>
        /// Existing SecureRandom constructor.
        /// </summary>
        /// <param name="EncryptionAlgorithm">The symmetric algorithm to use.</param>
        /// <param name="SecureRandom">Source of randomness.</param>
        public PgpEncryptedDataGenerator(SymmetricKeyAlgorithms  EncryptionAlgorithm,
                                         SecureRandom            SecureRandom)
        {
            this._EncryptionAlgorithm  = EncryptionAlgorithm;
            this._SecureRandom         = SecureRandom;
            this._Methods              = new List<EncMethod>();
        }

        #endregion

        #region PgpEncryptedDataGenerator(EncryptionAlgorithm, WithIntegrityPacket, SecureRandom)

        /// <summary>
        /// Creates a cipher stream which will have an integrity packet associated with it.
        /// </summary>
        /// <param name="EncryptionAlgorithm">The symmetric algorithm to use.</param>
        /// <param name="WithIntegrityPacket"></param>
        /// <param name="SecureRandom">Source of randomness.</param>
        /// <param name="UseOldFormat">PGP 2.6.x compatibility required.</param>
        public PgpEncryptedDataGenerator(SymmetricKeyAlgorithms  EncryptionAlgorithm,
                                         Boolean                 WithIntegrityPacket,
                                         SecureRandom            SecureRandom = null,
                                         Boolean                 UseOldFormat = false)
        {
            this._EncryptionAlgorithm  = EncryptionAlgorithm;
            this._WithIntegrityPacket  = WithIntegrityPacket;
            this._SecureRandom         = SecureRandom != null ? SecureRandom : new SecureRandom();
            this._UseOldFormat         = UseOldFormat;
            this._Methods              = new List<EncMethod>();
        }

        #endregion

        #endregion


        #region AddMethod(Passphrase)

        /// <summary>
        /// Add a PBE encryption method to the encrypted object using the default algorithm (S2K_SHA1).
        /// </summary>
        public void AddMethod(String Passphrase) 
        {
            AddMethod(Passphrase, HashAlgorithms.Sha1);
        }

        #endregion

        #region AddMethod(Passphrase, S2kDigest)

        /// <summary>
        /// Add a PBE encryption method to the encrypted object.
        /// </summary>
        public void AddMethod(String          Passphrase,
                              HashAlgorithms  S2kDigest)
        {

            var InitVector = new Byte[8];
            _SecureRandom.NextBytes(InitVector);

            var s2k = new S2k(S2kDigest, InitVector, 0x60);

            _Methods.Add(new PbeMethod(_EncryptionAlgorithm, s2k, PgpUtilities.MakeKeyFromPassPhrase(_EncryptionAlgorithm, s2k, Passphrase)));

        }

        #endregion

        #region AddMethod(PublicKey)

        /// <summary>
        /// Add a public key encrypted session key to the encrypted object.
        /// </summary>
        public void AddMethod(PgpPublicKey PublicKey)
        {

            if (!PublicKey.IsEncryptionKey)
                throw new ArgumentException("passed in key not an encryption key!");

            _Methods.Add(new PubMethod(PublicKey));

        }

        #endregion


        #region (private) AddCheckSum(SessionInfo)

        private void AddCheckSum(Byte[] SessionInfo)
        {

            Debug.Assert(SessionInfo        != null);
            Debug.Assert(SessionInfo.Length >= 3);

            int check = 0;

            for (var i = 1; i < SessionInfo.Length - 2; i++)
                check += SessionInfo[i];

            SessionInfo[SessionInfo.Length - 2] = (byte) (check >> 8);
            SessionInfo[SessionInfo.Length - 1] = (byte) (check);

        }

        #endregion

        #region (private) CreateSessionInfo(SymmetricKeyAlgorithm, KeyParameter)

        private Byte[] CreateSessionInfo(SymmetricKeyAlgorithms  SymmetricKeyAlgorithm,
                                         KeyParameter            KeyParameter)
        {

            var keyBytes = KeyParameter.GetKey();
            var sessionInfo = new Byte[keyBytes.Length + 3];
            sessionInfo[0] = (byte) SymmetricKeyAlgorithm;
            keyBytes.CopyTo(sessionInfo, 1);
            AddCheckSum(sessionInfo);

            return sessionInfo;

        }

        #endregion

        #region (private) Open(OutputStream, Length, Buffer)

        /// <summary>
        /// <p>
        /// If buffer is non null stream assumed to be partial, otherwise the length will be used
        /// to output a fixed length packet.
        /// </p>
        /// <p>
        /// The stream created can be closed off by either calling Close()
        /// on the stream or Close() on the generator. Closing the returned
        /// stream does not close off the Stream parameter <c>outStr</c>.
        /// </p>
        /// </summary>
        private Stream Open(Stream  OutputStream,
                            UInt64  Length,
                            Byte[]  Buffer)
        {

            if (_CipherStream != null)
                throw new InvalidOperationException("generator already in open state");

            if (_Methods.Count == 0)
                throw new InvalidOperationException("No encryption methods specified");

            if (OutputStream == null)
                throw new ArgumentNullException("outStr");

            _BCPGOutputStream = new BcpgOutputStream(OutputStream);

            KeyParameter key;

            if (_Methods.Count == 1)
            {

                if (_Methods[0] is PbeMethod)
                {
                    var m = (PbeMethod) _Methods[0];
                    key = m.Key;
                }

                else
                {

                    key              = PgpUtilities.MakeRandomKey(_EncryptionAlgorithm, _SecureRandom);
                    var sessionInfo  = CreateSessionInfo(_EncryptionAlgorithm, key);
                    var m            = (PubMethod)_Methods[0];

                    try
                    {
                        m.AddSessionInfo(sessionInfo, _SecureRandom);
                    }
                    catch (Exception e)
                    {
                        throw new PgpException("Exception encrypting session key", e);
                    }

                }

                _BCPGOutputStream.WritePacket((ContainedPacket) _Methods[0]);

            }

            else // multiple methods
            {

                key              = PgpUtilities.MakeRandomKey(_EncryptionAlgorithm, _SecureRandom);
                var sessionInfo  = CreateSessionInfo(_EncryptionAlgorithm, key);

                for (var i = 0; i != _Methods.Count; i++)
                {

                    var m  = (EncMethod) _Methods[i];

                    try
                    {
                        m.AddSessionInfo(sessionInfo, _SecureRandom);
                    }
                    catch (Exception e)
                    {
                        throw new PgpException("exception encrypting session key", e);
                    }

                    _BCPGOutputStream.WritePacket(m);

                }

            }

            var cName = PgpUtilities.GetSymmetricCipherName(_EncryptionAlgorithm);
            if (cName == null)
                throw new PgpException("null cipher specified");

            try
            {

                if (_WithIntegrityPacket)
                    cName += "/CFB/NoPadding";

                else
                    cName += "/OpenPGPCFB/NoPadding";

                _Cipher = CipherUtilities.GetCipher(cName);

                // TODO Confirm the IV should be all zero bytes (not inLineIv - see below)
                var iv = new Byte[_Cipher.GetBlockSize()];
                _Cipher.Init(true, new ParametersWithRandom(new ParametersWithIV(key, iv), _SecureRandom));

                if (Buffer == null)
                {

                    // we have to Add block size + 2 for the Generated IV and + 1 + 22 if integrity protected
                    if (_WithIntegrityPacket)
                    {
                        _BCPGOutputStream = new BcpgOutputStream(OutputStream, PacketTag.SymmetricEncryptedIntegrityProtected, Length + (UInt64) _Cipher.GetBlockSize() + 2 + 1 + 22);
                        _BCPGOutputStream.WriteByte(1);        // version number
                    }

                    else
                        _BCPGOutputStream = new BcpgOutputStream(OutputStream, PacketTag.SymmetricKeyEncrypted, Length + (UInt64) _Cipher.GetBlockSize() + 2, _UseOldFormat);

                }
                else
                {

                    if (_WithIntegrityPacket)
                    {
                        _BCPGOutputStream = new BcpgOutputStream(OutputStream, PacketTag.SymmetricEncryptedIntegrityProtected, Buffer);
                        _BCPGOutputStream.WriteByte(1);        // version number
                    }

                    else
                        _BCPGOutputStream = new BcpgOutputStream(OutputStream, PacketTag.SymmetricKeyEncrypted, Buffer);

                }

                var blockSize  = _Cipher.GetBlockSize();
                var inLineIv   = new Byte[blockSize + 2];
                _SecureRandom.NextBytes(inLineIv, 0, blockSize);
                Array.Copy(inLineIv, inLineIv.Length - 4, inLineIv, inLineIv.Length - 2, 2);

                Stream _OutputStream = _CipherStream = new CipherStream(_BCPGOutputStream, null, _Cipher);

                if (_WithIntegrityPacket)
                    _OutputStream = _DigestOutputStream = new DigestStream(_OutputStream, null, DigestUtilities.GetDigest(PgpUtilities.GetDigestName(HashAlgorithms.Sha1)));

                _OutputStream.Write(inLineIv, 0, inLineIv.Length);

                return new WrappedGeneratorStream(this, _OutputStream);

            }
            catch (Exception e)
            {
                throw new PgpException("Exception creating cipher", e);
            }

        }

        #endregion

        #region Open(OutputStream, Length)

        /// <summary>
        /// <p>
        /// Return an output stream which will encrypt the data as it is written to it.
        /// </p>
        /// <p>
        /// The stream created can be closed off by either calling Close()
        /// on the stream or Close() on the generator. Closing the returned
        /// stream does not close off the Stream parameter <c>outStr</c>.
        /// </p>
        /// </summary>
        public Stream Open(Stream  OutputStream,
                           UInt64  Length)
        {
            return Open(OutputStream, Length, null);
        }

        #endregion

        #region Open(OutputStream, Length)

        /// <summary>
        /// <p>
        /// Return an output stream which will encrypt the data as it is written to it.
        /// The stream will be written out in chunks according to the size of the passed in buffer.
        /// </p>
        /// <p>
        /// The stream created can be closed off by either calling Close()
        /// on the stream or Close() on the generator. Closing the returned
        /// stream does not close off the Stream parameter <c>outStr</c>.
        /// </p>
        /// <p>
        /// <b>Note</b>: if the buffer is not a power of 2 in length only the largest power of 2
        /// bytes worth of the buffer will be used.
        /// </p>
        /// </summary>
        public Stream Open(Stream  OutputStream,
                           Byte[]  Buffer)
        {
            return Open(OutputStream, 0, Buffer);
        }

        #endregion


        #region Close()

        /// <summary>
        /// <p>
        /// Close off the encrypted object - this is equivalent to calling Close() on the stream
        /// returned by the Open() method.
        /// </p>
        /// <p>
        /// <b>Note</b>: This does not close the underlying output stream, only the stream on top of
        /// it created by the Open() method.
        /// </p>
        /// </summary>
        public void Close()
        {

            if (_CipherStream != null)
            {

                // TODO Should this all be under the try/catch block?
                if (_DigestOutputStream != null)
                {

                    // hand code a mod detection packet
                    var BCPGOutputStream = new BcpgOutputStream(_DigestOutputStream, PacketTag.ModificationDetectionCode, 20);

                    BCPGOutputStream.Flush();
                    _DigestOutputStream.Flush();

                    // TODO
                    var dig = DigestUtilities.DoFinal(_DigestOutputStream.WriteDigest());
                    _CipherStream.Write(dig, 0, dig.Length);

                }

                _CipherStream.Flush();

                try
                {
                    _BCPGOutputStream.Write(_Cipher.DoFinal());
                    _BCPGOutputStream.Finish();
                }
                catch (Exception e)
                {
                    throw new IOException(e.Message, e);
                }

                _CipherStream = null;
                _BCPGOutputStream = null;

            }

        }

        #endregion

    }

}
