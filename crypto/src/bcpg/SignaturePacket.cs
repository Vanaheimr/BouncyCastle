using System;
using System.IO;
using System.Collections.Generic;

using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Utilities.Date;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace Org.BouncyCastle.Bcpg
{

    /// <summary>
    /// http://tools.ietf.org/html/rfc4880#page-59
    /// 5.2.4. Computing Signatures
    /// </summary>
    //public enum SignatureTypes
    //{
    //    binary = 0x00,
    //    text   = 0x01
    //}


    /// <summary>
    /// A generic signature packet.
    /// </summary>
    public class SignaturePacket : ContainedPacket //, PublicKeyAlgorithmTag
    {

        #region Data

        private readonly Byte[]  fingerprint;
        private readonly Byte[]  signatureEncoding;

        #endregion

        #region Properties

        #region Version

        private readonly Int32 version;

        public Int32 Version
        {
            get
            {
                return version;
            }
        }

        #endregion

        #region SignatureType

        private readonly PgpSignatureTypes signatureType;

        public PgpSignatureTypes SignatureType
        {
            get
            {
                return signatureType;
            }
        }

        #endregion

        #region CreationTime

        private readonly Int64 creationTime;

        /// <summary>Return the creation time in milliseconds since 1 Jan., 1970 UTC.</summary>
        public Int64 CreationTime
        {
            get
            {
                return creationTime;
            }
        }

        #endregion

        #region KeyId

        private readonly UInt64 keyId;

        /// <summary>
        /// The identification of the key that created the signature.
        /// </summary>
        public UInt64 KeyId
        {
            get
            {
                return keyId;
            }
        }

        #endregion

        #region KeyAlgorithm

        private readonly PublicKeyAlgorithms keyAlgorithm;

        public PublicKeyAlgorithms KeyAlgorithm
        {
            get
            {
                return keyAlgorithm;
            }
        }

        #endregion

        #region HashAlgorithm

        private readonly HashAlgorithms hashAlgorithm;

        public HashAlgorithms HashAlgorithm
        {
            get
            {
                return hashAlgorithm;
            }
        }

        #endregion

        #region Signature

        private readonly MPInteger[] signature;

        /// <summary>
        /// The signature as a set of integers.
        /// Note this is normalised to be the ASN.1 encoding of what appears in the signature packet.
        /// </summary>
        public MPInteger[] Signature
        {
            get
            {
                return signature;
            }
        }

        #endregion

        #region HashedSubPackets

        private readonly IEnumerable<SignatureSubpacket> hashedSubPackets;

        public IEnumerable<SignatureSubpacket> HashedSubPackets
        {
            get
            {
                return hashedSubPackets;
            }
        }

        #endregion

        #region UnhashedSubPackets

        private readonly IEnumerable<SignatureSubpacket> unhashedSubPackets;

        public IEnumerable<SignatureSubpacket> UnhashedSubPackets
        {
            get
            {
                return unhashedSubPackets;
            }
        }

        #endregion

        #region SignatureTrailer

        /// <summary>
        /// The signature trailer that must be included with the data to reconstruct the signature.
        /// </summary>
        public Byte[] SignatureTrailer
        {

            get
            {

                #region version 3...

                if (version == 3)
                {

                    var trailer = new byte[5];

                    long time = creationTime / 1000L;

                    trailer[0] = (byte) signatureType;
                    trailer[1] = (byte) (time >> 24);
                    trailer[2] = (byte) (time >> 16);
                    trailer[3] = (byte) (time >>  8);
                    trailer[4] = (byte) (time);

                    return trailer;

                }

                #endregion

                #region ...or all other!

                else
                {

                    var sOut = new MemoryStream();
                    sOut.WriteByte((byte) this.Version);
                    sOut.WriteByte((byte) this.SignatureType);
                    sOut.WriteByte((byte) this.KeyAlgorithm);
                    sOut.WriteByte((byte) this.HashAlgorithm);

                    var hOut    = new MemoryStream();

                    foreach (var hashed in this.HashedSubPackets)
                        hashed.Encode(hOut);

                    //var hashed  = this.HashedSubPackets;
                    //
                    //for (var i = 0; i != hashed.Length; i++)
                    //    hashed[i].Encode(hOut);

                    byte[] data = hOut.ToArray();
                    sOut.WriteByte((byte) (data.Length >> 8));
                    sOut.WriteByte((byte)  data.Length);
                    sOut.Write(data, 0, data.Length);

                    byte[] hData = sOut.ToArray();
                    sOut.WriteByte((byte) this.Version);
                    sOut.WriteByte((byte) 0xff);
                    sOut.WriteByte((byte) (hData.Length >> 24));
                    sOut.WriteByte((byte) (hData.Length >> 16));
                    sOut.WriteByte((byte) (hData.Length >>  8));
                    sOut.WriteByte((byte) (hData.Length));

                    return sOut.ToArray();

                }

                #endregion

            }

        }

        #endregion

        #endregion

        #region Constructor(s)

        #region (internal) SignaturePacket(BcpgInputStream)

        internal SignaturePacket(BcpgInputStream bcpgIn)
        {

            version = (Byte) bcpgIn.ReadByte();

            if (version == 3 || version == 2)
            {

                bcpgIn.ReadByte();

                signatureType = (PgpSignatureTypes) bcpgIn.ReadByte();
                creationTime  = (((long) bcpgIn.ReadByte() << 24) |
                                 ((long) bcpgIn.ReadByte() << 16) |
                                 ((long) bcpgIn.ReadByte() <<  8) |
                                  (uint) bcpgIn.ReadByte()) * 1000L;

                keyId |= (UInt64) bcpgIn.ReadByte() << 56;
                keyId |= (UInt64) bcpgIn.ReadByte() << 48;
                keyId |= (UInt64) bcpgIn.ReadByte() << 40;
                keyId |= (UInt64) bcpgIn.ReadByte() << 32;
                keyId |= (UInt64) bcpgIn.ReadByte() << 24;
                keyId |= (UInt64) bcpgIn.ReadByte() << 16;
                keyId |= (UInt64) bcpgIn.ReadByte() <<  8;
                keyId |= (UInt32) bcpgIn.ReadByte();

                keyAlgorithm   = (PublicKeyAlgorithms) bcpgIn.ReadByte();
                hashAlgorithm  = (HashAlgorithms)      bcpgIn.ReadByte();

            }

            else if (version == 4)
            {

                signatureType     = (PgpSignatureTypes)       bcpgIn.ReadByte();
                keyAlgorithm      = (PublicKeyAlgorithms) bcpgIn.ReadByte();
                hashAlgorithm     = (HashAlgorithms)      bcpgIn.ReadByte();

                var hashedLength  = (bcpgIn.ReadByte() << 8) |
                                     bcpgIn.ReadByte();

                var hashed        = new byte[hashedLength];

                bcpgIn.ReadFully(hashed);


                // read the signature sub packet data.
                var sIn = new SignatureSubpacketsParser(new MemoryStream(hashed, false));

                var SignatureSubpacketList = new List<SignatureSubpacket>();
                SignatureSubpacket sub;
                while ((sub = sIn.ReadPacket()) != null)
                {
                    SignatureSubpacketList.Add(sub);
                }


                var _hashedSubPackets = new List<SignatureSubpacket>();

                foreach (var _SignatureSubpacket in SignatureSubpacketList)
                {

                    if (_SignatureSubpacket is IssuerKeyId)
                        keyId = ((IssuerKeyId) _SignatureSubpacket).KeyId;

                    else if (_SignatureSubpacket is SignatureCreationTime)
                        creationTime = (Int64) DateTimeUtilities.DateTimeToUnixMs(((SignatureCreationTime) _SignatureSubpacket).Time);

                    _hashedSubPackets.Add(_SignatureSubpacket);

                }

                this.hashedSubPackets = _hashedSubPackets;



                int unhashedLength = (bcpgIn.ReadByte() << 8) |
                                      bcpgIn.ReadByte();

                byte[] unhashed = new byte[unhashedLength];

                bcpgIn.ReadFully(unhashed);

                sIn = new SignatureSubpacketsParser(new MemoryStream(unhashed, false));

                SignatureSubpacketList.Clear();

                while ((sub = sIn.ReadPacket()) != null)
                    SignatureSubpacketList.Add(sub);



                var _unhashedSubPackets = new List<SignatureSubpacket>();

                foreach (var _SignatureSubpacket in SignatureSubpacketList)
                {

                    if (_SignatureSubpacket is IssuerKeyId)
                        keyId = ((IssuerKeyId) _SignatureSubpacket).KeyId;

                    _unhashedSubPackets.Add(_SignatureSubpacket);

                }

                this.unhashedSubPackets = _unhashedSubPackets;


            }

            else
                throw new Exception("unsupported version: " + version);


            fingerprint = new byte[2];
            bcpgIn.ReadFully(fingerprint);

            switch (keyAlgorithm)
            {

                case PublicKeyAlgorithms.RsaGeneral:
                case PublicKeyAlgorithms.RsaSign:
                    var v = new MPInteger(bcpgIn);
                    signature = new MPInteger[]{ v };
                    break;

                case PublicKeyAlgorithms.Dsa:
                    var r = new MPInteger(bcpgIn);
                    var s = new MPInteger(bcpgIn);
                    signature = new MPInteger[]{ r, s };
                    break;

                case PublicKeyAlgorithms.ElGamalEncrypt: // yep, this really happens sometimes!
                case PublicKeyAlgorithms.ElGamalGeneral:
                    var p = new MPInteger(bcpgIn);
                    var g = new MPInteger(bcpgIn);
                    var y = new MPInteger(bcpgIn);
                    signature = new MPInteger[]{ p, g, y };
                    break;

                default:

                    if (keyAlgorithm >= PublicKeyAlgorithms.Experimental_1 &&
                        keyAlgorithm <= PublicKeyAlgorithms.Experimental_11)
                    {

                        signature = null;
                        var bOut  = new MemoryStream();
                        int ch;

                        while ((ch = bcpgIn.ReadByte()) >= 0)
                            bOut.WriteByte((byte) ch);

                        signatureEncoding = bOut.ToArray();

                    }

                    else
                        throw new IOException("unknown signature key algorithm: " + keyAlgorithm);

                    break;

            }

        }

        #endregion

        #region SignaturePacket(...version 4...)

        /// <summary>
        /// Generate a version 4 signature packet.
        /// </summary>
        public SignaturePacket(PgpSignatureTypes                    signatureType,
                               UInt64                           keyId,
                               PublicKeyAlgorithms              keyAlgorithm,
                               HashAlgorithms                   hashAlgorithm,
                               IEnumerable<SignatureSubpacket>  hashedData,
                               IEnumerable<SignatureSubpacket>  unhashedData,
                               Byte[]                           fingerprint,
                               MPInteger[]                      signature)

            : this(4, signatureType, keyId, keyAlgorithm, hashAlgorithm, hashedData, unhashedData, fingerprint, signature)

        { }

        #endregion

        #region SignaturePacket(...version 2/3...)

        /// <summary>
        /// Generate a version 2/3 signature packet.
        /// </summary>
        public SignaturePacket(Byte                 version,
                               PgpSignatureTypes        signatureType,
                               UInt64               keyId,
                               PublicKeyAlgorithms  keyAlgorithm,
                               HashAlgorithms       hashAlgorithm,
                               Int64                creationTime,
                               Byte[]               fingerprint,
                               MPInteger[]          signature)

            : this(version, signatureType, keyId, keyAlgorithm, hashAlgorithm, null, null, fingerprint, signature)

        {
            this.creationTime = creationTime;
        }

        #endregion

        #region SignaturePacket(...)

        public SignaturePacket(Byte                             version,
                               PgpSignatureTypes                signatureType,
                               UInt64                           keyId,
                               PublicKeyAlgorithms              keyAlgorithm,
                               HashAlgorithms                   hashAlgorithm,
                               IEnumerable<SignatureSubpacket>  hashedData,
                               IEnumerable<SignatureSubpacket>  unhashedData,
                               Byte[]                           fingerprint,
                               MPInteger[]                      signature)
        {

            this.version             = version;
            this.signatureType       = signatureType;
            this.keyId               = keyId;
            this.keyAlgorithm        = keyAlgorithm;
            this.hashAlgorithm       = hashAlgorithm;
            this.hashedSubPackets    = hashedData;
            this.unhashedSubPackets  = unhashedData;
            this.fingerprint         = fingerprint;
            this.signature           = signature;

            if (hashedData != null)
            {
                foreach (var SignatureSubpacket in hashedData)
                {
                    if (SignatureSubpacket is SignatureCreationTime)
                    {
                        creationTime = (Int64) DateTimeUtilities.DateTimeToUnixMs(((SignatureCreationTime)SignatureSubpacket).Time);
                        break;
                    }
                }
            }

        }

        #endregion

        #endregion


        #region GetSignatureBytes()

        /// <summary>
        /// Return the byte encoding of the signature section.
        /// </summary>
        public Byte[] GetSignatureBytes()
        {

            if (signatureEncoding != null)
                return (byte[]) signatureEncoding.Clone();

            var OutputStream         = new MemoryStream();
            var WrappedOutputStream  = new BcpgOutputStream(OutputStream);

            foreach (MPInteger sigObj in signature)
            {
                try
                {
                    WrappedOutputStream.WriteObject(sigObj);
                }
                catch (IOException e)
                {
                    throw new Exception("internal error: " + e);
                }
            }

            return OutputStream.ToArray();

        }

        #endregion

        #region Encode(BCPGOutputStream)

        public override void Encode(BcpgOutputStream BCPGOutputStream)
        {

            var OutputStream         = new MemoryStream();
            var WrappedOutputStream  = new BcpgOutputStream(OutputStream);

            WrappedOutputStream.WriteByte((byte) version);

            #region Version 2/3...

            if (version == 3 || version == 2)
            {

                // 5 == the length of the next block
                WrappedOutputStream.Write(5, (byte) signatureType);

                WrappedOutputStream.WriteInt((int)(creationTime / 1000L));

                WrappedOutputStream.WriteULong(keyId);

                WrappedOutputStream.Write((byte) keyAlgorithm,
                                          (byte) hashAlgorithm);

            }

            #endregion

            #region Version 4

            else if (version == 4)
            {

                WrappedOutputStream.Write((byte) signatureType,
                                          (byte) keyAlgorithm,
                                          (byte) hashAlgorithm);

                EncodeLengthAndData(WrappedOutputStream, GetEncodedSubpackets(hashedSubPackets));
                EncodeLengthAndData(WrappedOutputStream, GetEncodedSubpackets(unhashedSubPackets));

            }

            #endregion

            else
                throw new IOException("unknown version: " + version);


            WrappedOutputStream.Write(fingerprint);

            if (signature != null)
                WrappedOutputStream.WriteObjects(signature);
            else
                WrappedOutputStream.Write(signatureEncoding);

            BCPGOutputStream.WritePacket(PacketTag.Signature, OutputStream.ToArray(), true);

        }

        #endregion


        #region (private) EncodeLengthAndData(BCPGOutputStream, Data)

        private static void EncodeLengthAndData(BcpgOutputStream  BCPGOutputStream,
                                                Byte[]            Data)
        {
            BCPGOutputStream.WriteShort((short) Data.Length);
            BCPGOutputStream.Write(Data);
        }

        #endregion

        #region (private) GetEncodedSubpackets(SignatureSubpackets)

        private static Byte[] GetEncodedSubpackets(IEnumerable<SignatureSubpacket> SignatureSubpackets)
        {

            var OutputStream = new MemoryStream();

            foreach (var SignatureSubpacket in SignatureSubpackets)
                SignatureSubpacket.Encode(OutputStream);

            return OutputStream.ToArray();

        }

        #endregion


    }

}
