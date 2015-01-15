using System;
using System.IO;
using System.Linq;
using System.Collections;
using System.Collections.Generic;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    /// <summary>
    /// General class to handle a PGP public key object.
    /// </summary>
    public class PgpPublicKey
    {

        private static readonly PgpSignatureTypes[] MasterKeyCertificationTypes = new PgpSignatureTypes[]
        {
            PgpSignatureTypes.PositiveCertification,
            PgpSignatureTypes.CasualCertification,
            PgpSignatureTypes.NoCertification,
            PgpSignatureTypes.DefaultCertification
        };

        #region Data

        private UInt64                     _KeyId;
        private Byte[]                     _Fingerprint;
        private UInt32                     _KeyStrength;

        internal readonly PublicKeyPacket           _PublicKeyPacket;
        internal readonly TrustPacket               _TrustPacket;

        internal readonly List<PgpSignature>        _KeySignatures;
        internal readonly List<Object>              _UserIds;
        internal readonly List<TrustPacket>         _idTrusts;
        internal readonly List<List<PgpSignature>>  _idSigs;
        internal readonly List<PgpSignature>        _SubSignatures;

        #endregion

        #region Properties

        #region KeyId

        /// <summary>
        /// The keyId associated with the public key.
        /// </summary>
        public UInt64 KeyId
        {
            get
            {
                return _KeyId;
            }
        }

        #endregion

        #region Version

        /// <summary>
        /// The version of this key.
        /// </summary>
        public Int32 Version
        {
            get
            {
                return _PublicKeyPacket.Version;
            }
        }

        #endregion

        #region CreationTime

        /// <summary>
        /// The creation time of this key.
        /// </summary>
        public DateTime CreationTime
        {
            get
            {
                return _PublicKeyPacket.Time;
            }
        }

        #endregion

        #region Algorithm

        /// <summary>
        /// The algorithm code associated with the public key.
        /// </summary>
        public PublicKeyAlgorithms Algorithm
        {
            get
            {
                return _PublicKeyPacket.Algorithm;
            }
        }

        #endregion

        #region BitStrength

        /// <summary>
        /// The strength of the key in bits.
        /// </summary>
        public UInt32 BitStrength
        {
            get
            {
                return _KeyStrength;
            }
        }

        #endregion

        #region IsRevoked

        /// <summary>Check whether this (sub)key has a revocation signature on it.</summary>
        /// <returns>True, if this (sub)key has been revoked.</returns>
        public Boolean IsRevoked
        {

            get
            {

                int ns = 0;

                // Master key
                if (IsMasterKey)
                {
                    while (ns < _KeySignatures.Count)
                    {
                        if (_KeySignatures[ns++].SignatureType == PgpSignatureTypes.KeyRevocation)
                            return true;
                    }
                }

                // Sub-key
                while (ns < _SubSignatures.Count)
                {
                    if ((_SubSignatures[ns++]).SignatureType == PgpSignatureTypes.SubkeyRevocation)
                        return true;
                }

                return false;

            }

        }

        #endregion

        #region IsEncryptionKey

        /// <summary>
        /// Check if this key has an algorithm type that makes it suitable to use for encryption.
        /// </summary>
        /// <remarks>
        /// Note: with version 4 keys KeyFlags subpackets should also be considered when present for
        /// determining the preferred use of the key.
        /// </remarks>
        /// <returns>
        /// <c>true</c> if this key algorithm is suitable for encryption.
        /// </returns>
        public Boolean IsEncryptionKey
        {
            get
            {
                switch (_PublicKeyPacket.Algorithm)
                {

                    case PublicKeyAlgorithms.ElGamalEncrypt:
                    case PublicKeyAlgorithms.ElGamalGeneral:
                    case PublicKeyAlgorithms.RsaEncrypt:
                    case PublicKeyAlgorithms.RsaGeneral:
                        return true;

                    default:
                        return false;

                }
            }
        }

        #endregion

        #region IsMasterKey

        /// <summary>
        /// True, if this is a master key.
        /// </summary>
        public Boolean IsMasterKey
        {
            get
            {
                return _SubSignatures.Count == 0;
            }
        }

        #endregion

        #region ValidDays

        /// <summary>
        /// The number of valid days from creation time - zero means no expiry.
        /// </summary>
        public UInt32 ValidDays
        {
            get
            {

                if (_PublicKeyPacket.Version > 3)
                    return (UInt32) (ValidSeconds / (24 * 60 * 60));

                return (UInt32) _PublicKeyPacket.ValidDays;

            }
        }

        #endregion

        #region ValidSeconds

        /// <summary>
        /// The number of valid seconds from creation time - zero means no expiry.
        /// </summary>
        public UInt64 ValidSeconds
        {

            get
            {

                if (_PublicKeyPacket.Version > 3)
                {

                    if (IsMasterKey)
                    {
                        for (int i = 0; i != MasterKeyCertificationTypes.Length; i++)
                        {

                            var seconds = GetExpirationTimeFromSignature(true, MasterKeyCertificationTypes[i]);

                            if (seconds >= 0)
                                return seconds;

                        }
                    }
                    else
                    {

                        var seconds = GetExpirationTimeFromSignature(false, PgpSignatureTypes.SubkeyBinding);

                        if (seconds >= 0)
                            return seconds;

                    }

                    return 0;

                }

                return (UInt64) _PublicKeyPacket.ValidDays * 24 * 60 * 60;

            }

        }

        #endregion

        #region IsExpired

        /// <summary>
        /// Checks if the public key is already expired,
        /// if an expiration timestamp was defined.
        /// </summary>
        public Boolean IsExpired
        {
            get
            {

                var _ValidSeconds = _PublicKeyPacket.Version > 3
                                        ? ValidSeconds
                                        : _PublicKeyPacket.ValidDays * (24 * 60 * 60);

                return _ValidSeconds > 0
                           ? (DateTime.Now - CreationTime).TotalSeconds >= _ValidSeconds
                           : false;

            }
        }

        #endregion

        #region ExpiresAt

        /// <summary>
        /// Returns the expiration timestamp of the public key,
        /// if an expiration timestamp was defined.
        /// </summary>
        public DateTime? ExpiresAt
        {
            get
            {

                var _ValidSeconds = _PublicKeyPacket.Version > 3
                                        ? ValidSeconds
                                        : _PublicKeyPacket.ValidDays * (24 * 60 * 60);

                return _ValidSeconds > 0
                           ? new Nullable<DateTime>(CreationTime.AddSeconds(_ValidSeconds))
                           : new Nullable<DateTime>();

            }
        }

        #endregion

        #region TrustData

        /// <summary>
        /// Return the trust data associated with the public key, if present.
        /// </summary>
        public Byte[] TrustData
        {

            get
            {

                if (_TrustPacket == null)
                    return new Byte[0];

                return _TrustPacket.GetLevelAndTrustAmount();

            }

        }

        #endregion

        #region Fingerprint

        /// <summary>
        /// The fingerprint of the key
        /// </summary>
        public Byte[] Fingerprint
        {
            get
            {
                return _Fingerprint;
            }
        }

        #endregion

        #region Key

        /// <summary>
        /// The public key contained in the object.
        /// </summary>
        public AsymmetricKeyParameter Key
        {

            get
            {

                try
                {

                    switch (_PublicKeyPacket.Algorithm)
                    {

                        case PublicKeyAlgorithms.RsaEncrypt:
                        case PublicKeyAlgorithms.RsaGeneral:
                        case PublicKeyAlgorithms.RsaSign:
                            var rsaK = _PublicKeyPacket.Key as RsaPublicBcpgKey;
                            return new RsaKeyParameters(false, rsaK.Modulus, rsaK.PublicExponent);

                        case PublicKeyAlgorithms.Dsa:
                            var dsaK = _PublicKeyPacket.Key as DsaPublicBcpgKey;
                            return new DsaPublicKeyParameters(dsaK.Y, new DsaParameters(dsaK.P, dsaK.Q, dsaK.G));

                        case PublicKeyAlgorithms.ElGamalEncrypt:
                        case PublicKeyAlgorithms.ElGamalGeneral:
                            var elK = _PublicKeyPacket.Key as ElGamalPublicBcpgKey;
                            return new ElGamalPublicKeyParameters(elK.Y, new ElGamalParameters(elK.P, elK.G));

                        default:
                            throw new PgpException("unknown public key algorithm encountered");

                    }

                }
                catch (PgpException e)
                {
                    throw e;
                }
                catch (Exception e)
                {
                    throw new PgpException("exception constructing public key", e);
                }

            }

        }

        #endregion

        #region UserIds

        /// <summary>
        /// Allows enumeration of any user IDs associated with the key.
        /// </summary>
        /// <returns>An <c>IEnumerable</c> of <c>string</c> objects.</returns>
        public IEnumerable<String> UserIds
        {
            get
            {
                return _UserIds.Where(item => item is String).
                                Cast<String>();
            }
        }

        #endregion

        #region Signatures

        /// <summary>
        /// Allows enumeration of all signatures/certifications associated with this key.
        /// </summary>
        public IEnumerable<PgpSignature> Signatures
        {
            get
            {
                return _KeySignatures.Concat(_idSigs.SelectMany(v => v));
            }
        }

        #endregion

        #region UserAttributes

        /// <summary>
        /// Allows enumeration of any user attribute vectors associated with the key.
        /// </summary>
        public IEnumerable<PgpUserAttributeSubpacketVector> UserAttributes
        {
            get
            {
                return _UserIds.Where(item => item is PgpUserAttributeSubpacketVector).
                                Cast<PgpUserAttributeSubpacketVector>();
            }
        }

        #endregion

        #endregion

        #region Constructor(s)

        #region PgpPublicKey(Algorithm, AsymKeyParameter, CreationTime)

        /// <summary>
        /// Create a PgpPublicKey from the passed in lightweight one.
        /// </summary>
        /// <remarks>
        /// Note: the time passed in affects the value of the key's keyId, so you probably only want
        /// to do this once for a lightweight key, or make sure you keep track of the time you used.
        /// </remarks>
        /// <param name="Algorithm">Asymmetric algorithm type representing the public key.</param>
        /// <param name="AsymKeyParameter">Actual public key to associate.</param>
        /// <param name="CreationTime">Date of creation.</param>
        /// <exception cref="ArgumentException">If <c>pubKey</c> is not public.</exception>
        /// <exception cref="PgpException">On key creation problem.</exception>
        public PgpPublicKey(PublicKeyAlgorithms     Algorithm,
                            AsymmetricKeyParameter  AsymKeyParameter,
                            DateTime                CreationTime)
        {

            if (AsymKeyParameter.IsPrivate)
                throw new ArgumentException("Expected a public key", "pubKey");

            IBcpgKey bcpgKey;

            if (AsymKeyParameter is RsaKeyParameters)
            {
                var rK = (RsaKeyParameters) AsymKeyParameter;
                bcpgKey = new RsaPublicBcpgKey(rK.Modulus, rK.Exponent);
            }

            else if (AsymKeyParameter is DsaPublicKeyParameters)
            {
                var dK = (DsaPublicKeyParameters) AsymKeyParameter;
                var dP = dK.Parameters;
                bcpgKey = new DsaPublicBcpgKey(dP.P, dP.Q, dP.G, dK.Y);
            }

            else if (AsymKeyParameter is ElGamalPublicKeyParameters)
            {
                var eK = (ElGamalPublicKeyParameters) AsymKeyParameter;
                var eS = eK.Parameters;
                bcpgKey = new ElGamalPublicBcpgKey(eS.P, eS.G, eK.Y);
            }

            else
                throw new PgpException("unknown key class");

            this._PublicKeyPacket  = new PublicKeyPacket(Algorithm, CreationTime, bcpgKey);
            this._UserIds          = new List<Object>();
            this._idSigs           = new List<List<PgpSignature>>();

            try
            {
                Init();
            }
            catch (IOException e)
            {
                throw new PgpException("exception calculating keyId", e);
            }

        }

        #endregion

        #region (internal) PgpPublicKey(PublicKeyPacket, TrustPacket, SubSignatures)

        /// <summary>
        /// Constructor for a sub-key.
        /// </summary>
        internal PgpPublicKey(PublicKeyPacket            PublicKeyPacket,
                              TrustPacket                TrustPacket,
                              IEnumerable<PgpSignature>  SubSignatures)
        {

            this._PublicKeyPacket  = PublicKeyPacket;
            this._TrustPacket      = TrustPacket;
            this._SubSignatures    = new List<PgpSignature>(SubSignatures);

            this._KeySignatures    = new List<PgpSignature>();
            this._UserIds          = new List<Object>();
            this._idTrusts         = new List<TrustPacket>();
            this._idSigs           = new List<List<PgpSignature>>();

            Init();

        }

        #endregion

        #region (internal) PgpPublicKey(PublicKey, TrustPacket, SubSignatures)

        internal PgpPublicKey(PgpPublicKey               PublicKey,
                              TrustPacket                TrustPacket,
                              IEnumerable<PgpSignature>  SubSignatures)
        {

            this._PublicKeyPacket  = PublicKey._PublicKeyPacket;
            this._TrustPacket      = TrustPacket;
            this._SubSignatures    = new List<PgpSignature>(Signatures);

            this._Fingerprint      = PublicKey._Fingerprint;
            this._KeyId            = PublicKey._KeyId;
            this._KeyStrength      = PublicKey._KeyStrength;

            this._KeySignatures    = new List<PgpSignature>();
            this._UserIds          = new List<Object>();
            this._idTrusts         = new List<TrustPacket>();
            this._idSigs           = new List<List<PgpSignature>>();

        }

        #endregion

        #region (internal) PgpPublicKey(PublicKey)

        /// <summary>
        /// Copy constructor.
        /// </summary>
        /// <param name="PublicKey">The public key to copy.</param>
        internal PgpPublicKey(PgpPublicKey PublicKey)
        {

            this._PublicKeyPacket  = PublicKey._PublicKeyPacket;
            this._KeySignatures    = new List<PgpSignature>(PublicKey._KeySignatures);
            this._UserIds          = new List<Object>      (PublicKey._UserIds);
            this._idTrusts         = new List<TrustPacket> (PublicKey._idTrusts);
            this._idSigs           = new List<List<PgpSignature>>();

            for (int i = 0; i != PublicKey._idSigs.Count; i++)
                this._idSigs.Add(new List<PgpSignature>(PublicKey._idSigs[i]));

            this._SubSignatures    = new List<PgpSignature>();

            if (PublicKey._SubSignatures != null)
                this._SubSignatures.AddRange(PublicKey._SubSignatures);

            this._Fingerprint  = PublicKey._Fingerprint;
            this._KeyId        = PublicKey._KeyId;
            this._KeyStrength  = PublicKey._KeyStrength;

        }

        #endregion

        #region (internal) PgpPublicKey(PublicKey, Helper)

        /// <summary>
        /// Helper for the PgpKeyRingGenerator.
        /// </summary>
        /// <param name="PublicKey">A public key.</param>
        internal PgpPublicKey(PgpPublicKey PublicKey, Boolean Helper)
            : this(PublicKey)
        {
            this._PublicKeyPacket = new PublicSubkeyPacket(PublicKey.Algorithm, PublicKey.CreationTime, PublicKey._PublicKeyPacket.Key);
        }

        #endregion

        #region (internal) PgpPublicKey(PublicKeyPacket, ...)

        internal PgpPublicKey(PublicKeyPacket                  PublicKeyPacket,
                              TrustPacket                      TrustPacket,
                              IEnumerable<PgpSignature>        KeySignatures,
                              IEnumerable<Object>              UserIds,
                              IEnumerable<TrustPacket>         idTrusts,
                              IEnumerable<List<PgpSignature>>  idSigs)
        {

            this._PublicKeyPacket  = PublicKeyPacket;
            this._TrustPacket      = TrustPacket;

            this._KeySignatures    = new List<PgpSignature>(KeySignatures);
            this._UserIds          = new List<object>(UserIds);
            this._idTrusts         = new List<TrustPacket>(idTrusts);
            this._idSigs           = new List<List<PgpSignature>>(idSigs);
            this._SubSignatures    = new List<PgpSignature>();

            Init();

        }

        #endregion

        #region (internal) PgpPublicKey(PublicKeyPacket, UserIds, idSigs)

        internal PgpPublicKey(PublicKeyPacket                  PublicKeyPacket,
                              IEnumerable<Object>              UserIds,
                              IEnumerable<List<PgpSignature>>  idSigs)
        {

            this._PublicKeyPacket  = PublicKeyPacket;
            this._UserIds          = new List<Object>(UserIds);
            this._idSigs           = new List<List<PgpSignature>>(idSigs);

            this._KeySignatures    = new List<PgpSignature>();
            this._idTrusts         = new List<TrustPacket>();
            this._SubSignatures    = new List<PgpSignature>();

            Init();

        }

        #endregion

        #endregion


        #region Init()

        private void Init()
        {

            var key = _PublicKeyPacket.Key;

            if (_PublicKeyPacket.Version <= 3)
            {

                var rK = (RsaPublicBcpgKey) key;

                this._KeyId = (UInt64) rK.Modulus.LongValue;

                try
                {
                    IDigest digest = DigestUtilities.GetDigest("MD5");

                    byte[] bytes = rK.Modulus.ToByteArrayUnsigned();
                    digest.BlockUpdate(bytes, 0, bytes.Length);

                    bytes = rK.PublicExponent.ToByteArrayUnsigned();
                    digest.BlockUpdate(bytes, 0, bytes.Length);

                    this._Fingerprint = DigestUtilities.DoFinal(digest);
                }
                //catch (NoSuchAlgorithmException)
                catch (Exception e)
                {
                    throw new IOException("can't find MD5", e);
                }

                this._KeyStrength = (UInt32) rK.Modulus.BitLength;
            }
            else
            {
                byte[] kBytes = _PublicKeyPacket.GetEncodedContents();

                try
                {
                    IDigest digest = DigestUtilities.GetDigest("SHA1");

                    digest.Update(0x99);
                    digest.Update((byte)(kBytes.Length >> 8));
                    digest.Update((byte)kBytes.Length);
                    digest.BlockUpdate(kBytes, 0, kBytes.Length);
                    this._Fingerprint = DigestUtilities.DoFinal(digest);
                }
                catch (Exception e)
                {
                    throw new IOException("can't find SHA1", e);
                }

                this._KeyId = (((ulong) _Fingerprint[_Fingerprint.Length - 8] << 56) |
                               ((ulong) _Fingerprint[_Fingerprint.Length - 7] << 48) |
                               ((ulong) _Fingerprint[_Fingerprint.Length - 6] << 40) |
                               ((ulong) _Fingerprint[_Fingerprint.Length - 5] << 32) |
                               ((ulong) _Fingerprint[_Fingerprint.Length - 4] << 24) |
                               ((ulong) _Fingerprint[_Fingerprint.Length - 3] << 16) |
                               ((ulong) _Fingerprint[_Fingerprint.Length - 2] <<  8) |
                                (ulong) _Fingerprint[_Fingerprint.Length - 1]);

                if (key is RsaPublicBcpgKey)
                    this._KeyStrength = (UInt32) ((RsaPublicBcpgKey) key).Modulus.BitLength;

                else if (key is DsaPublicBcpgKey)
                    this._KeyStrength = (UInt32) ((DsaPublicBcpgKey) key).P.BitLength;

                else if (key is ElGamalPublicBcpgKey)
                    this._KeyStrength = (UInt32) ((ElGamalPublicBcpgKey) key).P.BitLength;

            }

        }

        #endregion


        #region (private) GetExpirationTimeFromSignature(SelfSigned, SignatureType)

        private UInt64 GetExpirationTimeFromSignature(Boolean            SelfSigned,
                                                      PgpSignatureTypes  SignatureType)
        {

            foreach (var sig in SignaturesOfType(SignatureType))
            {
                if (!SelfSigned || sig.KeyId == KeyId)
                {

                    var hashed = sig.HashedSubPackets;
                    if (hashed != null)
                        return hashed.KeyExpirationTime;

                    return 0;

                }
            }

            return 0;

        }

        #endregion


        #region SignaturesForUserId(UserId)

        /// <summary>
        /// Allows enumeration of any signatures associated with the passed in id.
        /// </summary>
        /// <param name="UserId">The ID to be matched.</param>
        /// <returns>An <c>IEnumerable</c> of <c>PgpSignature</c> objects.</returns>
        public IEnumerable<PgpSignature> SignaturesForUserId(String UserId)
        {

            if (UserId == null)
                throw new ArgumentNullException("id");

            for (int i = 0; i != _UserIds.Count; i++)
            {
                if (UserId.Equals(_UserIds[i]))
                    return _idSigs[i];
            }

            return null;

        }

        #endregion

        #region SignaturesForUserAttribute(UserAttributes)

        /// <summary>
        /// Allows enumeration of signatures associated with the passed in user attributes.
        /// </summary>
        /// <param name="UserAttributes">The vector of user attributes to be matched.</param>
        /// <returns>An <c>IEnumerable</c> of <c>PgpSignature</c> objects.</returns>
        public IEnumerable<PgpSignature> SignaturesForUserAttribute(PgpUserAttributeSubpacketVector UserAttributes)
        {

            for (int i = 0; i != _UserIds.Count; i++)
            {
                if (UserAttributes.Equals(_UserIds[i]))
                    return _idSigs[i];
            }

            return null;

        }

        #endregion

        #region SignaturesOfType(SignatureType)

        /// <summary>
        /// Allows enumeration of signatures of the passed in type that are on this key.
        /// </summary>
        /// <param name="SignatureType">The type of the signature to be returned.</param>
        /// <returns>An <c>IEnumerable</c> of <c>PgpSignature</c> objects.</returns>
        public IEnumerable<PgpSignature> SignaturesOfType(PgpSignatureTypes SignatureType)
        {
            return Signatures.Where(sig => sig.SignatureType == SignatureType);
        }

        #endregion


        public byte[] GetEncoded()
        {

            var bOut = new MemoryStream();
            Encode(bOut);

            return bOut.ToArray();

        }

        #region Encode(OutputStream)

        public void Encode(Stream OutputStream)
        {

            var BCPGOutputStream = BcpgOutputStream.Wrap(OutputStream);

            BCPGOutputStream.WritePacket(_PublicKeyPacket);
            if (_TrustPacket != null)
                BCPGOutputStream.WritePacket(_TrustPacket);

            // not a sub-key
            if (_SubSignatures == null)
            {

                foreach (var keySig in _KeySignatures)
                    keySig.Encode(BCPGOutputStream);

                for (int i = 0; i != _UserIds.Count; i++)
                {

                    if (_UserIds[i] is string)
                        BCPGOutputStream.WritePacket(new UserIdPacket((String) _UserIds[i]));

                    else
                        BCPGOutputStream.WritePacket(new UserAttributePacket(((PgpUserAttributeSubpacketVector) _UserIds[i]).ToSubpacketArray()));

                    if (_idTrusts[i] != null)
                        BCPGOutputStream.WritePacket((ContainedPacket) _idTrusts[i]);

                    foreach (var sig in _idSigs[i])
                        sig.Encode(BCPGOutputStream);

                }

            }

            else
            {
                foreach (var subSig in _SubSignatures)
                    subSig.Encode(BCPGOutputStream);
            }

        }

        #endregion



        #region (static) AddCertification(PublicKey, UserId, Certification)

        /// <summary>Add a certification for an id to the given public key.</summary>
        /// <param name="PublicKey">The key the certification is to be added to.</param>
        /// <param name="UserId">The ID the certification is associated with.</param>
        /// <param name="Certification">The new certification.</param>
        /// <returns>The re-certified key.</returns>
        public static PgpPublicKey AddCertification(PgpPublicKey  PublicKey,
                                                    String        UserId,
                                                    PgpSignature  Certification)
        {
            return AddCert(PublicKey, UserId, Certification);
        }

        #endregion

        #region (static) AddCertification(PublicKey, UserAttributes, Certification)

        /// <summary>Add a certification for the given UserAttributeSubpackets to the given public key.</summary>
        /// <param name="PublicKey">The key the certification is to be added to.</param>
        /// <param name="UserAttributes">The attributes the certification is associated with.</param>
        /// <param name="Certification">The new certification.</param>
        /// <returns>The re-certified key.</returns>
        public static PgpPublicKey AddCertification(PgpPublicKey                     PublicKey,
                                                    PgpUserAttributeSubpacketVector  UserAttributes,
                                                    PgpSignature                     Certification)
        {
            return AddCert(PublicKey, UserAttributes, Certification);
        }

        #endregion

        #region (private, static) AddCertification(PublicKey, Id, Certification)

        private static PgpPublicKey AddCert(PgpPublicKey  PublicKey,
                                            object        Id,
                                            PgpSignature  Certification)
        {

            var returnKey = new PgpPublicKey(PublicKey);
            List<PgpSignature> sigList = null;

            for (int i = 0; i != returnKey._UserIds.Count; i++)
            {
                if (Id.Equals(returnKey._UserIds[i]))
                {
                    sigList = returnKey._idSigs[i];
                }
            }

            if (sigList != null)
                sigList.Add(Certification);

            else
            {
                sigList = new List<PgpSignature>();
                sigList.Add(Certification);
                returnKey._UserIds.Add(Id);
                returnKey._idTrusts.Add(null);
                returnKey._idSigs.Add(sigList);
            }

            return returnKey;

        }

        #endregion


        #region (static) AddCertification(PublicKey, Certification)

        /// <summary>Add a revocation or some other key certification to a key.</summary>
        /// <param name="PublicKey">The key the revocation is to be added to.</param>
        /// <param name="Certification">The key signature to be added.</param>
        /// <returns>The new changed public key object.</returns>
        public static PgpPublicKey AddCertification(PgpPublicKey  PublicKey,
                                                    PgpSignature  Certification)
        {

            if (PublicKey.IsMasterKey)
            {
                if (Certification.SignatureType == PgpSignatureTypes.SubkeyRevocation)
                    throw new ArgumentException("signature type incorrect for master key revocation.");
            }

            else
            {
                if (Certification.SignatureType == PgpSignatureTypes.KeyRevocation)
                    throw new ArgumentException("signature type incorrect for sub-key revocation.");
            }

            var returnKey = new PgpPublicKey(PublicKey);

            if (returnKey._SubSignatures != null)
                returnKey._SubSignatures.Add(Certification);

            else
                returnKey._KeySignatures.Add(Certification);

            return returnKey;

        }

        #endregion



        #region (static) RemoveCertification(PublicKey, UserAttributes)

        /// <summary>
        /// Remove any certifications associated with a user attribute subpacket on a key.
        /// </summary>
        /// <param name="PublicKey">The key the certifications are to be removed from.</param>
        /// <param name="UserAttributes">The attributes to be removed.</param>
        /// <returns>
        /// The re-certified key, or null if the user attribute subpacket was not found on the key.
        /// </returns>
        public static PgpPublicKey RemoveCertification(PgpPublicKey                     PublicKey,
                                                       PgpUserAttributeSubpacketVector  UserAttributes)
        {
            return RemoveCert(PublicKey, UserAttributes);
        }

        #endregion

        #region (static) RemoveCertification(PublicKey, UserId)

        /// <summary>Remove any certifications associated with a given ID on a key.</summary>
        /// <param name="PublicKey">The key the certifications are to be removed from.</param>
        /// <param name="UserId">The ID that is to be removed.</param>
        /// <returns>The re-certified key, or null if the ID was not found on the key.</returns>
        public static PgpPublicKey RemoveCertification(PgpPublicKey  PublicKey,
                                                       String        UserId)
        {
            return RemoveCert(PublicKey, UserId);
        }

        #endregion

        #region (private, static) RemoveCert(PublicKey, Id)

        private static PgpPublicKey RemoveCert(PgpPublicKey  PublicKey,
                                               object        Id)
        {

            var  returnKey  = new PgpPublicKey(PublicKey);
            bool found      = false;

            for (int i = 0; i < returnKey._UserIds.Count; i++)
            {
                if (Id.Equals(returnKey._UserIds[i]))
                {
                    found = true;
                    returnKey._UserIds.RemoveAt(i);
                    returnKey._idTrusts.RemoveAt(i);
                    returnKey._idSigs.RemoveAt(i);
                }
            }

            return found ? returnKey : null;

        }

        #endregion


        #region (static) RemoveCertification(PublicKey, UserId, Certification)

        /// <summary>Remove a certification associated with a given ID on a key.</summary>
        /// <param name="PublicKey">The key the certifications are to be removed from.</param>
        /// <param name="UserId">The ID that the certfication is to be removed from.</param>
        /// <param name="Certification">The certfication to be removed.</param>
        /// <returns>The re-certified key, or null if the certification was not found.</returns>
        public static PgpPublicKey RemoveCertification(PgpPublicKey  PublicKey,
                                                       String        UserId,
                                                       PgpSignature  Certification)
        {
            return RemoveCert(PublicKey, UserId, Certification);
        }

        #endregion

        #region (static) RemoveCertification(PublicKey, UserAttributes, Certification)

        /// <summary>Remove a certification associated with a given user attributes on a key.</summary>
        /// <param name="PublicKey">The key the certifications are to be removed from.</param>
        /// <param name="UserAttributes">The user attributes that the certfication is to be removed from.</param>
        /// <param name="Certification">The certification to be removed.</param>
        /// <returns>The re-certified key, or null if the certification was not found.</returns>
        public static PgpPublicKey RemoveCertification(PgpPublicKey                     PublicKey,
                                                       PgpUserAttributeSubpacketVector  UserAttributes,
                                                       PgpSignature                     Certification)
        {
            return RemoveCert(PublicKey, UserAttributes, Certification);
        }

        #endregion

        #region (private, static) RemoveCert(PublicKey, Id, Certification)

        private static PgpPublicKey RemoveCert(PgpPublicKey    PublicKey,
                                               object          Id,
                                               PgpSignature    Certification)
        {

            var returnKey  = new PgpPublicKey(PublicKey);
            var found      = false;

            for (var i = 0; i < returnKey._UserIds.Count; i++)
            {
                if (Id.Equals(returnKey._UserIds[i]))
                {

                    IList certs = (IList) returnKey._idSigs[i];
                    found = certs.Contains(Certification);

                    if (found)
                        certs.Remove(Certification);

                }
            }

            return found ? returnKey : null;

        }

        #endregion


        #region (static) RemoveCertification(PublicKey, Certification)

        /// <summary>Remove a certification from the key.</summary>
        /// <param name="PublicKey">The key the certifications are to be removed from.</param>
        /// <param name="Certification">The certfication to be removed.</param>
        /// <returns>The modified key, null if the certification was not found.</returns>
        public static PgpPublicKey RemoveCertification(PgpPublicKey  PublicKey,
                                                       PgpSignature  Certification)
        {

            var returnKey = new PgpPublicKey(PublicKey);

            IList sigs = returnKey._SubSignatures != null
                ?    returnKey._SubSignatures
                :    returnKey._KeySignatures;

//            bool found = sigs.Remove(certification);
            int pos = sigs.IndexOf(Certification);
            bool found = pos >= 0;

            if (found)
            {
                sigs.RemoveAt(pos);
            }
            else
            {

                foreach (var UserId in PublicKey.UserIds)
                {
                    foreach (var Signature in PublicKey.SignaturesForUserId(UserId))
                    {
                        // TODO Is this the right type of equality test?
                        if (Certification == Signature)
                        {
                            found = true;
                            returnKey = PgpPublicKey.RemoveCertification(returnKey, UserId, Certification);
                        }
                    }
                }

                if (!found)
                {
                    foreach (var UserAttribute in PublicKey.UserAttributes)
                    {
                        foreach (var sig in PublicKey.SignaturesForUserAttribute(UserAttribute))
                        {
                            // TODO Is this the right type of equality test?
                            if (Certification == sig)
                            {
                                found = true;
                                returnKey = PgpPublicKey.RemoveCertification(returnKey, UserAttribute, Certification);
                            }
                        }
                    }
                }

            }

            return returnKey;

        }

        #endregion


        public override String ToString()
        {
            return (_UserIds.FirstOrDefault() != null ? _UserIds.FirstOrDefault().ToString() : "") + " 0x" + _KeyId.ToString("X") + " " + CreationTime.ToString();
        }

    }

}
