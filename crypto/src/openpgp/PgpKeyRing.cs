using System;
using System.IO;
using System.Collections.Generic;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    public abstract class PgpKeyRing : PgpObject
    {

        #region (internal) Constructor(s)

        internal PgpKeyRing()
        { }

        #endregion


        #region (internal) ReadOptionalTrustPacket(BCPGInputStream)

        internal static TrustPacket ReadOptionalTrustPacket(BcpgInputStream BCPGInputStream)
        {

            return (BCPGInputStream.NextPacketTag() == PacketTag.Trust)
                ? BCPGInputStream.ReadPacket<TrustPacket>()
                : null;

        }

        #endregion

        #region (internal) ReadSignaturesAndTrust(BCPGInputStream)

        internal static IEnumerable<PgpSignature> ReadSignaturesAndTrust(BcpgInputStream BCPGInputStream)
        {

            try
            {

                while (BCPGInputStream.NextPacketTag() == PacketTag.Signature)
                {

                    var signaturePacket  = BCPGInputStream.ReadPacket<SignaturePacket>();
                    var trustPacket      = ReadOptionalTrustPacket(BCPGInputStream);

                    return new List<PgpSignature>() { new PgpSignature(signaturePacket, trustPacket) };

                }

                return new List<PgpSignature>();

            }

            catch (PgpException e)
            {
                throw new IOException("Can't create signature object: " + e.Message, e);
            }

        }

        #endregion

        #region (internal) ReadUserIds(BCPGInputStream)

        internal static void ReadUserIds(BcpgInputStream               BCPGInputStream,
                                         out List<Object>              Ids,
                                         out List<TrustPacket>         IdTrusts,
                                         out List<List<PgpSignature>>  IdSigs)
        {

            Ids       = new List<Object>();
            IdTrusts  = new List<TrustPacket>();
            IdSigs    = new List<List<PgpSignature>>();

            while (BCPGInputStream.NextPacketTag() == PacketTag.UserId ||
                   BCPGInputStream.NextPacketTag() == PacketTag.UserAttribute)
            {

                var _Packet               = BCPGInputStream.ReadPacket();
                var _UserIdPacket         = _Packet as UserIdPacket;
                var _UserAttributePacket  = _Packet as UserAttributePacket;

                if (_UserIdPacket != null)
                    Ids.Add(_UserIdPacket.GetId());

                else if (_UserAttributePacket != null)
                    Ids.Add(new PgpUserAttributeSubpacketVector(_UserAttributePacket.GetSubpackets()));

                else
                    throw new Exception("Unknown packet received!");

                var optioalTrustPacket = ReadOptionalTrustPacket(BCPGInputStream);
                if (optioalTrustPacket != null)
                    IdTrusts.Add(optioalTrustPacket);

                IdSigs.  Add(new List<PgpSignature>(ReadSignaturesAndTrust (BCPGInputStream)));

            }

        }

        #endregion

    }

}
