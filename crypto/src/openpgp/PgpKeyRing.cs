using System.Collections;
using System.IO;

using Org.BouncyCastle.Utilities;
using System.Collections.Generic;
using System;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    public abstract class PgpKeyRing : PgpObject
    {

        internal PgpKeyRing()
        { }

        internal static TrustPacket ReadOptionalTrustPacket(BcpgInputStream bcpgInput)
        {
            return (bcpgInput.NextPacketTag() == PacketTag.Trust)
                ?    (TrustPacket) bcpgInput.ReadPacket()
                :    null;
        }

        internal static List<PgpSignature> ReadSignaturesAndTrust(BcpgInputStream bcpgInput)
        {

            try
            {

                var sigList = new List<PgpSignature>();

                while (bcpgInput.NextPacketTag() == PacketTag.Signature)
                {

                    var signaturePacket  = (SignaturePacket) bcpgInput.ReadPacket();
                    var trustPacket      = ReadOptionalTrustPacket(bcpgInput);

                    sigList.Add(new PgpSignature(signaturePacket, trustPacket));

                }

                return sigList;

            }

            catch (PgpException e)
            {
                throw new IOException("can't create signature object: " + e.Message, e);
            }

        }

        internal static void ReadUserIDs(BcpgInputStream               bcpgInput,
                                         out List<Object>              ids,
                                         out List<TrustPacket>         idTrusts,
                                         out List<List<PgpSignature>>  idSigs)
        {

            ids       = new List<Object>();
            idTrusts  = new List<TrustPacket>();
            idSigs    = new List<List<PgpSignature>>();

            while (bcpgInput.NextPacketTag() == PacketTag.UserId
                || bcpgInput.NextPacketTag() == PacketTag.UserAttribute)
            {

                Packet obj = bcpgInput.ReadPacket();

                if (obj is UserIdPacket)
                {
                    var id = (UserIdPacket) obj;
                    ids.Add(id.GetId());
                }
                else
                {
                    UserAttributePacket user = (UserAttributePacket) obj;
                    ids.Add(new PgpUserAttributeSubpacketVector(user.GetSubpackets()));
                }

                idTrusts.Add(ReadOptionalTrustPacket(bcpgInput));
                idSigs.  Add(ReadSignaturesAndTrust (bcpgInput));

            }

        }

    }

}
