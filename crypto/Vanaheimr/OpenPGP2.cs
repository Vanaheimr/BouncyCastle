/*
 * Copyright (c) 2014-2016, Achim 'ahzf' Friedland <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr BouncyCastle <http://www.github.com/Vanaheimr/BouncyCastle>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#region Usings

using System;
using System.IO;
using System.Linq;
using System.Text;

using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;

#endregion

namespace org.GraphDefined.Vanaheimr.BouncyCastle
{

    public static class OpenPGP2
    {

        private static void VerifySignature2(String  fileName,
                                             Stream  inputStream,
                                             Stream  keyIn)
        {

            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            var pgpFact = new PgpObjectFactory(inputStream);
            PgpSignatureList p3 = null;
            var PGPObject = pgpFact.NextPgpObject();

            if (PGPObject is PgpCompressedData)
            {
                var c1 = (PgpCompressedData)PGPObject;
                pgpFact = new PgpObjectFactory(c1.GetDataStream());
                p3 = (PgpSignatureList)pgpFact.NextPgpObject();
            }

            else
                p3 = (PgpSignatureList)PGPObject;

            var pgpPubRingCollection = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(keyIn));
            Stream dIn = File.OpenRead(fileName);
            var sig = p3[0];
            var key = pgpPubRingCollection.GetPublicKey(sig.KeyId);
            sig.InitVerify(key);

            int ch;
            while ((ch = dIn.ReadByte()) >= 0)
            {
                sig.Update((byte)ch);
            }

            dIn.Close();

            if (sig.IsValid)
                Console.WriteLine("signature verified.");
            else
                Console.WriteLine("signature verification failed.");

        }


        public class res
        {

            #region Properties

            #region Signature

            public PgpSignature _Signature;

            public PgpSignature Signature
            {
                get
                {
                    return _Signature;
                }
            }

            #endregion

            #region CreationTime

            public DateTime CreationTime
            {
                get
                {
                    return _Signature.CreationTime;
                }
            }

            #endregion

            #region HashAlgorithm

            public HashAlgorithms HashAlgorithm
            {
                get
                {
                    return _Signature.HashAlgorithm;
                }
            }

            #endregion

            #region KeyAlgorithm

            public PublicKeyAlgorithms KeyAlgorithm
            {
                get
                {
                    return _Signature.KeyAlgorithm;
                }
            }

            #endregion

            #region KeyIdHex

            public String KeyIdHex
            {
                get
                {
                    return _Signature.KeyIdHex;
                }
            }

            #endregion

            #region KeyId

            public UInt64 KeyId
            {
                get
                {
                    return _Signature.KeyId;
                }
            }

            #endregion

            #region PublicKey

            private PgpPublicKey _PublicKey;

            public PgpPublicKey PublicKey
            {
                get
                {
                    return _PublicKey;
                }
            }

            #endregion

            #region IsValid

            public Boolean _IsValid;

            /// <summary>
            /// Verifies the signature.
            /// (Will consume as constant verification time for security reasons!)
            /// </summary>
            public Boolean IsValid
            {

                get
                {
                    return _IsValid;
                }

            }

            #endregion

            #endregion

        }

        private static res VerifySignature(String  FileToVerify,
                                           Stream  SignatureInputStream,
                                           Stream  keyIn)
        {

            SignatureInputStream = PgpUtilities.GetDecoderStream(SignatureInputStream);

            var               pgpFact        = new PgpObjectFactory(SignatureInputStream);
            PgpSignatureList  SignatureList  = null;
            var               PGPObject      = pgpFact.NextPgpObject();

            if (PGPObject is PgpCompressedData)
            {
                var c1         = (PgpCompressedData) PGPObject;
                pgpFact        = new PgpObjectFactory(c1.GetDataStream());
                SignatureList  = (PgpSignatureList) pgpFact.NextPgpObject();
            }

            else
                SignatureList  = (PgpSignatureList) PGPObject;

            var pgpPubRingCollection  = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(keyIn));
            var FileToVerifyStream    = File.OpenRead(FileToVerify);
            var Signature             = SignatureList[0];
            var PublicKey             = pgpPubRingCollection.GetPublicKey(Signature.KeyId);

            Signature.InitVerify(PublicKey);

            int ch;
            while ((ch = FileToVerifyStream.ReadByte()) >= 0)
            {
                Signature.Update((byte) ch);
            }

            FileToVerifyStream.Close();

            var aa = new res();
            aa._Signature = Signature;
            aa._IsValid = Signature.IsValid;

            return aa;

        }

    }

}
