/*
 * Copyright (c) 2014-2015, Achim 'ahzf' Friedland <achim@graphdefined.org>
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

#endregion

namespace org.GraphDefined.Vanaheimr.BouncyCastle
{

    public static class OpenPGP
    {

        public static MemoryStream ToMemoryStream(this String InputStream)
        {

            var inputstream = new MemoryStream();
            var Bytes = Encoding.UTF8.GetBytes(InputStream);
            inputstream.Write(Bytes, 0, Bytes.Length);
            inputstream.Seek(0, SeekOrigin.Begin);

            return inputstream;

        }


        public static PgpPublicKeyRingBundle ReadPgpPublicKeyRingBundle(String Text)
        {
            return new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(Text.ToMemoryStream()));
        }

        public static PgpPublicKeyRingBundle ReadPgpPublicKeyRingBundle(Stream InputStream)
        {
            return new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(InputStream));
        }


        public static PgpPublicKeyRing ReadPublicKeyRing(String Text)
        {
            return new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(Text.ToMemoryStream())).First();
        }

        public static PgpPublicKeyRing ReadPublicKeyRing(Stream InputStream)
        {
            return new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(InputStream)).First();
        }


        public static PgpPublicKey ReadPublicKey(String Text)
        {
            return ReadPublicKeyRing(Text.ToMemoryStream()).First();
        }

        public static PgpPublicKey ReadPublicKey(Stream InputStream)
        {
            return ReadPublicKeyRing(InputStream).First();
        }




        public static PgpSecretKeyRingBundle ReadPgpSecretKeyRingBundle(String Text)
        {
            return new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(Text.ToMemoryStream()));
        }

        public static PgpSecretKeyRingBundle ReadPgpSecretKeyRingBundle(Stream InputStream)
        {
            return new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(InputStream));
        }



        public static PgpSecretKeyRing ReadSecretKeyRing(Stream InputStream)
        {

            var SecretKeyRingBundle = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(InputStream));

            // we just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.
            foreach (var SecretKeyRing in SecretKeyRingBundle)
            {
                foreach (var SecretKey in SecretKeyRing)
                {
                    if (SecretKey.IsSigningKey)
                        return SecretKeyRing;
                }
            }

            throw new ArgumentException("Can't find signing key in key ring.");

        }


        public static PgpSecretKey ReadSecretKey(String Text)
        {
            return ReadSecretKeyRing(Text.ToMemoryStream()).First();
        }

        public static PgpSecretKey ReadSecretKey(Stream InputStream)
        {
            return ReadSecretKeyRing(InputStream).First();
        }




        public static PgpSignature CreateSignature(Stream          InputStream,
                                                   PgpSecretKey    SecretKey,
                                                   String          Passphrase,
                                                   HashAlgorithms  HashAlgorithm      = HashAlgorithms.Sha512,
                                                   UInt32          BufferSize         = 2*1024*1024) // Bytes
        {

            #region Init signature generator

            var SignatureGenerator  = new PgpSignatureGenerator(SecretKey.PublicKey.Algorithm,
                                                                HashAlgorithm);

            SignatureGenerator.InitSign(PgpSignatureTypes.BinaryDocument,
                                        SecretKey.ExtractPrivateKey(Passphrase));

            #endregion

            #region Read input and update the signature generator

            var InputBuffer  = new Byte[BufferSize];
            var read         = 0;

            do
            {

                read = InputStream.Read(InputBuffer, 0, InputBuffer.Length);
                SignatureGenerator.Update(InputBuffer, 0, read);

            } while (read == BufferSize);

            InputStream.Close();

            #endregion

            return SignatureGenerator.Generate();

        }

        public static T WriteTo<T>(this PgpSignature  Signature,
                                   T                  OutputStream,
                                   Boolean            ArmoredOutput      = true,
                                   Boolean            CloseOutputStream  = true)

            where T : Stream

        {

            #region Open/create output streams

            BcpgOutputStream WrappedOutputStream = null;

            if (ArmoredOutput)
                WrappedOutputStream = new BcpgOutputStream(new ArmoredOutputStream(OutputStream));
            else
                WrappedOutputStream = new BcpgOutputStream(OutputStream);

            #endregion

            Signature.Encode(WrappedOutputStream);

            #region Close streams, if requested

            WrappedOutputStream.Flush();
            WrappedOutputStream.Close();

            // ArmoredOutputStream will not close the underlying stream!
            if (ArmoredOutput)
                OutputStream.Flush();

            if (CloseOutputStream)
                OutputStream.Close();

            #endregion

            return OutputStream;

        }








        private static void VerifySignature2(String fileName,
                                    Stream inputStream,
                                    Stream keyIn)
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
