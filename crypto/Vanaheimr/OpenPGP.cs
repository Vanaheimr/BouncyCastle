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
using System.Threading.Tasks;
using System.Collections.Generic;

using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;

#endregion

namespace org.GraphDefined.Vanaheimr.BouncyCastle
{

    public static class OpenPGP
    {

        public static PgpPublicKey ReadPublicKey(Stream input)
        {

            var pgpPub = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(input));

            foreach (var keyRing in pgpPub.KeyRings)
            {
                return keyRing.PublicKey;
            }

            throw new ArgumentException("Can't find public key in key ring.");

        }

        public static PgpSecretKey ReadSecretKey(Stream input)
        {

            var pgpSec = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(input));

            // we just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.
            foreach (var keyRing in pgpSec.GetKeyRings())
            {
                foreach (var key in keyRing.SecretKeys)
                {
                    if (key.IsSigningKey)
                        return key;
                }
            }

            throw new ArgumentException("Can't find signing key in key ring.");

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

            SignatureGenerator.InitSign(PgpSignatures.BinaryDocument,
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

    }

}
