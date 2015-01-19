using System.IO;

using Org.BouncyCastle.Asn1.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{

    public class WrappedGeneratorStream : FilterStream
    {

        private readonly IStreamGenerator StreamGenerator;

        public WrappedGeneratorStream(IStreamGenerator  StreamGenerator,
                                      Stream            Stream)

            : base(Stream)

        {
            this.StreamGenerator = StreamGenerator;
        }

        public override void Close()
        {
            StreamGenerator.Close();
        }

    }

}
