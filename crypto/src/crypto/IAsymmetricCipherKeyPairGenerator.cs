
namespace Org.BouncyCastle.Crypto
{

    /// <summary>
    /// The interface for all public/private key pair generators.
    /// </summary>
    public interface IAsymmetricCipherKeyPairGenerator
    {

        /// <summary>
        /// Intialise the key pair generator.
        /// </summary>
        /// <param name="parameters">The parameters the key pair is to be initialised with.</param>
        void Init(KeyGenerationParameters parameters);

        /// <summary>
        /// Generate the key pair.
        /// </summary>
        /// <returns></returns>
        AsymmetricCipherKeyPair GenerateKeyPair();

    }
}
