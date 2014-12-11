namespace Org.BouncyCastle.Bcpg
{

    /// <summary>
    /// Enumeration of compression algorithms.
    /// </summary>
    public enum CompressionAlgorithms
    {

        Uncompressed    = 0,    // Uncompressed
        Zip             = 1,    // ZIP (RFC 1951)
        ZLib            = 2,    // ZLIB (RFC 1950)
        BZip2           = 3,    // BZ2

    }

}
