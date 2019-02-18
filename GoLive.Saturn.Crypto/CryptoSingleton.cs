using System;

namespace GoLive.Saturn.Crypto
{
    public sealed class CryptoSingleton
    {
        private static readonly Lazy<CryptoSingleton> _lazyInstance = new Lazy<CryptoSingleton>(() => new CryptoSingleton());
        public static CryptoSingleton Instance => _lazyInstance.Value;

        private CryptoSingleton()
        {
        }

        public string MasterEncryptionKey { get; set; }

        public string MasterHashKey { get; set; }
    }
}
