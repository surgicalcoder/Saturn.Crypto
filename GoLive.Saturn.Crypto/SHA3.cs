using System;
using System.Collections.Generic;

namespace GoLive.Saturn.Crypto
{
    public abstract class SHA3 : System.Security.Cryptography.HashAlgorithm
    {
        #region Statics

        public static string DefaultHashName = "SHA3-512";

        protected static Dictionary<string, Func<SHA3>> HashNameMap;

        static SHA3()
        {
            HashNameMap = new Dictionary<string, Func<SHA3>>
            {
                { "SHA3-224", () => new SHA3Managed(224)},
                { "SHA3-256", () => new SHA3Managed(256)},
                { "SHA3-384", () => new SHA3Managed(384)},
                { "SHA3-512", () => new SHA3Managed(512)},
            };
        }

        public new static SHA3 Create()
        {
            return Create(DefaultHashName);
        }

        public new static SHA3 Create(string hashName)
        {
            Func<SHA3> ctor;
            if (HashNameMap.TryGetValue(hashName, out ctor))
                return ctor();
            return null;
        }

        #endregion

        #region Implementation

        public const int KeccakB = 1600;
        public const int KeccakNumberOfRounds = 24;
        public const int KeccakLaneSizeInBits = 8 * 8;

        public readonly ulong[] RoundConstants;

        protected ulong[] state;
        protected byte[] buffer;
        protected int buffLength;

        protected int keccakR;

        public int KeccakR
        {
            get => keccakR;
            protected set => keccakR = value;
        }

        public int SizeInBytes => KeccakR / 8;

        public int HashByteLength => HashSizeValue / 8;

        public override
            bool CanReuseTransform => true;

        protected SHA3(int hashBitLength)
        {
            if (hashBitLength != 224 && hashBitLength != 256 && hashBitLength != 384 && hashBitLength != 512)
                throw new ArgumentException("hashBitLength must be 224, 256, 384, or 512", nameof(hashBitLength));
            Initialize();
            HashSizeValue = hashBitLength;
            switch (hashBitLength)
            {
                case 224:
                    KeccakR = 1152;
                    break;
                case 256:
                    KeccakR = 1088;
                    break;
                case 384:
                    KeccakR = 832;
                    break;
                case 512:
                    KeccakR = 576;
                    break;
            }
            RoundConstants = new ulong[]
            {
                0x0000000000000001UL,
                0x0000000000008082UL,
                0x800000000000808aUL,
                0x8000000080008000UL,
                0x000000000000808bUL,
                0x0000000080000001UL,
                0x8000000080008081UL,
                0x8000000000008009UL,
                0x000000000000008aUL,
                0x0000000000000088UL,
                0x0000000080008009UL,
                0x000000008000000aUL,
                0x000000008000808bUL,
                0x800000000000008bUL,
                0x8000000000008089UL,
                0x8000000000008003UL,
                0x8000000000008002UL,
                0x8000000000000080UL,
                0x000000000000800aUL,
                0x800000008000000aUL,
                0x8000000080008081UL,
                0x8000000000008080UL,
                0x0000000080000001UL,
                0x8000000080008008UL
            };
        }

        protected ulong ROL(ulong a, int offset)
        {
            return (((a) << ((offset) % KeccakLaneSizeInBits)) ^
                    ((a) >> (KeccakLaneSizeInBits - ((offset) % KeccakLaneSizeInBits))));
        }

        protected void AddToBuffer(byte[] array, ref int offset, ref int count)
        {
            int amount = Math.Min(count, buffer.Length - buffLength);
            Buffer.BlockCopy(array, offset, buffer, buffLength, amount);
            offset += amount;
            buffLength += amount;
            count -= amount;
        }

        public override byte[] Hash => HashValue;

        public override int HashSize => HashSizeValue;

        #endregion

        public override void Initialize()
        {
            buffLength = 0;
            state = new ulong[5 * 5]; //1600 bits
            HashValue = null;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (array == null)
                throw new ArgumentNullException(nameof(array));
            if (ibStart < 0)
                throw new ArgumentOutOfRangeException(nameof(ibStart));
            if (cbSize > array.Length)
                throw new ArgumentOutOfRangeException(nameof(cbSize));
            if (ibStart + cbSize > array.Length)
                throw new ArgumentOutOfRangeException("ibStart or cbSize");
        }


    }
}