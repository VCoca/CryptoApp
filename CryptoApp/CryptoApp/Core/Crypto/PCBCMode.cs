using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoApp.Core.Crypto
{
    public class PCBCMode : IEncryptor
    {
        private readonly IEncryptor baseCipher = new RC6Cipher();
        public int BlockSize => baseCipher.BlockSize;

        private byte[] prevCipher;
        private byte[] prevPlain;
        private bool initialized = false;

        private void Init(byte[] iv)
        {
            if (initialized) return;
            prevCipher = new byte[BlockSize];
            prevPlain = new byte[BlockSize];
            Array.Copy(iv, prevCipher, BlockSize);
            initialized = true;
        }

        public byte[] Encrypt(byte[] data, byte[] key, byte[] iv)
        {
            Init(iv);

            // ⚠️ NEMA paddinga ovde — FileEncoder će to rešiti na kraju
            if (data.Length % BlockSize != 0)
                throw new ArgumentException("Data length must be multiple of block size except final block.");

            byte[] result = new byte[data.Length];

            for (int i = 0; i < data.Length; i += BlockSize)
            {
                byte[] block = new byte[BlockSize];
                Array.Copy(data, i, block, 0, BlockSize);

                byte[] xored = new byte[BlockSize];
                for (int j = 0; j < BlockSize; j++)
                    xored[j] = (byte)(block[j] ^ prevCipher[j] ^ prevPlain[j]);

                byte[] enc = baseCipher.Encrypt(xored, key, iv);
                Array.Copy(enc, 0, result, i, BlockSize);

                Array.Copy(block, prevPlain, BlockSize);
                Array.Copy(enc, prevCipher, BlockSize);
            }
            return result;
        }

        public byte[] Decrypt(byte[] data, byte[] key, byte[] iv)
        {
            Init(iv);

            if (data.Length % BlockSize != 0)
                throw new ArgumentException("Ciphertext length must be multiple of block size.");

            byte[] result = new byte[data.Length];

            for (int i = 0; i < data.Length; i += BlockSize)
            {
                byte[] block = new byte[BlockSize];
                Array.Copy(data, i, block, 0, BlockSize);

                byte[] dec = baseCipher.Decrypt(block, key, iv);

                for (int j = 0; j < BlockSize; j++)
                    dec[j] ^= (byte)(prevCipher[j] ^ prevPlain[j]);

                Array.Copy(dec, 0, result, i, BlockSize);

                Array.Copy(dec, prevPlain, BlockSize);
                Array.Copy(block, prevCipher, BlockSize);
            }
            return result;
        }
    }
}
