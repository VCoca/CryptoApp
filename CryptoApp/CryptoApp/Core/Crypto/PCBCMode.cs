using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoApp.Core.Crypto
{
    public class PCBCMode : IEncryptor
    {
        private readonly IEncryptor baseCipher;
        public int BlockSize => baseCipher.BlockSize;

        public PCBCMode()
        {
            this.baseCipher = new RC6Cipher();
        }

        public byte[] Encrypt(byte[] data, byte[] key, byte[] iv)
        {
            int blockSize = BlockSize;
            int paddedLength = ((data.Length + blockSize - 1) / blockSize) * blockSize;
            byte[] padded = new byte[paddedLength];
            Array.Copy(data, padded, data.Length);

            byte[] result = new byte[padded.Length];

            byte[] prevCipher = new byte[blockSize];
            byte[] prevPlain = new byte[blockSize];
            Array.Copy(iv, prevCipher, blockSize);

            for (int i = 0; i < padded.Length; i += blockSize)
            {
                byte[] block = new byte[blockSize];
                Array.Copy(padded, i, block, 0, blockSize);

                byte[] xored = new byte[blockSize];
                for (int j = 0; j < blockSize; j++)
                    xored[j] = (byte)(block[j] ^ prevCipher[j] ^ prevPlain[j]);

                byte[] encBlock = baseCipher.Encrypt(xored, key, iv);
                Array.Copy(encBlock, 0, result, i, blockSize);

                // Update prevPlain i prevCipher
                Array.Copy(block, prevPlain, blockSize);
                Array.Copy(encBlock, prevCipher, blockSize);
            }

            return result;
        }

        public byte[] Decrypt(byte[] data, byte[] key, byte[] iv)
        {
            int blockSize = BlockSize;
            byte[] result = new byte[data.Length];

            byte[] prevCipher = new byte[blockSize];
            byte[] prevPlain = new byte[blockSize];
            Array.Copy(iv, prevCipher, blockSize);

            for (int i = 0; i < data.Length; i += blockSize)
            {
                byte[] block = new byte[blockSize];
                Array.Copy(data, i, block, 0, blockSize);

                byte[] decBlock = baseCipher.Decrypt(block, key, iv);

                for (int j = 0; j < blockSize; j++)
                    decBlock[j] = (byte)(decBlock[j] ^ prevCipher[j] ^ prevPlain[j]);

                Array.Copy(decBlock, 0, result, i, blockSize);

                // Update prevPlain i prevCipher
                Array.Copy(decBlock, prevPlain, blockSize);
                Array.Copy(block, prevCipher, blockSize);
            }

            return result;

        }
    }
}
