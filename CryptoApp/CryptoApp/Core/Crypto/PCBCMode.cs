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
            int paddingLen = blockSize - (data.Length % blockSize);
            byte[] padded = new byte[data.Length + paddingLen];
            Array.Copy(data, padded, data.Length);
            padded[padded.Length - 1] = (byte)paddingLen;

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

            return RemovePadding(result);

        }
        private byte[] RemovePadding(byte[] data)
        {
            int pad = data[data.Length - 1];
            if (pad <= 0 || pad > BlockSize) return data;

            byte[] result = new byte[data.Length - pad];
            Array.Copy(data, result, result.Length);
            return result;
        }
    }
}
