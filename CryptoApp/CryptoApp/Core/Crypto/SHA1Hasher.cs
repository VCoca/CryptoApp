using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace CryptoApp.Core.Crypto
{
    internal class SHA1Hasher
    {
        public static string ComputeHash(string filePath)
        {
            uint h0 = 0x67452301;
            uint h1 = 0xEFCDAB89;
            uint h2 = 0x98BADCFE;
            uint h3 = 0x10325476;
            uint h4 = 0xC3D2E1F0;

            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                long fileLength = fs.Length;
                long bitLength = fileLength * 8;
                byte[] buffer = new byte[64]; // 512-bitni blokovi
                int bytesRead;
                bool padded = false;
                bool lengthWritten = false;

                while (!lengthWritten)
                {
                    bytesRead = fs.Read(buffer, 0, 64);
                    byte[] block = new byte[64];

                    if (bytesRead == 64)
                    {
                        Array.Copy(buffer, block, 64);
                    }
                    else if (!padded)
                    {
                        // Padding: dodaj 0x80 i nule
                        Array.Copy(buffer, block, bytesRead);
                        block[bytesRead] = 0x80;
                        padded = true;

                        // Ako ima mesta za dužinu (8 bajtova na kraju)
                        if (bytesRead < 56)
                        {
                            WriteLength(block, bitLength);
                            lengthWritten = true;
                        }
                    }
                    else
                    {
                        // Drugi blok paddinga ako dužina nije stala u prvi
                        WriteLength(block, bitLength);
                        lengthWritten = true;
                    }

                    // SHA-1 transformacija bloka
                    ProcessBlock(block, ref h0, ref h1, ref h2, ref h3, ref h4);
                }
            }
            return $"{h0:x8}{h1:x8}{h2:x8}{h3:x8}{h4:x8}";
        }

        private static void ProcessBlock(byte[] block, ref uint h0, ref uint h1, ref uint h2, ref uint h3, ref uint h4)
        {
            uint[] w = new uint[80];
            for (int j = 0; j < 16; j++)
                w[j] = (uint)block[j * 4] << 24 | (uint)block[j * 4 + 1] << 16 | (uint)block[j * 4 + 2] << 8 | (uint)block[j * 4 + 3];

            for (int j = 16; j < 80; j++)
                w[j] = RotateLeft(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);

            uint a = h0, b = h1, c = h2, d = h3, e = h4;
            for (int j = 0; j < 80; j++)
            {
                uint f, k;
                if (j < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
                else if (j < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
                else if (j < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
                else { f = b ^ c ^ d; k = 0xCA62C1D6; }

                uint temp = RotateLeft(a, 5) + f + e + k + w[j];
                e = d; d = c; c = RotateLeft(b, 30); b = a; a = temp;
            }
            h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
        }

        private static void WriteLength(byte[] block, long bitLength)
        {
            byte[] lenBytes = BitConverter.GetBytes(bitLength);
            if (BitConverter.IsLittleEndian) Array.Reverse(lenBytes);
            Array.Copy(lenBytes, 0, block, 56, 8);
        }

        private static uint RotateLeft(uint value, int count) => (value << count) | (value >> (32 - count));
    }
}
