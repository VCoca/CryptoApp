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
        public static string SHA1Hash(byte[] data)
        {
            // 1. Inicijalizacija varijabli (H0-H4)
            uint h0 = 0x67452301;
            uint h1 = 0xEFCDAB89;
            uint h2 = 0x98BADCFE;
            uint h3 = 0x10325476;
            uint h4 = 0xC3D2E1F0;

            // 2. Pre-processing (Padding)
            byte[] paddedData = PadMessage(data);

            // 3. Procesiranje u blokovima od 512 bita (64 bajta)
            for (int i = 0; i < paddedData.Length; i += 64)
            {
                uint[] w = new uint[80];

                // Razbijanje bloka na 16 32-bitnih reči
                for (int j = 0; j < 16; j++)
                {
                    w[j] = (uint)paddedData[i + j * 4] << 24 |
                           (uint)paddedData[i + j * 4 + 1] << 16 |
                           (uint)paddedData[i + j * 4 + 2] << 8 |
                           (uint)paddedData[i + j * 4 + 3];
                }

                // Ekspanzija 16 reči u 80 reči
                for (int j = 16; j < 80; j++)
                {
                    w[j] = LeftRotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
                }

                // Inicijalizacija vrednosti za ovaj blok
                uint a = h0;
                uint b = h1;
                uint c = h2;
                uint d = h3;
                uint e = h4;

                // Glavna petlja (80 rundi)
                for (int j = 0; j < 80; j++)
                {
                    uint f, k;

                    if (j <= 19)
                    {
                        f = (b & c) | ((~b) & d);
                        k = 0x5A827999;
                    }
                    else if (j <= 39)
                    {
                        f = b ^ c ^ d;
                        k = 0x6ED9EBA1;
                    }
                    else if (j <= 59)
                    {
                        f = (b & c) | (b & d) | (c & d);
                        k = 0x8F1BBCDC;
                    }
                    else
                    {
                        f = b ^ c ^ d;
                        k = 0xCA62C1D6;
                    }

                    uint temp = LeftRotate(a, 5) + f + e + k + w[j];
                    e = d;
                    d = c;
                    c = LeftRotate(b, 30);
                    b = a;
                    a = temp;
                }

                // Dodavanje rezultata bloka na ukupni hash
                h0 += a;
                h1 += b;
                h2 += c;
                h3 += d;
                h4 += e;
            }

            // Spajanje H0-H4 u finalni niz bajtova
            byte[] hashBytes = new byte[20];
            Array.Copy(BitConverter.GetBytes(ReverseBytes(h0)), 0, hashBytes, 0, 4);
            Array.Copy(BitConverter.GetBytes(ReverseBytes(h1)), 0, hashBytes, 4, 4);
            Array.Copy(BitConverter.GetBytes(ReverseBytes(h2)), 0, hashBytes, 8, 4);
            Array.Copy(BitConverter.GetBytes(ReverseBytes(h3)), 0, hashBytes, 12, 4);
            Array.Copy(BitConverter.GetBytes(ReverseBytes(h4)), 0, hashBytes, 16, 4);

            return Convert.ToBase64String(hashBytes);
        }

        // Pomoćna funkcija za bitwise rotaciju ulevo
        private static uint LeftRotate(uint value, int count) => (value << count) | (value >> (32 - count));

        // Pomoćna funkcija za Big-Endian konverziju
        private static uint ReverseBytes(uint value) =>
            (value & 0x000000FFU) << 24 | (value & 0x0000FF00U) << 8 |
            (value & 0x00FF0000U) >> 8 | (value & 0xFF000000U) >> 24;

        // Padding logika: dodaj '1', nule, i na kraju dužinu poruke
        private static byte[] PadMessage(byte[] data)
        {
            long originalLengthBits = data.Length * 8L;
            int paddingLength = (448 - (data.Length * 8 + 8) % 512 + 512) % 512;

            byte[] padded = new byte[data.Length + 1 + (paddingLength / 8) + 8];
            Array.Copy(data, 0, padded, 0, data.Length);

            padded[data.Length] = 0x80; // Dodaj bit '1' (kao bajt 10000000)

            // Dodaj dužinu poruke kao 64-bitni integer na kraj (Big Endian)
            for (int i = 0; i < 8; i++)
            {
                padded[padded.Length - 1 - i] = (byte)((originalLengthBits >> (i * 8)) & 0xFF);
            }

            return padded;
        }
    }
}
