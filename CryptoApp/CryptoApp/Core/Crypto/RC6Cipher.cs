using CryptoApp.Core.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoApp.Core.Crypto
{
    public class RC6Cipher : IEncryptor
    {
        private readonly int w = 32;       // bit po reči
        private readonly int r = 20;       // broj rundi
        private readonly uint Pw = 0xB7E15163;
        private readonly uint Qw = 0x9E3779B9;

        private uint[] S;                    // expanded key
        public int BlockSize => 16;         // 128-bit block


        public byte[] Encrypt(byte[] data, byte[] key, byte[] iv)
        {
            if (S == null) KeyExpansion(key);

            // Rezultat mora biti iste dužine kao ulazni podaci
            byte[] result = new byte[data.Length];

            // Prolazimo kroz podatke u koracima od 16 bajtova (BlockSize)
            for (int i = 0; i < data.Length; i += 16)
            {
                byte[] block = new byte[16];
                // Uzimamo trenutni blok
                Array.Copy(data, i, block, 0, 16);

                // Kriptujemo samo taj blok
                byte[] encryptedBlock = ProcessBlockEncrypt(block);

                // Vraćamo ga u rezultat
                Array.Copy(encryptedBlock, 0, result, i, 16);
            }

            return result;
        }

        public byte[] Decrypt(byte[] data, byte[] key, byte[] iv)
        {
            if (S == null) KeyExpansion(key);

            byte[] result = new byte[data.Length];

            for (int i = 0; i < data.Length; i += 16)
            {
                byte[] block = new byte[16];
                Array.Copy(data, i, block, 0, 16);

                byte[] decryptedBlock = ProcessBlockDecrypt(block);

                Array.Copy(decryptedBlock, 0, result, i, 16);
            }

            return result;
        }

        private void KeyExpansion(byte[] key)
        {
            int c = key.Length / 4;
            if (key.Length % 4 != 0) c++;

            // Sigurnosna provera ako je kljuc prazan (iako ne bi trebalo)
            if (c == 0) c = 1;

            uint[] L = new uint[c];
            for (int i = 0; i < key.Length; i++)
                L[i / 4] = (L[i / 4] & ~(0xFFu << (8 * (i % 4)))) | ((uint)key[i] << (8 * (i % 4)));

            int t = 2 * r + 4;
            S = new uint[t];
            S[0] = Pw;
            for (int i = 1; i < t; i++)
                S[i] = S[i - 1] + Qw;

            uint A = 0, B = 0;
            int iIndex = 0, jIndex = 0;
            int n = 3 * Math.Max(t, c);

            for (int k = 0; k < n; k++)
            {
                A = S[iIndex] = RotateLeft(S[iIndex] + A + B, 3);
                B = L[jIndex] = RotateLeft(L[jIndex] + A + B, (int)(A + B));
                iIndex = (iIndex + 1) % t;
                jIndex = (jIndex + 1) % c;
            }
        }

        private byte[] ProcessBlockEncrypt(byte[] block)
        {
            uint A = BitConverter.ToUInt32(block, 0);
            uint B = BitConverter.ToUInt32(block, 4);
            uint C = BitConverter.ToUInt32(block, 8);
            uint D = BitConverter.ToUInt32(block, 12);

            B += S[0];
            D += S[1];

            for (int i = 1; i <= r; i++)
            {
                uint t = RotateLeft(B * (2 * B + 1), 5);
                uint u = RotateLeft(D * (2 * D + 1), 5);
                A = RotateLeft(A ^ t, (int)u) + S[2 * i];
                C = RotateLeft(C ^ u, (int)t) + S[2 * i + 1];

                uint temp = A; A = B; B = C; C = D; D = temp;
            }

            A += S[2 * r + 2];
            C += S[2 * r + 3];

            byte[] cipher = new byte[16];
            Array.Copy(BitConverter.GetBytes(A), 0, cipher, 0, 4);
            Array.Copy(BitConverter.GetBytes(B), 0, cipher, 4, 4);
            Array.Copy(BitConverter.GetBytes(C), 0, cipher, 8, 4);
            Array.Copy(BitConverter.GetBytes(D), 0, cipher, 12, 4);

            return cipher;
        }

        private byte[] ProcessBlockDecrypt(byte[] block)
        {
            uint A = BitConverter.ToUInt32(block, 0);
            uint B = BitConverter.ToUInt32(block, 4);
            uint C = BitConverter.ToUInt32(block, 8);
            uint D = BitConverter.ToUInt32(block, 12);

            C -= S[2 * r + 3];
            A -= S[2 * r + 2];

            for (int i = r; i >= 1; i--)
            {
                uint temp = D; D = C; C = B; B = A; A = temp;

                uint t = RotateLeft(B * (2 * B + 1), 5);
                uint u = RotateLeft(D * (2 * D + 1), 5);
                C = RotateRight(C - S[2 * i + 1], (int)t) ^ u;
                A = RotateRight(A - S[2 * i], (int)u) ^ t;
            }

            D -= S[1];
            B -= S[0];

            byte[] plain = new byte[16];
            Array.Copy(BitConverter.GetBytes(A), 0, plain, 0, 4);
            Array.Copy(BitConverter.GetBytes(B), 0, plain, 4, 4);
            Array.Copy(BitConverter.GetBytes(C), 0, plain, 8, 4);
            Array.Copy(BitConverter.GetBytes(D), 0, plain, 12, 4);

            return plain;
        }

        private static uint RotateLeft(uint x, int y)
        {
            y &= 31;
            return (x << y) | (x >> (32 - y));
        }

        private static uint RotateRight(uint x, int y)
        {
            y &= 31;
            return (x >> y) | (x << (32 - y));
        }     
    }
}
