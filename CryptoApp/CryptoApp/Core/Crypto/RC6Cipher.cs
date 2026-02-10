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
        private readonly int Pw = unchecked((int)0xB7E15163);
        private readonly int Qw = unchecked((int)0x9E3779B9);

        private uint[] S;                    // expanded key
        public int BlockSize => 16;         // 128-bit block


        public byte[] Encrypt(byte[] data, byte[] key, byte[] iv)
        {
            if (S == null) KeyExpansion(key);

            uint A = BitConverter.ToUInt32(data, 0);
            uint B = BitConverter.ToUInt32(data, 4);
            uint C = BitConverter.ToUInt32(data, 8);
            uint D = BitConverter.ToUInt32(data, 12);

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

        public byte[] Decrypt(byte[] data, byte[] key, byte[] iv)
        {
            if (S == null) KeyExpansion(key);

            uint A = BitConverter.ToUInt32(data, 0);
            uint B = BitConverter.ToUInt32(data, 4);
            uint C = BitConverter.ToUInt32(data, 8);
            uint D = BitConverter.ToUInt32(data, 12);

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

        private void KeyExpansion(byte[] key)
        {
            int c = key.Length / 4;
            if (key.Length % 4 != 0) c++;

            uint[] L = new uint[c];
            for (int i = 0; i < key.Length; i++)
                L[i / 4] |= (uint)key[i] << (8 * (i % 4));

            int t = 2 * r + 4;
            S = new uint[t];
            S[0] = (uint)Pw;
            for (int i = 1; i < t; i++)
                S[i] = S[i - 1] + (uint)Qw;

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

        public void TestRC6Vectors()
        {
            // Test 1: Null key (16 bytes), null plaintext
            byte[] key1 = new byte[16]; // 00 00 ... 00
            byte[] plaintext1 = new byte[16]; // 00 00 ... 00
            KeyExpansion(key1); // Pozovi KeyExpansion jer S nije privatno inicijalizovan u konstruktoru
            byte[] ciphertext1 = Encrypt(plaintext1, key1, null); // iv null jer nije potreban
            AppLogger.Info("Test 1 Ciphertext: " + BitConverter.ToString(ciphertext1).Replace("-", " ")); // Očekivano: 8F C3 A5 36 56 B1 F7 78 C1 29 DF 4E 98 48 A4 1E

            // Test 2: Key 16 bytes
            byte[] key2 = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78 };
            byte[] plaintext2 = { 0x02, 0x13, 0x24, 0x35, 0x46, 0x57, 0x68, 0x79, 0x8a, 0x9b, 0xac, 0xbd, 0xce, 0xdf, 0xe0, 0xf1 };
            KeyExpansion(key2);
            byte[] ciphertext2 = Encrypt(plaintext2, key2, null);
            AppLogger.Info("Test 2 Ciphertext: " + BitConverter.ToString(ciphertext2).Replace("-", " ")); // Očekivano: 52 4E 19 2F 47 15 C6 23 1F 51 F6 36 7E A4 3F 18

            // Test 3: Key 24 bytes
            byte[] key3 = new byte[24]; // 00 00 ... 00
            byte[] plaintext3 = new byte[16]; // 00 00 ... 00
            KeyExpansion(key3);
            byte[] ciphertext3 = Encrypt(plaintext3, key3, null);
            AppLogger.Info("Test 3 Ciphertext: " + BitConverter.ToString(ciphertext3).Replace("-", " ")); // Očekivano: 6C D6 1B CB 19 0B 30 38 4E 8A 3F 16 86 90 AE 82

            // Test 4: Key 24 bytes (non-null)
            byte[] key4 = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0 };
            byte[] plaintext4 = { 0x02, 0x13, 0x24, 0x35, 0x46, 0x57, 0x68, 0x79, 0x8a, 0x9b, 0xac, 0xbd, 0xce, 0xdf, 0xe0, 0xf1 };
            KeyExpansion(key4);
            byte[] ciphertext4 = Encrypt(plaintext4, key4, null);
            AppLogger.Info("Test 4 Ciphertext: " + BitConverter.ToString(ciphertext4).Replace("-", " ")); // Očekivano: 68 83 29 D0 19 E5 05 04 1E 52 E9 2A F9 52 91 D4

            // Test 5: Key 32 bytes (null)
            byte[] key5 = new byte[32]; // 00 00 ... 00
            byte[] plaintext5 = new byte[16]; // 00 00 ... 00
            KeyExpansion(key5);
            byte[] ciphertext5 = Encrypt(plaintext5, key5, null);
            AppLogger.Info("Test 5 Ciphertext: " + BitConverter.ToString(ciphertext5).Replace("-", " ")); // Očekivano: 8F 5F BD 05 10 D1 5F A8 93 FA 3F DA 6E 85 7E C2

            // Test 6: Key 32 bytes (non-null)
            byte[] key6 = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe };
            byte[] plaintext6 = { 0x02, 0x13, 0x24, 0x35, 0x46, 0x57, 0x68, 0x79, 0x8a, 0x9b, 0xac, 0xbd, 0xce, 0xdf, 0xe0, 0xf1 };
            KeyExpansion(key6);
            byte[] ciphertext6 = Encrypt(plaintext6, key6, null);
            AppLogger.Info("Test 6 Ciphertext: " + BitConverter.ToString(ciphertext6).Replace("-", " ")); // Očekivano: C8 24 18 16 F0 D7 E4 89 20 AD 16 A1 67 4E 5D 48

            // Dodaj i dekripciju za provjeru (treba vratiti plaintext, primjer za test 6)
            byte[] decrypted6 = Decrypt(ciphertext6, key6, null);
            AppLogger.Info("Test 6 Decrypted: " + BitConverter.ToString(decrypted6).Replace("-", " "));
        }
    }
}
