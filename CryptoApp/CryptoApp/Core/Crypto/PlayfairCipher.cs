using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoApp.Core.Crypto
{
    public class PlayfairCipher : IEncryptor
    {
        private char[,] matrix = new char[5, 5];
        private readonly Dictionary<char, (int row, int col)> positions;
        private readonly char filler = 'X';

        public int BlockSize => 2;

        public PlayfairCipher()
        {
            positions = new Dictionary<char, (int row, int col)>();
        }
        private void GenerateKeyMatrix(string key)
        {
            positions.Clear();
            string normalized = Normalize(key);
            string alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ";

            string combined = new string((normalized + alphabet).Distinct().ToArray());

            int idx = 0;
            for (int r = 0; r < 5; r++)
            {
                for (int c = 0; c < 5; c++)
                {
                    char ch = combined[idx++];
                    matrix[r, c] = ch;
                    positions[ch] = (r, c);
                }
            }
        }
        byte[] IEncryptor.Encrypt(byte[] data, byte[] key, byte[] iv)
        {
            string keyStr = Encoding.UTF8.GetString(key);
            GenerateKeyMatrix(keyStr);

            string text = PrepareText(Encoding.ASCII.GetString(data));
            var sb = new StringBuilder();

            for (int i = 0; i < text.Length; i += 2)
                EncryptPair(text[i], text[i + 1], sb);

            return Encoding.ASCII.GetBytes(sb.ToString());
        }
        byte[] IEncryptor.Decrypt(byte[] data, byte[] key, byte[] iv)
        {
            string keyStr = Encoding.UTF8.GetString(key);
            GenerateKeyMatrix(keyStr);

            string text = Encoding.ASCII.GetString(data);
            var sb = new StringBuilder();

            for (int i = 0; i < text.Length; i += 2)
                DecryptPair(text[i], text[i + 1], sb);

            return Encoding.ASCII.GetBytes(sb.ToString());
        }

        private string PrepareText(string input)
        {
            string clean = Normalize(input);

            var sb = new StringBuilder();

            for (int i = 0; i < clean.Length; i++)
            {
                char a = clean[i];
                char b = (i + 1 < clean.Length) ? clean[i + 1] : filler;

                if (a == b)
                {
                    sb.Append(a).Append(filler);
                }
                else
                {
                    sb.Append(a).Append(b);
                    i++;
                }
            }

            if (sb.Length % 2 != 0)
                sb.Append(filler);

            return sb.ToString();
        }
        private string Normalize(string text)
        {
            return new string(
                text
                    .ToUpperInvariant()
                    .Where(char.IsLetter)
                    .Select(c => c == 'J' ? 'I' : c)
                    .ToArray()
            );
        }

        private void EncryptPair(char a, char b, StringBuilder sb)
        {
            var (r1, c1) = positions[a];
            var (r2, c2) = positions[b];

            if (r1 == r2) // same row
            {
                sb.Append(matrix[r1, (c1 + 1) % 5]);
                sb.Append(matrix[r2, (c2 + 1) % 5]);
            }
            else if (c1 == c2) // same column
            {
                sb.Append(matrix[(r1 + 1) % 5, c1]);
                sb.Append(matrix[(r2 + 1) % 5, c2]);
            }
            else // rectangle
            {
                sb.Append(matrix[r1, c2]);
                sb.Append(matrix[r2, c1]);
            }
        }
        private void DecryptPair(char a, char b, StringBuilder sb)
        {
            var (r1, c1) = positions[a];
            var (r2, c2) = positions[b];

            if (r1 == r2)
            {
                sb.Append(matrix[r1, (c1 + 4) % 5]);
                sb.Append(matrix[r2, (c2 + 4) % 5]);
            }
            else if (c1 == c2)
            {
                sb.Append(matrix[(r1 + 4) % 5, c1]);
                sb.Append(matrix[(r2 + 4) % 5, c2]);
            }
            else
            {
                sb.Append(matrix[r1, c2]);
                sb.Append(matrix[r2, c1]);
            }
        }
    }
}
