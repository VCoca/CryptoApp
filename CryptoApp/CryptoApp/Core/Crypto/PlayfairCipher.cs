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
        // Koristimo isti set karaktera kao u prvom projektu za mapiranje bajtova
        private const string MapChars = "ABCDEFGHIKLMNOPQ";

        public int BlockSize => 2; // Nije presudno za ovaj algoritam ali neka stoji

        public PlayfairCipher()
        {
        }

        // Generisanje matrice mora biti IDENTIČNO kao u prvom projektu
        private void GenerateKeyMatrix(string key)
        {
            // 1. Priprema kljuca (J -> I, samo slova, bez duplikata)
            string k = key.ToUpper().Replace("J", "I");
            string cleanKey = new string(k.Where(c => char.IsLetter(c) && c != 'J').Distinct().ToArray());

            // 2. Dodavanje alfabeta
            string alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
            string combined = cleanKey + alphabet;

            // 3. Konacni set bez duplikata
            string finalSet = new string(combined.Distinct().ToArray());

            // 4. Popunjavanje matrice
            for (int i = 0; i < 25; i++)
            {
                matrix[i / 5, i % 5] = finalSet[i];
            }
        }

        // Helper za nalazenje pozicije slova u matrici
        private (int row, int col) GetPosition(char c)
        {
            for (int r = 0; r < 5; r++)
                for (int col = 0; col < 5; col++)
                    if (matrix[r, col] == c) return (r, col);
            return (0, 0); // Should not happen with correct mapping
        }

        byte[] IEncryptor.Encrypt(byte[] data, byte[] key, byte[] iv)
        {
            // 1. Inicijalizacija matrice kljucem
            string keyStr = Encoding.UTF8.GetString(key);
            GenerateKeyMatrix(keyStr);

            // 2. Pretvaranje sirovih bajtova u slova (Mapiranje 1 bajt -> 2 karaktera)
            // Ovo je kljucno da bi se poklopilo sa prvim projektom!
            StringBuilder sbInput = new StringBuilder();
            foreach (byte b in data)
            {
                sbInput.Append(MapChars[b >> 4]);     // Prva 4 bita
                sbInput.Append(MapChars[b & 0x0F]);   // Druga 4 bita
            }
            string textToEncrypt = sbInput.ToString();

            // 3. Playfair Enkripcija
            StringBuilder sbEncrypted = new StringBuilder();
            for (int i = 0; i < textToEncrypt.Length; i += 2)
            {
                char a = textToEncrypt[i];
                char b = textToEncrypt[i + 1];
                var (r1, c1) = GetPosition(a);
                var (r2, c2) = GetPosition(b);

                if (r1 == r2) // Isti red
                {
                    sbEncrypted.Append(matrix[r1, (c1 + 1) % 5]);
                    sbEncrypted.Append(matrix[r2, (c2 + 1) % 5]);
                }
                else if (c1 == c2) // Ista kolona
                {
                    sbEncrypted.Append(matrix[(r1 + 1) % 5, c1]);
                    sbEncrypted.Append(matrix[(r2 + 1) % 5, c2]);
                }
                else // Pravougaonik
                {
                    sbEncrypted.Append(matrix[r1, c2]);
                    sbEncrypted.Append(matrix[r2, c1]);
                }
            }

            // Vracamo enkriptovan string kao bajtove
            return Encoding.ASCII.GetBytes(sbEncrypted.ToString());
        }

        byte[] IEncryptor.Decrypt(byte[] data, byte[] key, byte[] iv)
        {
            // 1. Inicijalizacija matrice
            string keyStr = Encoding.UTF8.GetString(key);
            GenerateKeyMatrix(keyStr);

            // 2. Podaci su sacuvani kao ASCII karakteri
            string cipher = Encoding.ASCII.GetString(data);
            StringBuilder decryptedText = new StringBuilder();

            // 3. Playfair Dekripcija
            for (int i = 0; i < cipher.Length; i += 2)
            {
                char a = cipher[i];
                char b = cipher[i + 1];
                var (r1, c1) = GetPosition(a);
                var (r2, c2) = GetPosition(b);

                if (r1 == r2)
                {
                    decryptedText.Append(matrix[r1, (c1 + 4) % 5]); // +4 je isto sto i -1 u modulu 5
                    decryptedText.Append(matrix[r2, (c2 + 4) % 5]);
                }
                else if (c1 == c2)
                {
                    decryptedText.Append(matrix[(r1 + 4) % 5, c1]);
                    decryptedText.Append(matrix[(r2 + 4) % 5, c2]);
                }
                else
                {
                    decryptedText.Append(matrix[r1, c2]);
                    decryptedText.Append(matrix[r2, c1]);
                }
            }

            // 4. Rekonstrukcija originalnih bajtova iz dekriptovanih slova
            string text = decryptedText.ToString();
            byte[] original = new byte[text.Length / 2];

            for (int i = 0; i < original.Length; i++)
            {
                int high = MapChars.IndexOf(text[i * 2]);
                int low = MapChars.IndexOf(text[i * 2 + 1]);

                // Spajamo dva dela nazad u jedan bajt
                original[i] = (byte)((high << 4) | low);
            }

            return original;
        }
    }
}
