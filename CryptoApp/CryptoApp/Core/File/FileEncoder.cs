using CryptoApp.Core.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using CryptoApp.Core.Logging;

namespace CryptoApp.Core.File
{
    public class FileEncoder
    {
        private readonly string outputDirectoryEncoded;
        private readonly string outputDirectoryDecoded;
        private readonly bool useSHA;
        private const int BufferSize = 64 * 1024; // 64 KB

        public FileEncoder(string outputDirectoryEncoded, string outputDirectoryDecoded, bool useSHA)
        {
            this.outputDirectoryEncoded = outputDirectoryEncoded;
            this.outputDirectoryDecoded = outputDirectoryDecoded;
            this.useSHA = useSHA;
        }
        public string EncodeFile(string inputPath, IEncryptor encryptor, CipherType cipherType, byte[] key)
        {
            AppLogger.Info($"Encoding file: {inputPath} using {cipherType} cipher.");
            Directory.CreateDirectory(outputDirectoryEncoded);

            var fileInfo = new FileInfo(inputPath);
            string outputPath = Path.Combine(outputDirectoryEncoded, fileInfo.Name + ".enc");

            string sha1Hash = "";
            if (cipherType != CipherType.Playfair && useSHA)
            {
                using var fs = new FileStream(inputPath, FileMode.Open, FileAccess.Read);
                using var sha1 = SHA1.Create();
                sha1Hash = Convert.ToBase64String(sha1.ComputeHash(fs));
                AppLogger.Info($"Computed SHA-1 hash: {sha1Hash}");
            }

            byte[] iv = Array.Empty<byte>();
            string ivString = string.Empty;

            if(cipherType == CipherType.RC6_PCBC)
            {
                iv = RandomNumberGenerator.GetBytes(encryptor.BlockSize);
                ivString = Convert.ToBase64String(iv);
                AppLogger.Info($"Generated IV (Base64): {ivString}");
            }

            using (var inputStreanm = new FileStream(inputPath, FileMode.Open, FileAccess.Read))
            using (var outputStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write))
            {
                var header = new MetadataHeader(
                    name: fileInfo.Name,
                    size: fileInfo.Length,
                    createdAt: fileInfo.CreationTimeUtc,
                    encryption: cipherType.ToString(),
                    hash: sha1Hash
                    );
                byte[] headerBytes = Encoding.UTF8.GetBytes(header.ToJson());
                outputStream.Write(BitConverter.GetBytes(headerBytes.Length));
                outputStream.Write(headerBytes);

                if (iv.Length > 0) outputStream.Write(iv);

                byte[] buffer = new byte[BufferSize];
                int bytesRead;
                while ((bytesRead = inputStreanm.Read(buffer, 0, buffer.Length)) > 0)
                {
                    byte[] dataToEncrypt = buffer;
                    if (bytesRead < buffer.Length)
                    {
                        Array.Resize(ref dataToEncrypt, bytesRead);
                    }

                    // Napomena: Za blokovske šifre (RC6), poslednji blok mora imati padding.
                    // Tvoj trenutni IEncryptor.Encrypt to radi interno.
                    byte[] encryptedChunk = encryptor.Encrypt(dataToEncrypt, key, iv);
                    outputStream.Write(encryptedChunk);
                }
            }      

            AppLogger.Success($"File encoded successfully: {outputPath}");
            return outputPath;
        }

        public string DecodeFile(string inputPath, byte[] key)
        {
            AppLogger.Info($"Decoding file: {inputPath}");
            Directory.CreateDirectory(outputDirectoryDecoded);

            using var input = new FileStream(inputPath, FileMode.Open, FileAccess.Read);

            byte[] lenBytes = new byte[4];
            input.ReadExactly(lenBytes);
            int headerLength = BitConverter.ToInt32(lenBytes);

            byte[] headerBytes = new byte[headerLength];
            input.ReadExactly(headerBytes);

            string headerJson = Encoding.UTF8.GetString(headerBytes);
            var header = MetadataHeader.FromJson(headerJson);

            CipherType cipherType = Enum.Parse<CipherType>(header.encryption);
            IEncryptor encryptor = GetEncryptor(cipherType);

            byte[] iv = (cipherType == CipherType.RC6_PCBC) ? new byte[encryptor.BlockSize] : Array.Empty<byte>();
            if (iv.Length > 0) input.ReadExactly(iv);

            string outputPath = Path.Combine(outputDirectoryDecoded, header.name);

            using (var output = new FileStream(outputPath, FileMode.Create, FileAccess.Write))
            {
                byte[] buffer = new byte[BufferSize]; // Mora biti usklađeno sa BlockSize enkriptora
                int bytesRead;
                while ((bytesRead = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    byte[] dataToDecrypt = buffer;
                    if (bytesRead < buffer.Length) Array.Resize(ref dataToDecrypt, bytesRead);

                    byte[] decryptedChunk = encryptor.Decrypt(dataToDecrypt, key, iv);

                    // Pišemo samo onoliko koliko je originalno bilo (uklanjanje paddinga na kraju fajla)
                    long remaining = header.size - output.Position;
                    int bytesToWrite = (int)Math.Min(decryptedChunk.Length, remaining);

                    if (bytesToWrite > 0)
                        output.Write(decryptedChunk, 0, bytesToWrite);
                }
            }
            if (cipherType != CipherType.Playfair && useSHA && !string.IsNullOrEmpty(header.hash))
            {
                AppLogger.Info("Vrši se provera integriteta fajla (SHA-1)...");

                using var fs = new FileStream(outputPath, FileMode.Open, FileAccess.Read);
                using var sha1 = SHA1.Create();
                string computedHash = Convert.ToBase64String(sha1.ComputeHash(fs));

                if (computedHash == header.hash)
                {
                    AppLogger.Success("Integritet potvrđen! Hash vrednosti se poklapaju.");
                }
                else
                {
                    AppLogger.Error("UPOZORENJE: Integritet narušen! Hash vrednosti se NE poklapaju.");
                    System.IO.File.Delete(outputPath);
                    throw new CryptographicException("Hash mismatch - file might be corrupted or tampered with.");
                }
            }
            AppLogger.Success($"Fajl dekodiran uspešno: {outputPath}");
            return outputPath;
        }

        private IEncryptor GetEncryptor(CipherType type) => type switch
        {
            CipherType.Playfair => new PlayfairCipher(),
            CipherType.RC6_PCBC => new PCBCMode(),
            _ => new RC6Cipher()
        };
    }
}
