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

            byte[] plaintext = System.IO.File.ReadAllBytes(inputPath);
            string sha1Hash = (cipherType == CipherType.Playfair || !useSHA) ? "" : SHA1Hasher.SHA1Hash(plaintext);

            if (cipherType != CipherType.Playfair && useSHA)
                AppLogger.Info($"Computed SHA-1 hash: {sha1Hash}");

            byte[] iv = Array.Empty<byte>();
            string ivString = string.Empty;

            if(cipherType == CipherType.RC6_PCBC)
            {
                iv = RandomNumberGenerator.GetBytes(encryptor.BlockSize);
                ivString = Convert.ToBase64String(iv);
                AppLogger.Info($"Generated IV (Base64): {ivString}");
            }

            var header = new MetadataHeader(
                name: fileInfo.Name,
                size: fileInfo.Length,
                createdAt: fileInfo.CreationTimeUtc,
                encryption: cipherType.ToString(),
                hash: sha1Hash
            );
            byte[] headerBytes = Encoding.UTF8.GetBytes(header.ToJson());
            byte[] headerLength = BitConverter.GetBytes(headerBytes.Length);

            byte[] ciphertext = encryptor.Encrypt(plaintext, key, iv);

            using var output = new FileStream(outputPath, FileMode.Create);
            output.Write(headerLength);
            output.Write(headerBytes);

            if (cipherType == CipherType.RC6_PCBC)
                output.Write(iv);

            output.Write(ciphertext);

            AppLogger.Success($"File encoded successfully: {outputPath}");
            return outputPath;
        }

        public string DecodeFile(string inputPath, byte[] key)
        {
            AppLogger.Info($"Decoding file: {inputPath}");
            Directory.CreateDirectory(outputDirectoryDecoded);
            using var input = new FileStream(inputPath, FileMode.Open, FileAccess.Read);

            byte[] lenBytes = new byte[4];
            ReadFully(input, lenBytes, 0, 4);
            int headerLength = BitConverter.ToInt32(lenBytes);

            byte[] headerBytes = new byte[headerLength];
            ReadFully(input, headerBytes, 0, headerLength);

            string headerJson = Encoding.UTF8.GetString(headerBytes);
            var header = MetadataHeader.FromJson(headerJson);

            CipherType cipherType = Enum.Parse<CipherType>(header.encryption);
            IEncryptor encryptor = cipherType switch
            {
                CipherType.Playfair => new PlayfairCipher(),
                CipherType.RC6_PCBC => new PCBCMode(),
                _ => new RC6Cipher()
            };

            byte[] iv = Array.Empty<byte>();
            if (cipherType == CipherType.RC6_PCBC)
            {
                iv = new byte[encryptor.BlockSize];
                ReadFully(input, iv, 0, iv.Length); // čitaj IV pre ciphertext-a
            }

            long cipherLength = input.Length - 4 - headerLength;

            if (cipherType == CipherType.RC6_PCBC)
                cipherLength -= encryptor.BlockSize;

            if (cipherLength > int.MaxValue)
                throw new NotSupportedException("File too large");

            byte[] ciphertext = new byte[cipherLength];
            ReadFully(input, ciphertext, 0, (int)cipherLength);

            byte[] plaintext = encryptor.Decrypt(ciphertext, key, iv);

            Array.Resize(ref plaintext, (int)header.size);

            if (cipherType != CipherType.Playfair && useSHA)
            {

                string computedHash = SHA1Hasher.SHA1Hash(plaintext);
                if (computedHash != header.hash)
                {
                    AppLogger.Error("File integrity check failed! SHA-1 mismatch.");
                    throw new InvalidOperationException("File integrity check failed! SHA-1 mismatch.");
                }
                AppLogger.Success("File integrity check passed. SHA-1 hash matches.");
            }

            string outputPath = Path.Combine(outputDirectoryDecoded, header.name);
            System.IO.File.WriteAllBytes(outputPath, plaintext);
            AppLogger.Success($"File decoded successfully: {outputPath}");
            return outputPath;
        }

        private static void ReadFully(Stream stream, byte[] buffer, int offset, int count)
        {
            int bytesRead = 0;
            while (bytesRead < count)
            {
                int read = stream.Read(buffer, offset + bytesRead, count - bytesRead);
                if (read == 0)
                    throw new EndOfStreamException("Unexpected end of file");
                bytesRead += read;
            }
        }
    }
}
