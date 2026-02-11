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
            if (useSHA)
            {
                using (var sha1 = SHA1.Create())
                using (var fs = new FileStream(inputPath, FileMode.Open, FileAccess.Read))
                    sha1Hash = Convert.ToBase64String(sha1.ComputeHash(fs));
            }

            byte[] iv = Array.Empty<byte>();
            string ivString = string.Empty;

            if(cipherType == CipherType.RC6_PCBC)
            {
                iv = RandomNumberGenerator.GetBytes(encryptor.BlockSize);
                ivString = Convert.ToBase64String(iv);
                AppLogger.Info($"Generated IV (Base64): {ivString}");
            }

            using (var inputStream = new FileStream(inputPath, FileMode.Open, FileAccess.Read))
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
                bool last;

                while ((bytesRead = inputStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    last = inputStream.Position == inputStream.Length;
                    byte[] chunk = new byte[bytesRead];
                    Array.Copy(buffer, chunk, bytesRead);

                    if (cipherType == CipherType.RC6 || cipherType == CipherType.RC6_PCBC)
                    {
                        if (last)
                        {
                            int pad = encryptor.BlockSize - (chunk.Length % encryptor.BlockSize);
                            if (pad == 0) pad = encryptor.BlockSize;
                            byte[] padded = new byte[chunk.Length + pad];
                            Array.Copy(chunk, padded, chunk.Length);
                            for (int k = chunk.Length; k < padded.Length; k++)
                                padded[k] = (byte)pad;
                            chunk = padded;
                        }
                        else if (chunk.Length % encryptor.BlockSize != 0)
                        {
                            throw new Exception("Non-final chunk must be multiple of block size.");
                        }
                    }
                    byte[] encrypted = encryptor.Encrypt(chunk, key, iv);
                    outputStream.Write(encrypted);
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
                byte[] buffer = new byte[BufferSize];
                int bytesRead;
                while ((bytesRead = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    byte[] chunk = new byte[bytesRead];
                    Array.Copy(buffer, chunk, bytesRead);

                    byte[] decrypted = encryptor.Decrypt(chunk, key, iv);

                    bool last = input.Position == input.Length;
                    if (last && (cipherType == CipherType.RC6 || cipherType == CipherType.RC6_PCBC))
                    {
                        int pad = decrypted[decrypted.Length - 1];
                        if (pad > 0 && pad <= 16)
                        {
                            Array.Resize(ref decrypted, decrypted.Length - pad);
                        }
                    }

                    output.Write(decrypted);
                }
            }
            if (useSHA && !string.IsNullOrEmpty(header.hash))
            {
                AppLogger.Info("Vrši se provera integriteta fajla (SHA-1)...");
                string computedHash;
                using (var sha1 = SHA1.Create())
                using (var fs = new FileStream(inputPath, FileMode.Open, FileAccess.Read))
                    computedHash = Convert.ToBase64String(sha1.ComputeHash(fs));

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
