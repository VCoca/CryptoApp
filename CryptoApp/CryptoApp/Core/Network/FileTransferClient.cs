using CryptoApp.Core.File;
using CryptoApp.Core.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace CryptoApp.Core.Network
{
    public class FileTransferClient
    {
        private readonly FileEncoder encoder;

        public FileTransferClient(FileEncoder encoder)
        {
            this.encoder = encoder;
        }

        public async Task SendFileAsync(string filePath, string host, int port)
        {
            AppLogger.Info($"Connecting to {host}:{port}");

            using var client = new TcpClient();
            await client.ConnectAsync(host, port);

            using var stream = client.GetStream();

            // 1️⃣ Encode file
            string encodedPath = encoder.EncodeFile(filePath);
            byte[] fileBytes = await System.IO.File.ReadAllBytesAsync(encodedPath);
            string fileName = Path.GetFileName(encodedPath);

            byte[] nameBytes = Encoding.UTF8.GetBytes(fileName);
            byte[] nameLen = BitConverter.GetBytes(nameBytes.Length);
            byte[] fileLen = BitConverter.GetBytes(fileBytes.Length);

            // 2️⃣ Send header + file
            await stream.WriteAsync(nameLen);
            await stream.WriteAsync(nameBytes);
            await stream.WriteAsync(fileLen);
            await stream.WriteAsync(fileBytes);

            AppLogger.Success($"File sent: {fileName}");
        }
    }
}
