using CryptoApp.Core.Crypto;
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
        public async Task SendFileAsync(string filePath, string host, int port)
        {
            using var client = new TcpClient();
            await client.ConnectAsync(host, port);
            using var stream = client.GetStream();

            string fileName = Path.GetFileName(filePath);
            byte[] nameBytes = Encoding.UTF8.GetBytes(fileName);
            byte[] nameLen = BitConverter.GetBytes(nameBytes.Length);
            byte[] fileBytes = await System.IO.File.ReadAllBytesAsync(filePath);
            byte[] fileLen = BitConverter.GetBytes(fileBytes.Length);

            await stream.WriteAsync(nameLen);
            await stream.WriteAsync(nameBytes);
            await stream.WriteAsync(fileLen);
            await stream.WriteAsync(fileBytes);

            AppLogger.Success($"File sent: {fileName}");
        }
    }
}
