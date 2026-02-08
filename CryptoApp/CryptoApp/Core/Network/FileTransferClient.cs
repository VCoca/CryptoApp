using CryptoApp.Core.Crypto;
using CryptoApp.Core.File;
using CryptoApp.Core.Logging;
using System;
using System.Collections.Generic;
using System.IO;
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
            var networkStream = client.GetStream();
            using var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read); using var stream = client.GetStream();

            string fileName = Path.GetFileName(filePath);
            byte[] nameBytes = Encoding.UTF8.GetBytes(fileName);

            // 1. Šaljemo dužinu imena (4 bajta)
            await networkStream.WriteAsync(BitConverter.GetBytes(nameBytes.Length));
            // 2. Šaljemo ime
            await networkStream.WriteAsync(nameBytes);
            // 3. Šaljemo dužinu fajla kao LONG (8 bajtova) - podržava TB fajlove
            await networkStream.WriteAsync(BitConverter.GetBytes(fileStream.Length));

            // 4. Strimujemo sadržaj direktno sa diska u mrežni stream bez punjenja RAM-a
            byte[] buffer = new byte[64 * 1024]; // 64KB bafer
            int bytesRead;
            while ((bytesRead = await fileStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
            {
                await networkStream.WriteAsync(buffer, 0, bytesRead);
            }

            AppLogger.Success($"File sent: {fileName}");
        }
    }
}
