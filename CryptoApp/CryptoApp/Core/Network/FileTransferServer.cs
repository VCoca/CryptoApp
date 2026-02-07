using CryptoApp.Core.File;
using CryptoApp.Core.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace CryptoApp.Core.Network
{
    public class FileTransferServer
    {
        private readonly FileEncoder encoder;
        private TcpListener listener;
        private CancellationTokenSource cts;

        public FileTransferServer(FileEncoder encoder)
        {
            this.encoder = encoder;
        }

        public void Start(int port)
        {
            cts = new CancellationTokenSource();
            listener = new TcpListener(IPAddress.Any, port);
            listener.Start();

            AppLogger.Success($"Receiver listening on port {port}");

            Task.Run(() => AcceptLoop(cts.Token));
        }

        public void Stop()
        {
            cts?.Cancel();
            listener?.Stop();
            AppLogger.Info("Receiver stopped");
        }

        private async Task AcceptLoop(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync();
                _ = Task.Run(() => HandleClient(client));
            }
        }

        private async Task HandleClient(TcpClient client)
        {
            using var stream = client.GetStream();

            // 1️⃣ Read filename
            byte[] buf4 = new byte[4];
            await ReadExact(stream, buf4);
            int nameLen = BitConverter.ToInt32(buf4);

            byte[] nameBytes = new byte[nameLen];
            await ReadExact(stream, nameBytes);
            string fileName = Encoding.UTF8.GetString(nameBytes);

            // 2️⃣ Read file bytes
            await ReadExact(stream, buf4);
            int fileLen = BitConverter.ToInt32(buf4);

            byte[] fileBytes = new byte[fileLen];
            await ReadExact(stream, fileBytes);

            string encodedPath = Path.Combine("received", fileName);
            Directory.CreateDirectory("received");
            await System.IO.File.WriteAllBytesAsync(encodedPath, fileBytes);

            AppLogger.Info($"File received: {fileName}");

            // 3️⃣ Auto decode
            encoder.DecodeFile(encodedPath);
            AppLogger.Success($"File decoded: {fileName}");
        }

        private static async Task ReadExact(NetworkStream stream, byte[] buffer)
        {
            int read = 0;
            while (read < buffer.Length)
            {
                int r = await stream.ReadAsync(buffer.AsMemory(read));
                if (r == 0) throw new IOException("Connection closed");
                read += r;
            }
        }
    }
}
