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
        private readonly Func<byte[]> keyProvider;
        private TcpListener listener;
        private CancellationTokenSource cts;

        public FileTransferServer(FileEncoder encoder, Func<byte[]> keyProvider)
        {
            this.encoder = encoder;
            this.keyProvider = keyProvider;
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
            try
            {
                using var stream = client.GetStream();

                // --- Read filename ---
                byte[] buf4 = new byte[4];
                await ReadExact(stream, buf4);
                int nameLen = BitConverter.ToInt32(buf4);

                byte[] nameBytes = new byte[nameLen];
                await ReadExact(stream, nameBytes);
                string fileName = Encoding.UTF8.GetString(nameBytes);

                // --- Read file length ---
                byte[] buf8 = new byte[8];
                await ReadExact(stream, buf8);
                long fileLen = BitConverter.ToInt64(buf8);

                string encodedPath = Path.Combine("received", fileName);
                Directory.CreateDirectory("received");

                using (var fs = System.IO.File.Create(encodedPath))
                {
                    byte[] buffer = new byte[8192];
                    long remaining = fileLen;

                    while (remaining > 0)
                    {
                        int read = await stream.ReadAsync(buffer, 0, (int)Math.Min(buffer.Length, remaining));
                        if (read == 0) throw new IOException("Connection closed");
                        await fs.WriteAsync(buffer, 0, read);
                        remaining -= read;
                    }
                }

                AppLogger.Info($"File received: {fileName}");

                // --- Decode using header-selected cipher ---
                byte[] key = keyProvider();
                encoder.DecodeFile(encodedPath, key);

                AppLogger.Success($"File decoded: {fileName}");
            }
            catch (Exception ex)
            {
                AppLogger.Error($"Receiver error: {ex.Message}");
            }
            finally
            {
                client.Close();
            }
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
