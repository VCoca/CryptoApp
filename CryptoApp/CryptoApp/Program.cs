using CryptoApp.Core.File;
using CryptoApp.Watcher;
using System.Text;

FileEncoder encoder = new FileEncoder(
    encryptor: new CryptoApp.Core.Crypto.PCBCMode(),
    outputDirectoryEncoded: "D:\\cryptoTest\\encoded",
    outputDirectoryDecoded: "D:\\cryptoTest\\decoded",
    key: Encoding.UTF8.GetBytes("MONARCHY123"),
    cipherType: CipherType.RC6_PCBC,
    useSHA: true
);

var watcher = new DirectoryWatcher((filePath) =>
{
    encoder.EncodeFile(filePath);
    Thread.Sleep(500); // Wait for encoding to finish
    string encodedPath = Path.Combine("D:\\cryptoTest\\encoded", Path.GetFileName(filePath) + ".enc");
    encoder.DecodeFile(encodedPath);
});

watcher.Start("D:\\cryptoTest");

while (true)
{
    Thread.Sleep(1000);
    if (Console.KeyAvailable && Console.ReadKey(true).Key == ConsoleKey.Escape)
    {
        break;
    }
}

watcher.Stop();