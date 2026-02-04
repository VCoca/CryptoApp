using CryptoApp.Core.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoApp.Watcher
{
    public class DirectoryWatcher
    {
        private readonly FileSystemWatcher watcher;
        private readonly Action<string> onFileCreated;
        public DirectoryWatcher(Action<string> onFileCreated)
        {
            watcher = new FileSystemWatcher();
            this.onFileCreated = onFileCreated;
        }
        public void Start(string path)
        {
            watcher.Path = path;
            watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite;
            watcher.Filter = "*.*";
            watcher.Created += OnCreated;
            watcher.EnableRaisingEvents = true;
            AppLogger.Info($"Started watching directory: {path}");
        }
        public void Stop()
        {
            watcher.EnableRaisingEvents = false;
            watcher.Created -= OnCreated;
            watcher.Dispose();
            AppLogger.Info("Stopped watching directory.");
        }

        private void OnCreated(object source, FileSystemEventArgs e)
        {
            if (!WaitForFile(e.FullPath)) return;

            AppLogger.Info($"New file detected: {e.FullPath}");

            onFileCreated.Invoke(e.FullPath);
        }
        private bool WaitForFile(string path)
        {
            for (int i = 0; i < 10; i++)
            {
                try
                {
                    using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.None);
                    return true;
                }
                catch
                {
                    Thread.Sleep(300);
                }
            }
            return false;
        }
    }
}
