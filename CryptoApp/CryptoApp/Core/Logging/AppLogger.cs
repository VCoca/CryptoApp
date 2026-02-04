using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoApp.Core.Logging
{
    public static class AppLogger
    {
        private static readonly object lockObj = new();
        private static readonly string logFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "crypto.log");
        public static event Action<string>? OnLog;

        public static void Info(string message)
        {
            Log("INFO", message);
        }
        public static void Error(string message)
        {
            Log("ERROR", message);
        }
        public static void Success(string message)
        {
            Log("SUCCESS", message);
        }
        private static void Log(string level, string message)
        {
            string logEntry = $"{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} [{level}] {message}";
            lock (lockObj)
            {
                System.IO.File.AppendAllText(logFilePath, logEntry + Environment.NewLine);
            }
            Console.WriteLine(logEntry);

            OnLog?.Invoke(logEntry);
        }
    }
}
