using CryptoApp.Core.File;
using CryptoApp.Core.Logging;
using Microsoft.Win32;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using CryptoApp.Core.Crypto;
using CryptoApp.Watcher;
using CryptoApp.Core.Network;

namespace CryptoApp.UI
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private DirectoryWatcher watcher;
        private bool watcherRunning = false;
        private FileTransferServer server;

        public MainWindow()
        {
            InitializeComponent();
            AppLogger.OnLog += msg => Dispatcher.Invoke(() => LogList.Items.Insert(0, msg));
            UpdateUIState();
        }

        // ===================== UI State Logic =====================

        private void UpdateUIState()
        {
            bool folderSelected = !string.IsNullOrWhiteSpace(WatchFolderBox.Text);
            bool algoSelected = AlgorithmBox.SelectedItem != null;

            StartWatcherBtn.IsEnabled = !watcherRunning && folderSelected && algoSelected;
            StopWatcherBtn.IsEnabled = watcherRunning;
            ManualEncodeBtn.IsEnabled = !watcherRunning;

            if (AlgorithmBox.Text == "Playfair")
                ModeBox.IsEnabled = true;
            else
                ModeBox.IsEnabled = false;
        }

        // ===================== Folder Browsing =====================

        private void Browse_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFolderDialog();
            if (dlg.ShowDialog() == true)
            {
                WatchFolderBox.Text = dlg.FolderName;
                UpdateUIState();
            }
        }

        private void BrowseOutput_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFolderDialog();
            if (dlg.ShowDialog() == true)
            {
                OutputFolderBox.Text = dlg.FolderName;
            }
        }

        // ===================== Watcher Control =====================

        private void StartWatcher_Click(object sender, RoutedEventArgs e)
        {
            var encoder = BuildEncoder();
            var encryptor = BuildEncryptor();
            var cipherType = BuildCipherType();
            var key = GetKey();

            watcher = new DirectoryWatcher(path =>
            {
                _ = Task.Run(() =>
                {
                    try
                    {
                        encoder.EncodeFile(path, encryptor, cipherType, key);
                        AppLogger.Success($"Encoded: {System.IO.Path.GetFileName(path)}");
                    }
                    catch (Exception ex)
                    {
                        AppLogger.Error($"Encode failed: {ex.Message}");
                    }
                });
            });

            watcher.Start(WatchFolderBox.Text);
            watcherRunning = true;
            UpdateUIState();
        }

        private void StopWatcher_Click(object sender, RoutedEventArgs e)
        {
            watcher?.Stop();
            watcherRunning = false;

            AppLogger.Info("Directory watcher stopped");
            UpdateUIState();
        }

        // ===================== Manual Encoding =====================

        private void ManualEncode_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog();
            if (dlg.ShowDialog() != true) return;

            var encoder = BuildEncoder();
            var encryptor = BuildEncryptor();
            var cipherType = BuildCipherType();
            var key = GetKey();

            try
            {
                _ = Task.Run(() => encoder.EncodeFile(dlg.FileName, encryptor, cipherType, key));
                AppLogger.Success("File manually encoded");
            }
            catch (Exception ex)
            {
                AppLogger.Error($"Manual encode failed: {ex.Message}");
            }
        }

        // ===================== Algorithm Logic =====================

        private void AlgorithmBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            UpdateUIState();
        }

        // ===================== Encoder Factory =====================

        private async void SendFile_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog();
            if (dlg.ShowDialog() != true) return;

            var client = new FileTransferClient();

            await client.SendFileAsync(dlg.FileName, HostBox.Text, int.Parse(PortBox.Text));
        }
        private void StartReceiver_Click(object sender, RoutedEventArgs e)
        {
            var encoder = BuildEncoder();
            server = new FileTransferServer(encoder, GetKey);
            server.Start(int.Parse(PortBox.Text));
        }

        private void StopReceiver_Click(object sender, RoutedEventArgs e)
        {
            server.Stop();
        }

        private IEncryptor BuildEncryptor()
        {
            if (AlgorithmBox.Text == "Playfair")
                return new PlayfairCipher();
            if (ModeBox.Text == "PCBC")
                return new PCBCMode();
            return new RC6Cipher();
        }

        private CipherType BuildCipherType()
        {
            if (AlgorithmBox.Text == "Playfair")
                return CipherType.Playfair;
            if (ModeBox.Text == "PCBC")
                return CipherType.RC6_PCBC;
            return CipherType.RC6;
        }

        private byte[] GetKey()
        {
            return Encoding.UTF8.GetBytes(KeyBox.Password);
        }

        private FileEncoder BuildEncoder()
        {
            bool useSHA = UseSHABox.IsChecked == true;
            string baseDir = string.IsNullOrWhiteSpace(OutputFolderBox.Text)
                ? WatchFolderBox.Text
                : OutputFolderBox.Text;

            return new FileEncoder(
                System.IO.Path.Combine(baseDir, "encoded"),
                System.IO.Path.Combine(baseDir, "decoded"),
                useSHA
            );
        }
    }
}