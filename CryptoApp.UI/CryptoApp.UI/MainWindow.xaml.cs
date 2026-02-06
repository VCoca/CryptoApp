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

namespace CryptoApp.UI
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private DirectoryWatcher watcher;
        private bool watcherRunning = false;

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
            watcher = new DirectoryWatcher(path =>
            {
                var encoder = BuildEncoder(); // uvek uzima trenutni algoritam
                Task.Run(() => encoder.EncodeFile(path));
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
            encoder.EncodeFile(dlg.FileName);
            AppLogger.Success("File manually encoded");
        }

        // ===================== Algorithm Logic =====================

        private void AlgorithmBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            UpdateUIState();
        }

        // ===================== Encoder Factory =====================

        private FileEncoder BuildEncoder()
        {
            string algo = null;
            string mode = null;
            string keyText = null;
            bool useSHA = false;
            string outputBase = null;

            Dispatcher.Invoke(() =>
            {
                algo = AlgorithmBox.Text;
                mode = ModeBox.Text;
                keyText = KeyBox.Password;
                useSHA = UseSHABox.IsChecked == true;
                outputBase = string.IsNullOrWhiteSpace(OutputFolderBox.Text)
                    ? WatchFolderBox.Text
                    : OutputFolderBox.Text;
            });

            var key = Encoding.UTF8.GetBytes(keyText);

            IEncryptor cipher;
            CipherType cipherType;

            if (algo == "Playfair")
            {
                cipher = new PlayfairCipher();
                cipherType = CipherType.Playfair;
            }
            else if (mode == "PCBC")
            {
                cipher = new PCBCMode();
                cipherType = CipherType.RC6_PCBC;
            }
            else
            {
                cipher = new RC6Cipher();
                cipherType = CipherType.RC6;
            }

            return new FileEncoder(cipher,
                System.IO.Path.Combine(outputBase, "encoded"),
                System.IO.Path.Combine(outputBase, "decoded"),
                key,
                cipherType,
                useSHA);
        }
    }
}