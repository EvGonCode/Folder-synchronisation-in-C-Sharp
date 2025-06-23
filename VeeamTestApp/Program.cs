using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace VeeamTestApp
{
    class SyncFolders
    {
        private readonly object consoleLock = new object();
        private CancellationTokenSource cancellationTokenSource;
        private const int MinimalSyncSeconds = 1;
        private string GetTimestamp() => DateTime.Now.ToString("HH:mm:ss dd:MM:yyyy");

        private string sourceFolder { get; set; }
        private string targetFolder { get; set; }
        private int syncIntervalSec { get; set; }
        private string logFilepath { get; set; }

        private bool isStopRequested { get; set; }

        public SyncFolders()
        {
            sourceFolder = "";
            targetFolder = "";
            syncIntervalSec = 0;
            logFilepath = "";
            isStopRequested = false;
        }

        protected bool CanReadDirectory(string folderPath)
        {
            return CheckAccess(folderPath, FileSystemRights.Read | FileSystemRights.ListDirectory);
        }

        protected static bool CanModifyDirectory(string folderPath)
        {
            return CheckAccess(folderPath, 
                FileSystemRights.Write | 
                FileSystemRights.Modify | 
                FileSystemRights.Delete);
        }

        protected static bool CheckAccess(string folderPath, FileSystemRights rightsToCheck)
        {
            if (!Directory.Exists(folderPath)) return false;

            var directoryInfo = new DirectoryInfo(folderPath);
            var accessControl = directoryInfo.GetAccessControl();
            var rules = accessControl.GetAccessRules(true, true, typeof(NTAccount));

            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);

            bool allow = false;

            foreach (FileSystemAccessRule rule in rules)
            {
                if (principal.IsInRole(rule.IdentityReference.Value))
                {
                    if (rule.AccessControlType == AccessControlType.Allow && rule.FileSystemRights.HasFlag(rightsToCheck))
                    {
                        allow = true;
                    }
                    if (rule.AccessControlType == AccessControlType.Deny && rule.FileSystemRights.HasFlag(rightsToCheck))
                    {
                        return false;
                    }
                }
            }

            return allow;
        }

        public void GetSourceFolder()
        {
            string folderPath = "";
            while (folderPath.Length < 1)
            {
                Console.Write("Enter source folder: ");
                folderPath = Console.ReadLine();
                if (!Directory.Exists(folderPath))
                {
                    Console.WriteLine("This folder does not exist.");
                    folderPath = "";
                    continue;
                }
                if (!CanReadDirectory(folderPath))
                {
                    Console.WriteLine("Cannot read from this directory.");
                    folderPath = "";
                    continue;
                }
                if (folderPath.Equals(targetFolder))
                {
                    Console.WriteLine("Source folder cannot be the same as a target folder.");
                    folderPath = "";
                    continue;
                }

                this.sourceFolder = folderPath;
                Console.WriteLine("Source folder set to \"" + folderPath + "\"");
                Console.WriteLine();
            }
        }
        
        public void GetTargetFolder()
        {
            string folderPath = "";
            while (folderPath.Length < 1)
            {
                Console.Write("Enter target folder: ");
                folderPath = Console.ReadLine();
                if (!Directory.Exists(folderPath))
                {
                    Console.WriteLine("This folder does not exist.");
                    folderPath = "";
                    continue;
                }
                if (!CanModifyDirectory(folderPath))
                {
                    Console.WriteLine("Cannot modify this directory.");
                    folderPath = "";
                    continue;
                }
                if (folderPath.Equals(sourceFolder))
                {
                    Console.WriteLine("Target folder cannot be the same as a source folder.");
                    folderPath = "";
                    continue;
                }

                this.targetFolder = folderPath;
                Console.WriteLine("Target folder set to \"" + folderPath + "\"");
                Console.WriteLine();
            }
        }
        
        public void GetSyncInterval()
        {
            int syncInterval = 0;
            string tmp = "";
            while (syncInterval < MinimalSyncSeconds)
            {
                Console.Write("Enter synchronisation interval in seconds: " );
                tmp = Console.ReadLine();
                try
                {
                    syncInterval = int.Parse(tmp);
                }
                catch (Exception)
                {
                    Console.WriteLine("Invalid input type.");
                    continue;
                }

                if (syncInterval < MinimalSyncSeconds)
                {
                    Console.WriteLine("Interval cannot be smaller than " + MinimalSyncSeconds + " seconds.");
                    continue;
                }
            }

            this.syncIntervalSec = syncInterval;
            Console.WriteLine("Synchronisation interval set to " + tmp + " seconds");
            Console.WriteLine();
        }
        
        public void GetLogFilePath()
        {
            string filePath = "";
            string folderPath = "";
            while (filePath.Length < 1)
            {
                Console.Write("Enter log filepath: ");
                filePath = Console.ReadLine();
                folderPath = Path.GetDirectoryName(filePath);
                
                if (!Directory.Exists(folderPath))
                {
                    Console.WriteLine("This folder does not exist.");
                    filePath = "";
                    continue;
                }
                if (!CanModifyDirectory(folderPath))
                {
                    Console.WriteLine("Cannot modify this directory.");
                    filePath = "";
                    continue;
                }
                if (folderPath.Equals(sourceFolder))
                {
                    Console.WriteLine("Log folder cannot be the same as a source folder.");
                    filePath = "";
                    continue;
                }

                filePath = Path.ChangeExtension(filePath, ".txt");

                if (!File.Exists(filePath))
                {
                    using (FileStream fs = File.Create(filePath)){}
                }

                this.logFilepath = filePath;
                Console.WriteLine("Log file path set to \"" + filePath + "\"");
                Console.WriteLine();
            }
        }

        public void Log(string log)
        {
            File.AppendAllText(logFilepath, log + Environment.NewLine);
            lock (consoleLock)
            {
                Console.WriteLine(log);
                Console.Out.Flush();
            }
        }
        private bool FilesAreDifferent(string filePath1, string filePath2, HashAlgorithm hasher)
        {
            var fileInfo1 = new FileInfo(filePath1);
            var fileInfo2 = new FileInfo(filePath2);

            if (fileInfo1.Length != fileInfo2.Length)
                return true;

            using (FileStream fs1 = File.Open(filePath1, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (FileStream fs2 = File.Open(filePath2, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                byte[] hash1 = hasher.ComputeHash(fs1);
                byte[] hash2 = hasher.ComputeHash(fs2);

                return !hash1.SequenceEqual(hash2);
            }
        }

        private bool IsEnoughSpaceToCopy(String filePath, String targetDir)
        {
            long sourceFileSize = new FileInfo(filePath).Length;
            string driveName = Path.GetPathRoot(targetFolder);
            DriveInfo drive = new DriveInfo(driveName);

            if (drive.AvailableFreeSpace < sourceFileSize)
            {
                return false;
            }

            return true;
        }
        
        private void SyncFilesHelper(string sourceFolder, string targetFolder)
        {
            using (var sha256 = SHA256.Create())
            {
                foreach (var sourceFile in Directory.GetFiles(sourceFolder)) // sync files
                {
                    string fileName = Path.GetFileName(sourceFile);
                    string targetFile = Path.Combine(targetFolder, fileName);

                    if (!File.Exists(targetFile) || FilesAreDifferent(sourceFile, targetFile, sha256))
                    {
                        if (!IsEnoughSpaceToCopy(sourceFile, targetFolder))
                        {
                            Log(DateTime.Now.ToString(GetTimestamp()) + 
                                $" ERROR: Not enough disk space to copy {fileName}. Skipping.");
                            continue;
                        }

                        try
                        {
                            Directory.CreateDirectory(Path.GetDirectoryName(targetFile));
                            File.Copy(sourceFile, targetFile, true);
                            Log(DateTime.Now.ToString(GetTimestamp()) + " Synchronised " + fileName);
                        }
                        catch (Exception ex)
                        {
                            Log(DateTime.Now.ToString(GetTimestamp()) + $" ERROR copying {fileName}: {ex.Message}");
                        }
                    }
                }
            }
            
            var sourceFileNames = Directory.GetFiles(sourceFolder).Select(Path.GetFileName).ToHashSet();
                
            foreach (var targetFile in Directory.GetFiles(targetFolder)) // sync deleted files
            {
                string fileName = Path.GetFileName(targetFile);
                if (!sourceFileNames.Contains(fileName))
                {
                    try
                    {
                        File.Delete(targetFile);
                        Log(DateTime.Now.ToString(GetTimestamp()) + " Deleted from target " + fileName);
                    }
                    catch (Exception ex)
                    {
                        Log(DateTime.Now.ToString(GetTimestamp()) + $" ERROR deleting {fileName}: {ex.Message}");
                    }
                }
            }
        }

        private void SynchronizeFolders(string sourceFolder, string targetFolder)
        {
            using (var sha256 = SHA256.Create())
            {
                SyncFilesHelper(sourceFolder, targetFolder);
                
                foreach (var sourceSubDir in Directory.GetDirectories(sourceFolder)) // sync folders
                {
                    string dirName = Path.GetFileName(sourceSubDir);
                    string targetSubDir = Path.Combine(targetFolder, dirName);
                    SynchronizeFolders(sourceSubDir, targetSubDir);
                }
                
                var sourceDirNames = Directory.GetDirectories(sourceFolder).Select(Path.GetFileName).ToHashSet();
                foreach (var targetSubDir in Directory.GetDirectories(targetFolder)) // sync deleted dirs
                {
                    string dirName = Path.GetFileName(targetSubDir);
                    if (!sourceDirNames.Contains(dirName))
                    {
                        try
                        {
                            Directory.Delete(targetSubDir, true);
                            Log(DateTime.Now.ToString(GetTimestamp()) + " Deleted folder from target " + dirName);
                        }
                        catch (Exception ex)
                        {
                            Log(DateTime.Now.ToString(GetTimestamp()) + $" ERROR deleting folder {dirName}: {ex.Message}");
                        }
                    }
                }
            }
        }

        private async Task SyncLoopAsync(string sourceFolder, string targetFolder, int intervalSeconds, CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    SynchronizeFolders(sourceFolder, targetFolder);
                    Log($"Folder {targetFolder} synchronised with folder {sourceFolder} at {DateTime.Now.ToString(GetTimestamp())}");
                }
                catch (Exception ex)
                {
                    Log($"Error: {ex.Message}");
                }

                try
                {
                    await Task.Delay(intervalSeconds * 1000, token);
                }
                catch (TaskCanceledException)
                {
                    break; // exit cleanly if cancelled during delay
                }
            }
        }
        
        public void StartSync()
        {
            while (true)
            {
                isStopRequested = false;
                GetSourceFolder();
                GetTargetFolder();
                GetSyncInterval();
                GetLogFilePath();

                Log("Starting synchronization of " + targetFolder + " with " + sourceFolder +
                    " every " + syncIntervalSec + " seconds...");
                Console.WriteLine("Log file: " + logFilepath);
                Console.WriteLine("Press \"ctrl + s\" to stop the program.");
                
                cancellationTokenSource = new CancellationTokenSource();
                var syncTask = SyncLoopAsync(sourceFolder, targetFolder, syncIntervalSec, cancellationTokenSource.Token);

                while (true)
                {
                    ConsoleKeyInfo keyInfo = Console.ReadKey(intercept: true);
                    if (keyInfo.Key == ConsoleKey.S && keyInfo.Modifiers.HasFlag(ConsoleModifiers.Control))
                    {
                        cancellationTokenSource.Cancel();
                        break;
                    }
                }

                syncTask.Wait(); // Wait for task to finish gracefully

                Log("Synchronisation stopped.");
            }
        }
    }

    class App
    {
        public static void Main()
        {
            SyncFolders syncFolders = new SyncFolders();

            syncFolders.StartSync();
        }
    }
    
}