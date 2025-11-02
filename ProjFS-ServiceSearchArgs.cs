/*******************************************************************************
 * File: ProjFS-Service.cs
 * Author: Casey Smith 
 * Date: 2025
 * Version: 1.0.1
 * 
 * Description:
 *   Windows service that creates a virtual file system using the Windows
 *   Projected File System (ProjFS) API. Monitors file access attempts and
 *   sends DNS alerts when virtual files are accessed.
 * 
 * MODIFICATIONS:
 *   - Added search pattern logging to capture wildcard searches (e.g., *passwords*.*)
 *   - Added AlertOnSearch method to send DNS alerts for suspicious searches
 *   - Enhanced console output for search pattern detection
 * 
 * Dependencies:
 *   - .NET Framework 4.8 or higher
 *   - Windows 10 version 1809 (build 17763) or later
 *   - Windows Server 2019 or later
 *   - ProjectedFSLib.dll (Windows system library)
 *   - Windows Projected File System feature must be enabled

 * 
 * 
 * Compilation:
 *   csc ProjFS-Service.cs
 * 
 * Installation:
 *   1. Enable Windows Projected File System feature:
 *      Enable-WindowsOptionalFeature -Online -FeatureName "Client-ProjFS"
 * 
 *   2. Install the service (run as Administrator):
 *       C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe ProjFS-Service.exe
 * 
 *   3. Start the service:
 *      net start WindowsFakeFileSystem
 * 
 *   
 * 
 * Uninstallation:
 *   1. Stop the service:
 *      net stop WindowsFakeFileSystem
 * 
 *   2. Uninstall the service (run as Administrator):
 *      C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /u ProjFS-Service.exe
 *      OR
 *      sc delete WindowsFakeFileSystem
 * 
 *   3. Optionally disable ProjFS feature:
 *      Disable-WindowsOptionalFeature -Online -FeatureName "Client-ProjFS"
 * 
 * Configuration (App.config):
 *   RootPath - Virtual file system location (default: C:\Secrets)
 *   AlertDomain - DNS domain for alerts
 *   DebugMode - Enable debug output (true/false)
 * 
 * Console Mode (for testing):
 *   Minimalist file structures.
 *   ProjFS-Service.exe /console
 * 
 * Notes:
 *   - Service runs as LocalSystem by default
 *   - Virtual files are created on-demand, folder may appear empty
 *   - DNS alerts use Base32 encoding for file/process information
 *   - Ensure firewall allows DNS queries for alerting functionality
 *   - Search patterns (like *passwords*.*) are now logged and alerted
 * 
 * License: MIT License
 *
 * 
 ******************************************************************************/




using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration;
using System.Configuration.Install;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace WindowsFakeFileSystemService
{
    // Main Service Class
    public partial class WindowsFakeFileSystemService : ServiceBase
    {
        private ProjFSProvider provider;
        private Thread serviceThread;
        private ManualResetEvent stopEvent;
        
        public WindowsFakeFileSystemService()
        {
            ServiceName = "WindowsFakeFileSystem";
            CanStop = true;
            CanPauseAndContinue = false;
            AutoLog = true;
        }

        protected override void OnStart(string[] args)
        {
            stopEvent = new ManualResetEvent(false);
            serviceThread = new Thread(ServiceWorkerThread);
            serviceThread.Start();
        }

        protected override void OnStop()
        {
            if (provider != null)
            {
                provider.StopVirtualizing();
            }
            
            stopEvent.Set();
            if (serviceThread != null)
            {
                serviceThread.Join(5000);
            }
        }

        private void ServiceWorkerThread()
        {
            try
            {
                string rootPath = ConfigurationManager.AppSettings["RootPath"] ?? @"C:\Secrets";
                string alertDomain = ConfigurationManager.AppSettings["AlertDomain"] ?? "TODO-INSERTTOKENHERE";
                bool debugMode = bool.Parse(ConfigurationManager.AppSettings["DebugMode"] ?? "false");
                
                if (!Directory.Exists(rootPath))
                {
                    Directory.CreateDirectory(rootPath);
                }
                
                Guid guid = Guid.NewGuid();
                
                string csvData = GetFileSystemCsvData();
                provider = new ProjFSProvider(rootPath, csvData, alertDomain, debugMode);
                
                int result = ProjFSNative.PrjMarkDirectoryAsPlaceholder(rootPath, null, IntPtr.Zero, ref guid);
                
                provider.StartVirtualizing();
                
                stopEvent.WaitOne();
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("WindowsFakeFileSystem", string.Concat("Error: ", ex.Message), EventLogEntryType.Error);
            }
        }
        
        private string GetFileSystemCsvData()
        {
            return @"\Network,true,0,1743942586
\Network\Network Diagram.pdf,false,2303,1727206186
\Network\Router Configuration.xml,false,25267,1741508986
\Network\Switch Configuration.doc,false,1417,1739636986
\Server,true,0,1752402586
\Server\Server Inventory.xlsx,false,38366,1735799386
\Server\Server Configurations.doc,false,29960,1728386986
\Server\Server Manual.pdf,false,12626,1730197786
\Server\Server Room Access Log.pdf,false,23237,1730136586
\Firewall,true,0,1751527786
\Firewall\Firewall Configuration.doc,false,5246,1728322186
\Firewall\Firewall Rules.pdf,false,13401,1738927786
\Firewall\Firewall Logs.xlsx,false,43633,1736926186
\VPN,true,0,1744586986
\VPN\VPN Configuration.doc,false,9854,1736177386
\VPN\VPN Access Logs.pdf,false,38036,1731446986
\VPN\VPN User List.xlsx,false,5241,1740680986
\Wireless Network,true,0,1760545786
\Wireless Network\Wireless Network Configuration.doc,false,42243,1734780586
\Wireless Network\Wireless Network Access Log.pdf,false,47147,1748708986
\Wireless Network\Wireless Network Security.pdf,false,17590,1742354986
\CCTV,true,0,1733984986
\CCTV\CCTV Configuration.doc,false,19896,1755520186
\CCTV\CCTV Footage Backup.xlsx,false,29644,1742938186
\CCTV\CCTV Incident Report.pdf,false,2752,1739932186
\Access Control,true,0,1733178586
\Access Control\Access Control Configuration.doc,false,28184,1737556186
\Access Control\Access Control Audit Log.xlsx,false,33592,1732876186
\Access Control\Access Control Policy.pdf,false,25825,1731788986
\Incident Response,true,0,1760621386
\Incident Response\Incident Response Plan.doc,false,42254,1749252586
\Incident Response\Incident Report Form.doc,false,9936,1745674186
\Incident Response\Incident Investigation Report.pdf,false,45521,1736659786
\Incident Response\Incident Response Team Contact List.xlsx,false,22373,1755574186
\Antivirus,true,0,1759598986
\Antivirus\Antivirus Configuration.doc,false,36794,1752125386
\Antivirus\Antivirus Reports.pdf,false,7548,1759976986
\Antivirus\Antivirus User Manual.doc,false,34872,1758972586
\Security Policies,true,0,1754688586
\Security Policies\IT Security Policy.pdf,false,25935,1749911386
\Security Policies\Password Policy.doc,false,32981,1753788586
\Security Policies\Information Security Awareness Training.pptx,false,17951,1748244586
\Disaster Recovery,true,0,1741278586
\Disaster Recovery\Disaster Recovery Plan.doc,false,42009,1748096986
\Disaster Recovery\Disaster Recovery Test Results.xlsx,false,15201,1756268986
\Disaster Recovery\Backup Details.doc,false,29755,1756780186
\Disaster Recovery\Recovery Procedures.pdf,false,22633,1760315386
\IT Infrastructure,true,0,1727432986
\IT Infrastructure\IT Infrastructure Diagram.pdf,false,31415,1732238986
\IT Infrastructure\IT Asset Register.xlsx,false,21364,1728437386
\IT Infrastructure\IT Maintenance Schedule.xlsx,false,3274,1746678586
\User Management,true,0,1757222986
\User Management\User Access Management.doc,false,9109,1740907786
\User Management\User Account Request Form.doc,false,2649,1747607386
\User Management\User Account Suspension Notification.pdf,false,36469,1727904586
\User Management\User Account Termination Notification.pdf,false,9072,1737350986
\Vulnerability Management,true,0,1743391786
\Vulnerability Management\Vulnerability Assessment Report.doc,false,45541,1759490986
\Vulnerability Management\Vulnerability Scan Results.xlsx,false,6835,1756780186
\Vulnerability Management\Vulnerability Remediation Procedure.pdf,false,9861,1756654186
\Training and Education,true,0,1743373786
\Training and Education\IT Security Training Schedule.xlsx,false,31002,1742869786
\Training and Education\IT Security Training Material.pdf,false,9933,1739276986
\Training and Education\IT Security Quiz.doc,false,22850,1747384186";
        }
    }

    // Program Entry Point
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length > 0 && args[0] == "/console")
            {
                RunInConsoleMode();
            }
            else
            {
                ServiceBase[] ServicesToRun;
                ServicesToRun = new ServiceBase[]
                {
                    new WindowsFakeFileSystemService()
                };
                ServiceBase.Run(ServicesToRun);
            }
        }
        
        static void RunInConsoleMode()
        {
            string rootPath = ConfigurationManager.AppSettings["RootPath"] ?? @"C:\Secrets";
            string alertDomain = ConfigurationManager.AppSettings["AlertDomain"] ?? "INSERT TOKEN HERE";
            bool debugMode = bool.Parse(ConfigurationManager.AppSettings["DebugMode"] ?? "false");
            
            Console.WriteLine(string.Concat("Virtual Folder: ", rootPath));
            Console.WriteLine(string.Concat("Debug Mode: ", debugMode.ToString()));
            
            try
            {
                if (!Directory.Exists(rootPath))
                {
                    Directory.CreateDirectory(rootPath);
                    Console.WriteLine(string.Concat("Created directory: ", rootPath));
                }
                
                DriveInfo drive = new DriveInfo(Path.GetPathRoot(rootPath));
                Console.WriteLine(string.Concat("Available free space: ", drive.AvailableFreeSpace.ToString(), " bytes"));
                // Minimalst File / Folder for Debugging.
                string csvData = @"\Network,true,0,1743942586
\Network\Network Diagram.pdf,false,2303,1727206186
\Network\Router Configuration.xml,false,25267,1741508986";
                
                var provider = new ProjFSProvider(rootPath, csvData, alertDomain, debugMode);
                Guid guid = Guid.NewGuid();
                int result = ProjFSNative.PrjMarkDirectoryAsPlaceholder(rootPath, null, IntPtr.Zero, ref guid);
                
                provider.StartVirtualizing();
                
                Console.WriteLine("Projected File System Provider started. Press any key to exit.");
                Console.ReadKey();
                
                provider.StopVirtualizing();
            }
            catch (Exception ex)
            {
                Console.WriteLine(string.Concat("Error: ", ex.Message));
                if (ex is Win32Exception)
                {
                    Console.WriteLine(string.Concat("Win32 Error Code: ", ((Win32Exception)ex).NativeErrorCode.ToString()));
                }
            }
        }
    }

    // Projected File System Provider
    class ProjFSProvider
    {
        private readonly string rootPath;
        private readonly Dictionary<string, List<FileEntry>> fileSystem = new Dictionary<string, List<FileEntry>>();
        private IntPtr instanceHandle;
        private readonly bool enableDebug;
        private readonly string alertDomain;
        private Dictionary<Guid, int> enumerationIndices = new Dictionary<Guid, int>();

        public ProjFSProvider(string rootPath, string csvStr, string alertDomain, bool enableDebug)
        {
            this.rootPath = rootPath;
            this.enableDebug = enableDebug;
            this.alertDomain = alertDomain;
            LoadFileSystemFromCsvString(csvStr);
        }

        private static string BytesToBase32(byte[] bytes)
        {
            const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            string output = "";
            for (int bitIndex = 0; bitIndex < bytes.Length * 8; bitIndex += 5)
            {
                int dualbyte = bytes[bitIndex / 8] << 8;
                if (bitIndex / 8 + 1 < bytes.Length)
                    dualbyte |= bytes[bitIndex / 8 + 1];
                dualbyte = 0x1f & (dualbyte >> (16 - bitIndex % 8 - 5));
                output += alphabet[dualbyte];
            }
            return output;
        }

        private void AlertOnFileAccess(string filePath, string imgFileName)
        {
            Console.WriteLine(string.Format("Alerting on: {0} from process {1}", filePath, imgFileName));
            string[] pathParts = filePath.Split('\\');
            string filename = pathParts[pathParts.Length - 1];
            string[] imgParts = imgFileName.Split('\\');
            string imgname = imgParts[imgParts.Length - 1];
            string fnb32 = BytesToBase32(Encoding.UTF8.GetBytes(filename));
            string inb32 = BytesToBase32(Encoding.UTF8.GetBytes(imgname));
            Random rnd = new Random();
            string uniqueval = string.Concat("u", rnd.Next(1000, 10000).ToString(), ".");

            try
            {
                Task.Run(() => Dns.GetHostEntry(string.Concat(uniqueval, "f", fnb32, ".i", inb32, ".", alertDomain)));
            }
            catch (Exception ex)
            {
                Console.WriteLine(string.Concat("Error: ", ex.Message));
            }
        }

        private void AlertOnSearch(string directoryPath, string searchPattern, string processName)
        {
            string fullPath = string.Concat(directoryPath == "\\" ? "" : directoryPath, "\\", searchPattern);
            Console.WriteLine("================================================================================");
            Console.WriteLine("*** SEARCH DETECTED ***");
            Console.WriteLine(string.Format("  Pattern:   {0}", searchPattern));
            Console.WriteLine(string.Format("  Directory: {0}", directoryPath));
            Console.WriteLine(string.Format("  Full Path: {0}", fullPath));
            Console.WriteLine(string.Format("  Process:   {0}", processName));
            Console.WriteLine("================================================================================");
            
            string[] imgParts = processName.Split('\\');
            string imgname = imgParts[imgParts.Length - 1];
            string searchb32 = BytesToBase32(Encoding.UTF8.GetBytes(searchPattern));
            string dirb32 = BytesToBase32(Encoding.UTF8.GetBytes(directoryPath));
            string inb32 = BytesToBase32(Encoding.UTF8.GetBytes(imgname));
            Random rnd = new Random();
            string uniqueval = string.Concat("s", rnd.Next(1000, 10000).ToString(), ".");

            try
            {
                Task.Run(() => Dns.GetHostEntry(string.Concat(uniqueval, "q", searchb32, ".d", dirb32, ".i", inb32, ".", alertDomain)));
            }
            catch (Exception ex)
            {
                Console.WriteLine(string.Concat("Error sending search alert: ", ex.Message));
            }
        }

        private void LoadFileSystemFromCsvString(string csvStr)
        {
            string[] lines = csvStr.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
            foreach (var line in lines)
            {
                var parts = line.Split(',');
                if (parts.Length != 4) continue;

                string path = parts[0].TrimStart('\\');
                string name = Path.GetFileName(path);
                string parentPath = Path.GetDirectoryName(path);
                bool isDirectory = bool.Parse(parts[1]);
                long fileSize = long.Parse(parts[2]);

                long unixTimestamp = long.Parse(parts[3]);
                DateTime lastWriteTime = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(unixTimestamp);

                if (string.IsNullOrEmpty(parentPath))
                {
                    parentPath = "\\";
                }

                if (!fileSystem.ContainsKey(parentPath))
                {
                    fileSystem[parentPath] = new List<FileEntry>();
                }

                fileSystem[parentPath].Add(new FileEntry
                {
                    Name = name,
                    IsDirectory = isDirectory,
                    FileSize = fileSize,
                    LastWriteTime = lastWriteTime,
                    Opened = false,
                    LastAlert = 0
                });
            }
        }

        public void StartVirtualizing()
        {
            ProjFSNative.PrjCallbacks callbacks = new ProjFSNative.PrjCallbacks
            {
                StartDirectoryEnumerationCallback = StartDirectoryEnumeration,
                EndDirectoryEnumerationCallback = EndDirectoryEnumeration,
                GetDirectoryEnumerationCallback = GetDirectoryEnumeration,
                GetPlaceholderInfoCallback = GetPlaceholderInfo,
                NotificationCallback = NotificationCB,
                GetFileDataCallback = GetFileData
            };

            ProjFSNative.PrjStartVirutalizingOptions options = new ProjFSNative.PrjStartVirutalizingOptions
            {
                flags = ProjFSNative.PrjStartVirutalizingFlags.PrjFlagNone,
                PoolThreadCount = 1,
                ConcurrentThreadCount = 1,
                NotificationMappings = new ProjFSNative.PrjNotificationMapping(),
                NotificationMappingCount = 0
            };

            Console.WriteLine("Attempting to start virtualization...");
            int hr = ProjFSNative.PrjStartVirtualizing(rootPath, ref callbacks, IntPtr.Zero, IntPtr.Zero, ref instanceHandle);
            if (hr != 0)
            {
                Console.WriteLine(string.Concat("PrjStartVirtualizing failed. HRESULT: ", hr.ToString()));
                throw new Win32Exception(hr);
            }
            Console.WriteLine("Virtualization started successfully.");
        }

        public void StopVirtualizing()
        {
            if (instanceHandle != IntPtr.Zero)
            {
                Console.WriteLine("Stopping virtualization...");

                ProjFSNative.PrjStopVirtualizing(instanceHandle);
                instanceHandle = IntPtr.Zero;

                DirectoryInfo di = new DirectoryInfo(rootPath);
                foreach (FileInfo file in di.GetFiles())
                {
                    file.Delete();
                }
                foreach (DirectoryInfo dir in di.GetDirectories())
                {
                    dir.Delete(true);
                }

                Console.WriteLine("Virtualization stopped.");
            }
        }

        private long GetUnixTimeStamp()
        {
            long ticks = DateTime.UtcNow.Ticks - DateTime.Parse("01/01/1970 00:00:00").Ticks;
            ticks /= 10000000;
            return ticks;
        }

        private int NotificationCB(ProjFSNative.PrjCallbackData callbackData, bool isDirectory, ProjFSNative.PrjNotification notification, string destinationFileName, ref ProjFSNative.PrjNotificationParameters operationParameters)
        {
            if (notification != ProjFSNative.PrjNotification.FileOpened || isDirectory)
                return ProjFSNative.S_OK;

            string parentPath = Path.GetDirectoryName(callbackData.FilePathName);
            if (string.IsNullOrEmpty(parentPath))
            {
                parentPath = "\\";
            }
            string fileName = Path.GetFileName(callbackData.FilePathName);

            List<FileEntry> entries;
            if (!fileSystem.TryGetValue(parentPath, out entries))
            {
                return ProjFSNative.ERROR_FILE_NOT_FOUND;
            }

            var entry = entries.Find(e => string.Equals(e.Name, fileName, StringComparison.OrdinalIgnoreCase));
            if (entry == null || entry.IsDirectory)
            {
                return ProjFSNative.ERROR_FILE_NOT_FOUND;
            }

            if (entry.Opened && (GetUnixTimeStamp() - entry.LastAlert) > 5)
            {
                entry.LastAlert = GetUnixTimeStamp();
                AlertOnFileAccess(callbackData.FilePathName.ToLower(), callbackData.TriggeringProcessImageFileName);
            }

            return ProjFSNative.S_OK;
        }

        private int StartDirectoryEnumeration(ProjFSNative.PrjCallbackData callbackData, ref Guid enumerationId)
        {
            return ProjFSNative.S_OK;
        }

        private int EndDirectoryEnumeration(ProjFSNative.PrjCallbackData callbackData, ref Guid enumerationId)
        {
            if (enumerationIndices.ContainsKey(enumerationId))
            {
                enumerationIndices.Remove(enumerationId);
            }
            return ProjFSNative.S_OK;
        }

        private int GetDirectoryEnumeration(ProjFSNative.PrjCallbackData callbackData, ref Guid enumerationId, string searchExpression, IntPtr dirEntryBufferHandle)
        {
            string directoryPath = callbackData.FilePathName ?? "";
            bool single = false;

            if (string.IsNullOrEmpty(directoryPath))
            {
                directoryPath = "\\";
            }

            // Log search patterns, especially those with wildcards
            if (!string.IsNullOrEmpty(searchExpression) && searchExpression != "*")
            {
                string processName = callbackData.TriggeringProcessImageFileName ?? "unknown";
                string logMessage = string.Format("Search Pattern: '{0}' in directory '{1}' by process: {2}", 
                    searchExpression, directoryPath, processName);
                Console.WriteLine(logMessage);
                
                if (enableDebug)
                {
                    EventLog.WriteEntry("WindowsFakeFileSystem", logMessage, EventLogEntryType.Information);
                }
                
                // Alert on interesting search patterns
                if (ProjFSNative.PrjDoesNameContainWildCards(searchExpression))
                {
                    AlertOnSearch(directoryPath, searchExpression, processName);
                }
            }

            List<FileEntry> entries;
            if (!fileSystem.TryGetValue(directoryPath, out entries))
            {
                return ProjFSNative.ERROR_FILE_NOT_FOUND;
            }

            int currentIndex;
            if (!enumerationIndices.TryGetValue(enumerationId, out currentIndex))
            {
                currentIndex = 0;
                enumerationIndices[enumerationId] = currentIndex;
            }

            if (callbackData.Flags == ProjFSNative.PrjCallbackDataFlags.RestartScan)
            {
                currentIndex = 0;
                enumerationIndices[enumerationId] = 0;
            }
            else if (callbackData.Flags == ProjFSNative.PrjCallbackDataFlags.ReturnSingleEntry)
            {
                single = true;
            }

            entries.Sort(delegate(FileEntry a, FileEntry b) { return ProjFSNative.PrjFileNameCompare(a.Name, b.Name); });

            for (; currentIndex < entries.Count; currentIndex++)
            {
                if (currentIndex >= entries.Count)
                {
                    return ProjFSNative.S_OK;
                }

                var entry = entries[currentIndex];

                if (!ProjFSNative.PrjFileNameMatch(entry.Name, searchExpression))
                {
                    enumerationIndices[enumerationId] = currentIndex + 1;
                    continue;
                }

                ProjFSNative.PrjFileBasicInfo fileInfo = new ProjFSNative.PrjFileBasicInfo
                {
                    IsDirectory = entry.IsDirectory,
                    FileSize = entry.FileSize,
                    CreationTime = entry.LastWriteTime.ToFileTime(),
                    LastAccessTime = entry.LastWriteTime.ToFileTime(),
                    LastWriteTime = entry.LastWriteTime.ToFileTime(),
                    ChangeTime = entry.LastWriteTime.ToFileTime(),
                    FileAttributes = entry.IsDirectory ? FileAttributes.Directory : FileAttributes.Normal
                };

                int result = ProjFSNative.PrjFillDirEntryBuffer(entry.Name, ref fileInfo, dirEntryBufferHandle);
                if (result != ProjFSNative.S_OK)
                {
                    return ProjFSNative.S_OK;
                }

                enumerationIndices[enumerationId] = currentIndex + 1;
                if (single)
                    return ProjFSNative.S_OK;
            }

            return ProjFSNative.S_OK;
        }

        private int GetPlaceholderInfo(ProjFSNative.PrjCallbackData callbackData)
        {
            string filePath = callbackData.FilePathName ?? "";

            if (string.IsNullOrEmpty(filePath))
            {
                return ProjFSNative.ERROR_FILE_NOT_FOUND;
            }

            string parentPath = Path.GetDirectoryName(filePath);
            string fileName = Path.GetFileName(filePath);

            if (string.IsNullOrEmpty(parentPath))
            {
                parentPath = "\\";
            }

            List<FileEntry> entries;
            if (!fileSystem.TryGetValue(parentPath, out entries))
            {
                return ProjFSNative.ERROR_FILE_NOT_FOUND;
            }

            FileEntry entry = null;
            foreach (var e in entries)
            {
                if (string.Equals(e.Name, fileName, StringComparison.OrdinalIgnoreCase))
                {
                    entry = e;
                    break;
                }
            }

            if (entry == null)
            {
                return ProjFSNative.ERROR_FILE_NOT_FOUND;
            }

            entries.Sort(delegate(FileEntry a, FileEntry b) { return ProjFSNative.PrjFileNameCompare(a.Name, b.Name); });

            ProjFSNative.PrjPlaceholderInfo placeholderInfo = new ProjFSNative.PrjPlaceholderInfo
            {
                FileBasicInfo = new ProjFSNative.PrjFileBasicInfo
                {
                    IsDirectory = entry.IsDirectory,
                    FileSize = entry.FileSize,
                    CreationTime = entry.LastWriteTime.ToFileTime(),
                    LastAccessTime = entry.LastWriteTime.ToFileTime(),
                    LastWriteTime = entry.LastWriteTime.ToFileTime(),
                    ChangeTime = entry.LastWriteTime.ToFileTime(),
                    FileAttributes = entry.IsDirectory ? FileAttributes.Directory : FileAttributes.Normal
                }
            };

            int result = ProjFSNative.PrjWritePlaceholderInfo(
                callbackData.NamespaceVirtualizationContext,
                filePath,
                ref placeholderInfo,
                (uint)Marshal.SizeOf(placeholderInfo));

            return result;
        }

        private int GetFileData(ProjFSNative.PrjCallbackData callbackData, ulong byteOffset, uint length)
        {
            string parentPath = Path.GetDirectoryName(callbackData.FilePathName);
            if (string.IsNullOrEmpty(parentPath))
            {
                parentPath = "\\";
            }
            string fileName = Path.GetFileName(callbackData.FilePathName);

            AlertOnFileAccess(callbackData.FilePathName, callbackData.TriggeringProcessImageFileName);

            List<FileEntry> entries;
            if (!fileSystem.TryGetValue(parentPath, out entries))
            {
                return ProjFSNative.ERROR_FILE_NOT_FOUND;
            }

            var entry = entries.Find(e => string.Equals(e.Name, fileName, StringComparison.OrdinalIgnoreCase));
            if (entry == null || entry.IsDirectory)
            {
                return ProjFSNative.ERROR_FILE_NOT_FOUND;
            }

            entry.Opened = true;
            entry.LastAlert = GetUnixTimeStamp();

            byte[] bom = { 0xEF, 0xBB, 0xBF };
            byte[] textBytes = Encoding.UTF8.GetBytes(string.Format("This is the content of {0}", fileName));
            byte[] fileContent = new byte[bom.Length + textBytes.Length];
            Buffer.BlockCopy(bom, 0, fileContent, 0, bom.Length);
            Buffer.BlockCopy(textBytes, 0, fileContent, bom.Length, textBytes.Length);

            if (byteOffset >= (ulong)fileContent.Length)
            {
                return ProjFSNative.S_OK;
            }

            uint bytesToWrite = Math.Min(length, (uint)(fileContent.Length - (int)byteOffset));
            IntPtr buffer = ProjFSNative.PrjAllocateAlignedBuffer(instanceHandle, bytesToWrite);
            try
            {
                Marshal.Copy(fileContent, (int)byteOffset, buffer, (int)bytesToWrite);
                return ProjFSNative.PrjWriteFileData(instanceHandle, ref callbackData.DataStreamId, buffer, byteOffset, bytesToWrite);
            }
            finally
            {
                ProjFSNative.PrjFreeAlignedBuffer(buffer);
            }
        }
    }

    // File Entry Model
    class FileEntry
    {
        public string Name { get; set; }
        public bool IsDirectory { get; set; }
        public long FileSize { get; set; }
        public DateTime LastWriteTime { get; set; }
        public bool Opened { get; set; }
        public long LastAlert { get; set; }
    }

    // Native P/Invoke Declarations
    static class ProjFSNative
    {
        public const int S_OK = 0;
        public const int ERROR_INSUFFICIENT_BUFFER = 122;
        public const int ERROR_FILE_NOT_FOUND = 2;

        [DllImport("ProjectedFSLib.dll")]
        public static extern IntPtr PrjAllocateAlignedBuffer(IntPtr namespaceVirtualizationContext, uint size);

        [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode)]
        public static extern bool PrjDoesNameContainWildCards(string fileName);

        [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode)]
        public static extern int PrjFileNameCompare(string fileName1, string fileName2);

        [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode)]
        public static extern bool PrjFileNameMatch(string fileNameToCheck, string pattern);

        [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode)]
        public static extern int PrjFillDirEntryBuffer(string fileName, ref PrjFileBasicInfo fileBasicInfo,
            IntPtr dirEntryBufferHandle);

        [DllImport("ProjectedFSLib.dll")]
        public static extern void PrjFreeAlignedBuffer(IntPtr buffer);

        [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode)]
        public static extern int PrjMarkDirectoryAsPlaceholder(string rootPathName, string targetPathName,
            IntPtr versionInfo, ref Guid virtualizationInstanceID);

        [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode)]
        public static extern int PrjStartVirtualizing(string virtualizationRootPath, ref PrjCallbacks callbacks,
            IntPtr instanceContext, IntPtr options, ref IntPtr namespaceVirtualizationContext);

        [DllImport("ProjectedFSLib.dll")]
        public static extern void PrjStopVirtualizing(IntPtr namespaceVirtualizationContext);

        [DllImport("ProjectedFSLib.dll")]
        public static extern int PrjDeleteFile(IntPtr namespaceVirtualizationContext, string destinationFileName, int updateFlags, ref int failureReason);

        [DllImport("ProjectedFSLib.dll")]
        public static extern int PrjWriteFileData(IntPtr namespaceVirtualizationContext, ref Guid dataStreamId,
            IntPtr buffer, ulong byteOffset, uint length);

        [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode)]
        public static extern int PrjWritePlaceholderInfo(IntPtr namespaceVirtualizationContext,
            string destinationFileName, ref PrjPlaceholderInfo placeholderInfo, uint placeholderInfoSize);

        [StructLayout(LayoutKind.Sequential)]
        public struct PrjCallbacks
        {
            public PrjStartDirectoryEnumerationCb StartDirectoryEnumerationCallback;
            public PrjEndDirectoryEnumerationCb EndDirectoryEnumerationCallback;
            public PrjGetDirectoryEnumerationCb GetDirectoryEnumerationCallback;
            public PrjGetPlaceholderInfoCb GetPlaceholderInfoCallback;
            public PrjGetFileDataCb GetFileDataCallback;
            public PrjQueryFileNameCb QueryFileNameCallback;
            public PrjNotificationCb NotificationCallback;
            public PrjCancelCommandCb CancelCommandCallback;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct PrjCallbackData
        {
            public uint Size;
            public PrjCallbackDataFlags Flags;
            public IntPtr NamespaceVirtualizationContext;
            public int CommandId;
            public Guid FileId;
            public Guid DataStreamId;
            public string FilePathName;
            public IntPtr VersionInfo;
            public uint TriggeringProcessId;
            public string TriggeringProcessImageFileName;
            public IntPtr InstanceContext;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PrjFileBasicInfo
        {
            public bool IsDirectory;
            public long FileSize;
            public long CreationTime;
            public long LastAccessTime;
            public long LastWriteTime;
            public long ChangeTime;
            public FileAttributes FileAttributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PrjNotificationParameters
        {
            public PrjNotifyTypes PostCreateNotificationMask;
            public PrjNotifyTypes FileRenamedNotificationMask;
            public bool FileDeletedOnHandleCloseIsFileModified;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PrjPlaceholderInfo
        {
            public PrjFileBasicInfo FileBasicInfo;
            public uint EaBufferSize;
            public uint OffsetToFirstEa;
            public uint SecurityBufferSize;
            public uint OffsetToSecurityDescriptor;
            public uint StreamsInfoBufferSize;
            public uint OffsetToFirstStreamInfo;
            public PrjPlaceholderVersionInfo VersionInfo;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)] 
            public byte[] VariableData;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PrjStartVirutalizingOptions
        {
            public PrjStartVirutalizingFlags flags;
            public uint PoolThreadCount;
            public uint ConcurrentThreadCount;
            public PrjNotificationMapping NotificationMappings;
            public uint NotificationMappingCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PrjNotificationMapping
        {
            public PrjNotifyTypes NotificationBitMask;
            public string NotifcationRoot;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PrjPlaceholderVersionInfo
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = (int)PrjPlaceholderID.Length)] 
            public byte[] ProviderID;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = (int)PrjPlaceholderID.Length)] 
            public byte[] ContentID;
        }

        [Flags]
        public enum PrjCallbackDataFlags : uint
        {
            RestartScan = 1,
            ReturnSingleEntry = 2
        }

        public enum PrjNotification : uint
        {
            FileOpened = 0x2,
            NewFileCreated = 0x4,
            FileOverwritten = 0x8,
            PreDelete = 0x10,
            PreRename = 0x20,
            PreSetHardlink = 0x40,
            FileRename = 0x80,
            HardlinkCreated = 0x100,
            FileHandleClosedNoModification = 0x200,
            FileHandleClosedFileModified = 0x400,
            FileHandleClosedFileDeleted = 0x800,
            FilePreConvertToFull = 0x1000
        }

        public enum PrjNotifyTypes : uint
        {
            None,
            SuppressNotifications,
            FileOpened,
            NewFileCreated,
            FileOverwritten,
            PreDelete,
            PreRename,
            PreSetHardlink,
            FileRenamed,
            HardlinkCreated,
            FileHandleClosedNoModification,
            FileHandleClosedFileModified,
            FileHandleClosedFileDeleted,
            FilePreConvertToFull,
            UseExistingMask
        }

        public enum PrjPlaceholderID : uint
        {
            Length = 128
        }

        public enum PrjStartVirutalizingFlags : uint
        {
            PrjFlagNone,
            PrjFlagUseNegativePathCache
        }

        public delegate int PrjCancelCommandCb(IntPtr callbackData);

        public delegate int PrjEndDirectoryEnumerationCb(PrjCallbackData callbackData, ref Guid enumerationId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public delegate int PrjGetDirectoryEnumerationCb(PrjCallbackData callbackData, ref Guid enumerationId,
            string searchExpression, IntPtr dirEntryBufferHandle);

        public delegate int PrjGetFileDataCb(PrjCallbackData callbackData, ulong byteOffset, uint length);

        public delegate int PrjGetPlaceholderInfoCb(PrjCallbackData callbackData);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public delegate int PrjNotificationCb(PrjCallbackData callbackData, bool isDirectory, PrjNotification notification,
            string destinationFileName, ref PrjNotificationParameters operationParameters);

        public delegate int PrjStartDirectoryEnumerationCb(PrjCallbackData callbackData, ref Guid enumerationId);

        public delegate int PrjQueryFileNameCb(IntPtr callbackData);
    }

    // Service Installer
    [RunInstaller(true)]
    public class ProjectInstaller : System.Configuration.Install.Installer
    {
        private ServiceProcessInstaller serviceProcessInstaller;
        private ServiceInstaller serviceInstaller;

        public ProjectInstaller()
        {
            serviceProcessInstaller = new ServiceProcessInstaller();
            serviceInstaller = new ServiceInstaller();

            // Set the account under which the service will run
            serviceProcessInstaller.Account = ServiceAccount.LocalSystem;
            serviceProcessInstaller.Username = null;
            serviceProcessInstaller.Password = null;

            // Configure the service
            serviceInstaller.ServiceName = "WindowsFakeFileSystem";
            serviceInstaller.DisplayName = "Windows Fake File System Service";
            serviceInstaller.Description = "Monitors file system access using Windows Projected File System";
            serviceInstaller.StartType = ServiceStartMode.Automatic;

            // Add installers to collection
            Installers.Add(serviceProcessInstaller);
            Installers.Add(serviceInstaller);
        }
    }
}
