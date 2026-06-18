/*******************************************************************************
 * File: ProjFS-Service.patched.cs
 * Author: Casey Smith
 * Date: 2026-06-18
 * Version: 1.0.2-hardening
 *
 * Description:
 *   Hardened Windows service that creates a virtual file system using the
 *   Windows Projected File System (ProjFS) API. It monitors virtual file access
 *   and suspicious wildcard searches, logs alerts to the Windows Application
 *   Event Log, and can optionally emit bounded DNS canary alerts.
 *
 * Security/optimization changes from prior versions:
 *   - Validates RootPath before creating or deleting anything.
 *   - Uses a sentinel file before root cleanup to avoid accidental data loss.
 *   - Checks HRESULTs from ProjFS setup calls.
 *   - Uses safe config parsing and sane defaults.
 *   - Supports <fileList> config section with fallback CSV.
 *   - Uses ConcurrentDictionary for callback state.
 *   - Sorts directory entries once after load rather than in every callback.
 *   - Makes alerting null-safe and rate-limited.
 *   - Bounds DNS labels/query length and disables DNS alerts unless explicitly configured.
 *   - Uses cryptographic random bytes for alert IDs.
 *   - Keeps callback delegates rooted for the lifetime of virtualization.
 *   - Reduces service privileges by defaulting installer account to NetworkService.
 *
 * Dependencies:
 *   - .NET Framework 4.8 or higher
 *   - Windows 10 version 1809 (build 17763) or later
 *   - Windows Server 2019 or later
 *   - ProjectedFSLib.dll
 *   - Windows Projected File System feature enabled
 *
 * Compilation:
 *   csc /target:exe /platform:anycpu /optimize+ ProjFS-Service.patched.cs
 *
 * Console Mode:
 *   ProjFS-Service.patched.exe /console
 *
 * App.config keys:
 *   RootPath          Required/optional. Defaults to C:\SecretsAppConfig.
 *   DebugMode         Optional bool. Defaults to false.
 *   EnableDnsAlerts   Optional bool. Defaults to false.
 *   AlertDomain       Required only when EnableDnsAlerts=true.
 *   AlertMinSeconds   Optional int. Defaults to 5.
 *   <fileList>        Optional CDATA section: \Path\Entry,isDirectory,fileSize,unixTimestamp
 *
 * License: MIT License
 ******************************************************************************/

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration;
using System.Configuration.Install;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Xml;

namespace WindowsFakeFileSystemService
{
    public partial class WindowsFakeFileSystemService : ServiceBase
    {
        internal const string ServiceNameConst = "WindowsFakeFileSystem";
        internal const string EventSourceName = "WindowsFakeFileSystem";
        internal const string DefaultRootPath = @"C:\SecretsAppConfig";

        private ProjFSProvider provider;
        private Thread serviceThread;
        private ManualResetEvent stopEvent;

        public WindowsFakeFileSystemService()
        {
            ServiceName = ServiceNameConst;
            CanStop = true;
            CanPauseAndContinue = false;
            AutoLog = true;
        }

        protected override void OnStart(string[] args)
        {
            stopEvent = new ManualResetEvent(false);
            serviceThread = new Thread(ServiceWorkerThread);
            serviceThread.Name = "ProjFS service worker";
            serviceThread.IsBackground = true;
            serviceThread.Start();
        }

        protected override void OnStop()
        {
            ManualResetEvent localStopEvent = stopEvent;
            if (localStopEvent != null)
            {
                localStopEvent.Set();
            }

            ProjFSProvider localProvider = provider;
            if (localProvider != null)
            {
                localProvider.StopVirtualizing();
            }

            Thread localThread = serviceThread;
            if (localThread != null && localThread.IsAlive)
            {
                localThread.Join(5000);
            }

            if (localStopEvent != null)
            {
                localStopEvent.Dispose();
            }
        }

        private void ServiceWorkerThread()
        {
            try
            {
                ServiceSettings settings = ServiceSettings.LoadFromConfig();
                DirectorySecurityGuard.PrepareRoot(settings.RootPath);

                string csvData = FileSystemDataProvider.GetCsvDataFromConfigOrFallback();
                provider = new ProjFSProvider(settings.RootPath, csvData, settings);

                Guid virtualizationInstanceId = Guid.NewGuid();
                int hr = ProjFSNative.PrjMarkDirectoryAsPlaceholder(settings.RootPath, null, IntPtr.Zero, ref virtualizationInstanceId);
                if (hr != ProjFSNative.S_OK)
                {
                    throw new Win32Exception(hr, "PrjMarkDirectoryAsPlaceholder failed.");
                }

                provider.StartVirtualizing();

                ManualResetEvent localStopEvent = stopEvent;
                if (localStopEvent != null)
                {
                    localStopEvent.WaitOne();
                }
            }
            catch (Exception ex)
            {
                SafeLogger.Error("Service worker failed: " + ex);
            }
        }
    }

    internal static class Program
    {
        private static void Main(string[] args)
        {
            if (args.Length > 0 && string.Equals(args[0], "/console", StringComparison.OrdinalIgnoreCase))
            {
                RunInConsoleMode();
                return;
            }

            ServiceBase.Run(new ServiceBase[] { new WindowsFakeFileSystemService() });
        }

        private static void RunInConsoleMode()
        {
            ProjFSProvider provider = null;
            try
            {
                ServiceSettings settings = ServiceSettings.LoadFromConfig();
                DirectorySecurityGuard.PrepareRoot(settings.RootPath);

                Console.WriteLine("Virtual Folder: " + settings.RootPath);
                Console.WriteLine("Debug Mode: " + settings.DebugMode);
                Console.WriteLine("DNS Alerts: " + settings.EnableDnsAlerts);

                string root = Path.GetPathRoot(settings.RootPath);
                if (!string.IsNullOrEmpty(root))
                {
                    DriveInfo drive = new DriveInfo(root);
                    Console.WriteLine("Available free space: " + drive.AvailableFreeSpace + " bytes");
                }

                string csvData = FileSystemDataProvider.GetCsvDataFromConfigOrFallback();
                provider = new ProjFSProvider(settings.RootPath, csvData, settings);

                Guid virtualizationInstanceId = Guid.NewGuid();
                int hr = ProjFSNative.PrjMarkDirectoryAsPlaceholder(settings.RootPath, null, IntPtr.Zero, ref virtualizationInstanceId);
                if (hr != ProjFSNative.S_OK)
                {
                    throw new Win32Exception(hr, "PrjMarkDirectoryAsPlaceholder failed.");
                }

                provider.StartVirtualizing();
                Console.WriteLine("Projected File System Provider started. Press Enter to exit.");
                Console.ReadLine();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error: " + ex.Message);
                Win32Exception win32 = ex as Win32Exception;
                if (win32 != null)
                {
                    Console.Error.WriteLine("Win32 Error Code: " + win32.NativeErrorCode);
                }
            }
            finally
            {
                if (provider != null)
                {
                    provider.StopVirtualizing();
                }
            }
        }
    }

    internal sealed class ServiceSettings
    {
        public string RootPath { get; private set; }
        public bool DebugMode { get; private set; }
        public bool EnableDnsAlerts { get; private set; }
        public string AlertDomain { get; private set; }
        public int AlertMinSeconds { get; private set; }

        public static ServiceSettings LoadFromConfig()
        {
            string rootPath = ConfigurationManager.AppSettings["RootPath"];
            if (string.IsNullOrWhiteSpace(rootPath))
            {
                rootPath = WindowsFakeFileSystemService.DefaultRootPath;
            }

            bool debugMode = GetBool("DebugMode", false);
            bool enableDnsAlerts = GetBool("EnableDnsAlerts", false);
            int alertMinSeconds = GetInt("AlertMinSeconds", 5, 1, 3600);
            string alertDomain = (ConfigurationManager.AppSettings["AlertDomain"] ?? string.Empty).Trim().Trim('.');

            if (enableDnsAlerts)
            {
                ValidateAlertDomainOrThrow(alertDomain);
            }
            else
            {
                alertDomain = string.Empty;
            }

            return new ServiceSettings
            {
                RootPath = DirectorySecurityGuard.NormalizeAndValidateRoot(rootPath),
                DebugMode = debugMode,
                EnableDnsAlerts = enableDnsAlerts,
                AlertDomain = alertDomain.ToLowerInvariant(),
                AlertMinSeconds = alertMinSeconds
            };
        }

        private static bool GetBool(string key, bool defaultValue)
        {
            bool parsed;
            string raw = ConfigurationManager.AppSettings[key];
            return bool.TryParse(raw, out parsed) ? parsed : defaultValue;
        }

        private static int GetInt(string key, int defaultValue, int minValue, int maxValue)
        {
            int parsed;
            string raw = ConfigurationManager.AppSettings[key];
            if (!int.TryParse(raw, out parsed))
            {
                return defaultValue;
            }

            if (parsed < minValue)
            {
                return minValue;
            }

            if (parsed > maxValue)
            {
                return maxValue;
            }

            return parsed;
        }

        private static void ValidateAlertDomainOrThrow(string value)
        {
            if (string.IsNullOrWhiteSpace(value) ||
                value.IndexOf("TODO", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf("INSERT", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.Length > 253 ||
                value.StartsWith(".", StringComparison.Ordinal) ||
                value.EndsWith(".", StringComparison.Ordinal))
            {
                throw new ConfigurationErrorsException("EnableDnsAlerts=true requires a valid AlertDomain.");
            }

            string[] labels = value.Split('.');
            foreach (string label in labels)
            {
                if (label.Length == 0 || label.Length > 63)
                {
                    throw new ConfigurationErrorsException("AlertDomain contains an invalid label length.");
                }

                if (label[0] == '-' || label[label.Length - 1] == '-')
                {
                    throw new ConfigurationErrorsException("AlertDomain labels must not start or end with '-'.");
                }

                for (int i = 0; i < label.Length; i++)
                {
                    char c = label[i];
                    if (!((c >= 'a' && c <= 'z') ||
                          (c >= 'A' && c <= 'Z') ||
                          (c >= '0' && c <= '9') ||
                          c == '-'))
                    {
                        throw new ConfigurationErrorsException("AlertDomain contains invalid characters.");
                    }
                }
            }
        }
    }

    internal static class DirectorySecurityGuard
    {
        private const string SentinelFileName = ".projfs-service-root";

        public static string NormalizeAndValidateRoot(string rootPath)
        {
            if (string.IsNullOrWhiteSpace(rootPath))
            {
                throw new ConfigurationErrorsException("RootPath is required.");
            }

            string fullPath = Path.GetFullPath(rootPath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            string pathRoot = Path.GetPathRoot(fullPath);
            if (string.IsNullOrEmpty(pathRoot))
            {
                throw new ConfigurationErrorsException("RootPath must be an absolute path.");
            }

            string normalizedRoot = pathRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            if (string.Equals(fullPath, normalizedRoot, StringComparison.OrdinalIgnoreCase))
            {
                throw new ConfigurationErrorsException("RootPath must not be a drive root.");
            }

            if (fullPath.Length < 8)
            {
                throw new ConfigurationErrorsException("RootPath is too short to be considered safe.");
            }

            string windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\');
            string systemDir = Environment.GetFolderPath(Environment.SpecialFolder.System).TrimEnd('\\');
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile).TrimEnd('\\');

            if (IsSameOrChild(fullPath, windowsDir) || IsSameOrChild(fullPath, systemDir) || IsSameOrChild(fullPath, userProfile))
            {
                throw new ConfigurationErrorsException("RootPath must not be inside Windows, System, or the service account profile directories.");
            }

            return fullPath;
        }

        public static void PrepareRoot(string rootPath)
        {
            string fullPath = NormalizeAndValidateRoot(rootPath);
            if (!Directory.Exists(fullPath))
            {
                Directory.CreateDirectory(fullPath);
            }

            string sentinel = GetSentinelPath(fullPath);
            if (!File.Exists(sentinel))
            {
                File.WriteAllText(sentinel, "WindowsFakeFileSystem ProjFS virtualization root. Do not delete.\r\n", Encoding.UTF8);
                File.SetAttributes(sentinel, FileAttributes.Hidden | FileAttributes.System);
            }
        }

        public static void CleanupRoot(string rootPath)
        {
            string fullPath = NormalizeAndValidateRoot(rootPath);
            string sentinel = GetSentinelPath(fullPath);
            if (!File.Exists(sentinel))
            {
                throw new InvalidOperationException("Refusing cleanup because the ProjFS sentinel file is missing: " + sentinel);
            }

            DirectoryInfo di = new DirectoryInfo(fullPath);
            foreach (FileInfo file in di.GetFiles())
            {
                if (string.Equals(file.Name, SentinelFileName, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                file.Attributes = FileAttributes.Normal;
                file.Delete();
            }

            foreach (DirectoryInfo dir in di.GetDirectories())
            {
                dir.Delete(true);
            }
        }

        private static string GetSentinelPath(string rootPath)
        {
            return Path.Combine(rootPath, SentinelFileName);
        }

        private static bool IsSameOrChild(string path, string parent)
        {
            if (string.IsNullOrEmpty(parent))
            {
                return false;
            }

            string normalizedPath = path.TrimEnd('\\') + "\\";
            string normalizedParent = parent.TrimEnd('\\') + "\\";
            return normalizedPath.StartsWith(normalizedParent, StringComparison.OrdinalIgnoreCase);
        }
    }

    internal static class FileSystemDataProvider
    {
        public static string GetCsvDataFromConfigOrFallback()
        {
            try
            {
                object section = ConfigurationManager.GetSection("fileList");
                string configured = section as string;
                if (!string.IsNullOrWhiteSpace(configured))
                {
                    return configured;
                }
            }
            catch (ConfigurationErrorsException ex)
            {
                SafeLogger.Warning("Unable to read <fileList> config section; using fallback file list. " + ex.Message);
            }

            return GetFallbackCsvData();
        }

        private static string GetFallbackCsvData()
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

    internal sealed class ProjFSProvider
    {
        private readonly string rootPath;
        private readonly Dictionary<string, List<FileEntry>> fileSystem = new Dictionary<string, List<FileEntry>>(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<Guid, int> enumerationIndices = new ConcurrentDictionary<Guid, int>();
        private readonly AlertDispatcher alertDispatcher;
        private readonly ServiceSettings settings;
        private readonly object lifecycleLock = new object();

        private ProjFSNative.PrjCallbacks callbacks;
        private IntPtr instanceHandle;
        private bool isVirtualizing;

        public ProjFSProvider(string rootPath, string csvStr, ServiceSettings settings)
        {
            if (settings == null)
            {
                throw new ArgumentNullException("settings");
            }

            this.rootPath = DirectorySecurityGuard.NormalizeAndValidateRoot(rootPath);
            this.settings = settings;
            this.alertDispatcher = new AlertDispatcher(settings);
            LoadFileSystemFromCsvString(csvStr);
        }

        public void StartVirtualizing()
        {
            lock (lifecycleLock)
            {
                if (isVirtualizing)
                {
                    return;
                }

                callbacks = new ProjFSNative.PrjCallbacks
                {
                    StartDirectoryEnumerationCallback = StartDirectoryEnumeration,
                    EndDirectoryEnumerationCallback = EndDirectoryEnumeration,
                    GetDirectoryEnumerationCallback = GetDirectoryEnumeration,
                    GetPlaceholderInfoCallback = GetPlaceholderInfo,
                    NotificationCallback = NotificationCB,
                    GetFileDataCallback = GetFileData
                };

                SafeLogger.Info("Attempting to start ProjFS virtualization at " + rootPath, settings.DebugMode);
                int hr = ProjFSNative.PrjStartVirtualizing(rootPath, ref callbacks, IntPtr.Zero, IntPtr.Zero, ref instanceHandle);
                if (hr != ProjFSNative.S_OK)
                {
                    throw new Win32Exception(hr, "PrjStartVirtualizing failed.");
                }

                isVirtualizing = true;
                SafeLogger.Info("ProjFS virtualization started successfully.", settings.DebugMode);
            }
        }

        public void StopVirtualizing()
        {
            lock (lifecycleLock)
            {
                if (!isVirtualizing || instanceHandle == IntPtr.Zero)
                {
                    return;
                }

                SafeLogger.Info("Stopping ProjFS virtualization.", settings.DebugMode);
                ProjFSNative.PrjStopVirtualizing(instanceHandle);
                instanceHandle = IntPtr.Zero;
                isVirtualizing = false;

                try
                {
                    DirectorySecurityGuard.CleanupRoot(rootPath);
                }
                catch (Exception ex)
                {
                    SafeLogger.Warning("Cleanup skipped or failed: " + ex.Message);
                }
            }
        }

        private void LoadFileSystemFromCsvString(string csvStr)
        {
            if (string.IsNullOrWhiteSpace(csvStr))
            {
                throw new ConfigurationErrorsException("The virtual file list is empty.");
            }

            string[] lines = csvStr.Split(new string[] { "\r\n", "\r", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            int rowNumber = 0;
            foreach (string rawLine in lines)
            {
                rowNumber++;
                string line = rawLine.Trim();
                if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal))
                {
                    continue;
                }

                string[] parts = line.Split(',');
                if (parts.Length != 4)
                {
                    SafeLogger.Warning("Skipping malformed fileList row " + rowNumber + ": expected 4 comma-separated fields.");
                    continue;
                }

                string rawPath = parts[0].Trim();
                bool isDirectory;
                long fileSize;
                long unixTimestamp;
                if (!bool.TryParse(parts[1].Trim(), out isDirectory) ||
                    !long.TryParse(parts[2].Trim(), out fileSize) ||
                    !long.TryParse(parts[3].Trim(), out unixTimestamp) ||
                    fileSize < 0)
                {
                    SafeLogger.Warning("Skipping malformed fileList row " + rowNumber + ": invalid type, size, or timestamp.");
                    continue;
                }

                if (!VirtualPathValidator.TryNormalize(rawPath, out string normalizedRelativePath))
                {
                    SafeLogger.Warning("Skipping unsafe fileList row " + rowNumber + ": " + rawPath);
                    continue;
                }

                string name = Path.GetFileName(normalizedRelativePath);
                string parentPath = Path.GetDirectoryName(normalizedRelativePath);
                if (string.IsNullOrEmpty(parentPath))
                {
                    parentPath = "\\";
                }

                DateTime lastWriteTime = UnixTimeToUtc(unixTimestamp);

                List<FileEntry> entries;
                if (!fileSystem.TryGetValue(parentPath, out entries))
                {
                    entries = new List<FileEntry>();
                    fileSystem[parentPath] = entries;
                }

                bool duplicate = entries.Any(e => string.Equals(e.Name, name, StringComparison.OrdinalIgnoreCase));
                if (duplicate)
                {
                    SafeLogger.Warning("Skipping duplicate fileList row " + rowNumber + ": " + rawPath);
                    continue;
                }

                entries.Add(new FileEntry
                {
                    Name = name,
                    IsDirectory = isDirectory,
                    FileSize = isDirectory ? 0 : fileSize,
                    LastWriteTime = lastWriteTime,
                    Opened = false,
                    LastAlertUnixSeconds = 0
                });
            }

            foreach (string key in fileSystem.Keys.ToList())
            {
                fileSystem[key] = fileSystem[key]
                    .OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
                    .ToList();
            }

            if (!fileSystem.ContainsKey("\\"))
            {
                throw new ConfigurationErrorsException("The virtual file list does not contain any root-level entries.");
            }
        }

        private static DateTime UnixTimeToUtc(long unixTimestamp)
        {
            if (unixTimestamp < 0)
            {
                unixTimestamp = 0;
            }

            DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            try
            {
                return epoch.AddSeconds(unixTimestamp);
            }
            catch (ArgumentOutOfRangeException)
            {
                return DateTime.UtcNow;
            }
        }

        private static long GetUnixTimeStamp()
        {
            return (long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
        }

        private int NotificationCB(
            ProjFSNative.PrjCallbackData callbackData,
            bool isDirectory,
            ProjFSNative.PrjNotification notification,
            string destinationFileName,
            ref ProjFSNative.PrjNotificationParameters operationParameters)
        {
            if (notification != ProjFSNative.PrjNotification.FileOpened || isDirectory)
            {
                return ProjFSNative.S_OK;
            }

            string callbackPath = callbackData.FilePathName ?? string.Empty;
            if (callbackPath.Length == 0)
            {
                return ProjFSNative.ERROR_FILE_NOT_FOUND;
            }

            string parentPath = Path.GetDirectoryName(callbackPath);
            if (string.IsNullOrEmpty(parentPath))
            {
                parentPath = "\\";
            }

            string fileName = Path.GetFileName(callbackPath);
            List<FileEntry> entries;
            if (!fileSystem.TryGetValue(parentPath, out entries))
            {
                return ProjFSNative.ERROR_FILE_NOT_FOUND;
            }

            FileEntry entry = entries.Find(e => string.Equals(e.Name, fileName, StringComparison.OrdinalIgnoreCase));
            if (entry == null || entry.IsDirectory)
            {
                return ProjFSNative.ERROR_FILE_NOT_FOUND;
            }

            long now = GetUnixTimeStamp();
            lock (entry.SyncRoot)
            {
                if (entry.Opened && (now - entry.LastAlertUnixSeconds) >= settings.AlertMinSeconds)
                {
                    entry.LastAlertUnixSeconds = now;
                    alertDispatcher.AlertOnFileAccess(callbackPath, callbackData.TriggeringProcessImageFileName);
                }
            }

            return ProjFSNative.S_OK;
        }

        private int StartDirectoryEnumeration(ProjFSNative.PrjCallbackData callbackData, ref Guid enumerationId)
        {
            enumerationIndices[enumerationId] = 0;
            return ProjFSNative.S_OK;
        }

        private int EndDirectoryEnumeration(ProjFSNative.PrjCallbackData callbackData, ref Guid enumerationId)
        {
            int ignored;
            enumerationIndices.TryRemove(enumerationId, out ignored);
            return ProjFSNative.S_OK;
        }

        private int GetDirectoryEnumeration(
            ProjFSNative.PrjCallbackData callbackData,
            ref Guid enumerationId,
            string searchExpression,
            IntPtr dirEntryBufferHandle)
        {
            string directoryPath = callbackData.FilePathName ?? string.Empty;
            bool single = false;

            if (string.IsNullOrEmpty(directoryPath))
            {
                directoryPath = "\\";
            }

            string effectiveSearchExpression = string.IsNullOrEmpty(searchExpression) ? "*" : searchExpression;

            if (!string.IsNullOrEmpty(searchExpression) && searchExpression != "*")
            {
                string processName = callbackData.TriggeringProcessImageFileName ?? "unknown";
                string message = string.Format("Search Pattern: '{0}' in directory '{1}' by process: {2}",
                    SanitizeForLog(searchExpression), SanitizeForLog(directoryPath), SanitizeForLog(processName));
                SafeLogger.Info(message, settings.DebugMode);

                if (ProjFSNative.PrjDoesNameContainWildCards(searchExpression))
                {
                    alertDispatcher.AlertOnSearch(directoryPath, searchExpression, processName);
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
                enumerationIndices[enumerationId] = 0;
            }

            if ((callbackData.Flags & ProjFSNative.PrjCallbackDataFlags.RestartScan) == ProjFSNative.PrjCallbackDataFlags.RestartScan)
            {
                currentIndex = 0;
                enumerationIndices[enumerationId] = 0;
            }

            if ((callbackData.Flags & ProjFSNative.PrjCallbackDataFlags.ReturnSingleEntry) == ProjFSNative.PrjCallbackDataFlags.ReturnSingleEntry)
            {
                single = true;
            }

            for (; currentIndex < entries.Count; currentIndex++)
            {
                FileEntry entry = entries[currentIndex];
                if (!ProjFSNative.PrjFileNameMatch(entry.Name, effectiveSearchExpression))
                {
                    enumerationIndices[enumerationId] = currentIndex + 1;
                    continue;
                }

                ProjFSNative.PrjFileBasicInfo fileInfo = BuildBasicInfo(entry);
                int result = ProjFSNative.PrjFillDirEntryBuffer(entry.Name, ref fileInfo, dirEntryBufferHandle);
                if (result != ProjFSNative.S_OK)
                {
                    return ProjFSNative.S_OK;
                }

                enumerationIndices[enumerationId] = currentIndex + 1;
                if (single)
                {
                    return ProjFSNative.S_OK;
                }
            }

            return ProjFSNative.S_OK;
        }

        private int GetPlaceholderInfo(ProjFSNative.PrjCallbackData callbackData)
        {
            string filePath = callbackData.FilePathName ?? string.Empty;
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

            FileEntry entry = entries.Find(e => string.Equals(e.Name, fileName, StringComparison.OrdinalIgnoreCase));
            if (entry == null)
            {
                return ProjFSNative.ERROR_FILE_NOT_FOUND;
            }

            ProjFSNative.PrjPlaceholderInfo placeholderInfo = new ProjFSNative.PrjPlaceholderInfo
            {
                FileBasicInfo = BuildBasicInfo(entry)
            };

            int result = ProjFSNative.PrjWritePlaceholderInfo(
                callbackData.NamespaceVirtualizationContext,
                filePath,
                ref placeholderInfo,
                (uint)Marshal.SizeOf(typeof(ProjFSNative.PrjPlaceholderInfo)));

            return result;
        }

        private int GetFileData(ProjFSNative.PrjCallbackData callbackData, ulong byteOffset, uint length)
        {
            if (instanceHandle == IntPtr.Zero)
            {
                return ProjFSNative.ERROR_FILE_NOT_FOUND;
            }

            string callbackPath = callbackData.FilePathName ?? string.Empty;
            if (callbackPath.Length == 0)
            {
                return ProjFSNative.ERROR_FILE_NOT_FOUND;
            }

            string parentPath = Path.GetDirectoryName(callbackPath);
            if (string.IsNullOrEmpty(parentPath))
            {
                parentPath = "\\";
            }

            string fileName = Path.GetFileName(callbackPath);

            List<FileEntry> entries;
            if (!fileSystem.TryGetValue(parentPath, out entries))
            {
                return ProjFSNative.ERROR_FILE_NOT_FOUND;
            }

            FileEntry entry = entries.Find(e => string.Equals(e.Name, fileName, StringComparison.OrdinalIgnoreCase));
            if (entry == null || entry.IsDirectory)
            {
                return ProjFSNative.ERROR_FILE_NOT_FOUND;
            }

            long now = GetUnixTimeStamp();
            lock (entry.SyncRoot)
            {
                if (!entry.Opened || (now - entry.LastAlertUnixSeconds) >= settings.AlertMinSeconds)
                {
                    alertDispatcher.AlertOnFileAccess(callbackPath, callbackData.TriggeringProcessImageFileName);
                    entry.LastAlertUnixSeconds = now;
                }

                entry.Opened = true;
            }

            byte[] fileContent = BuildVirtualFileContent(fileName, entry.FileSize);
            if (byteOffset >= (ulong)fileContent.Length)
            {
                return ProjFSNative.S_OK;
            }

            ulong remaining = (ulong)fileContent.Length - byteOffset;
            uint bytesToWrite = remaining > length ? length : (uint)remaining;
            IntPtr buffer = ProjFSNative.PrjAllocateAlignedBuffer(instanceHandle, bytesToWrite);
            if (buffer == IntPtr.Zero)
            {
                return ProjFSNative.ERROR_INSUFFICIENT_BUFFER;
            }

            try
            {
                Marshal.Copy(fileContent, checked((int)byteOffset), buffer, checked((int)bytesToWrite));
                return ProjFSNative.PrjWriteFileData(instanceHandle, ref callbackData.DataStreamId, buffer, byteOffset, bytesToWrite);
            }
            finally
            {
                ProjFSNative.PrjFreeAlignedBuffer(buffer);
            }
        }

        private static ProjFSNative.PrjFileBasicInfo BuildBasicInfo(FileEntry entry)
        {
            long fileTime = entry.LastWriteTime.ToFileTimeUtc();
            return new ProjFSNative.PrjFileBasicInfo
            {
                IsDirectory = entry.IsDirectory,
                FileSize = entry.IsDirectory ? 0 : entry.FileSize,
                CreationTime = fileTime,
                LastAccessTime = fileTime,
                LastWriteTime = fileTime,
                ChangeTime = fileTime,
                FileAttributes = entry.IsDirectory ? FileAttributes.Directory : FileAttributes.Normal
            };
        }

        private static byte[] BuildVirtualFileContent(string fileName, long advertisedSize)
        {
            byte[] bom = new byte[] { 0xEF, 0xBB, 0xBF };
            byte[] textBytes = Encoding.UTF8.GetBytes("This is the content of " + fileName + Environment.NewLine);
            byte[] baseContent = new byte[bom.Length + textBytes.Length];
            Buffer.BlockCopy(bom, 0, baseContent, 0, bom.Length);
            Buffer.BlockCopy(textBytes, 0, baseContent, bom.Length, textBytes.Length);

            if (advertisedSize <= baseContent.Length || advertisedSize > 1024 * 1024)
            {
                return baseContent;
            }

            byte[] padded = new byte[(int)advertisedSize];
            Buffer.BlockCopy(baseContent, 0, padded, 0, baseContent.Length);
            for (int i = baseContent.Length; i < padded.Length; i++)
            {
                padded[i] = (byte)' ';
            }

            return padded;
        }

        private static string SanitizeForLog(string value)
        {
            if (value == null)
            {
                return "unknown";
            }

            return value.Replace("\r", " ").Replace("\n", " ").Replace("\t", " ");
        }
    }

    internal sealed class FileEntry
    {
        public string Name { get; set; }
        public bool IsDirectory { get; set; }
        public long FileSize { get; set; }
        public DateTime LastWriteTime { get; set; }
        public bool Opened { get; set; }
        public long LastAlertUnixSeconds { get; set; }
        public object SyncRoot { get; private set; }

        public FileEntry()
        {
            SyncRoot = new object();
        }
    }

    internal static class VirtualPathValidator
    {
        private static readonly HashSet<string> ReservedDeviceNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
        };

        public static bool TryNormalize(string input, out string normalizedRelativePath)
        {
            normalizedRelativePath = null;
            if (string.IsNullOrWhiteSpace(input))
            {
                return false;
            }

            string trimmed = input.Trim();
            if (trimmed.StartsWith("\\\\", StringComparison.Ordinal) || trimmed.Contains(":"))
            {
                return false;
            }

            trimmed = trimmed.TrimStart('\\', '/');
            string[] parts = trimmed.Split(new char[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0)
            {
                return false;
            }

            foreach (string part in parts)
            {
                if (!IsSafeSegment(part))
                {
                    return false;
                }
            }

            normalizedRelativePath = string.Join("\\", parts);
            return true;
        }

        private static bool IsSafeSegment(string segment)
        {
            if (string.IsNullOrWhiteSpace(segment) || segment == "." || segment == "..")
            {
                return false;
            }

            if (segment.EndsWith(".", StringComparison.Ordinal) || segment.EndsWith(" ", StringComparison.Ordinal))
            {
                return false;
            }

            string nameWithoutExtension = segment;
            int dot = segment.IndexOf('.');
            if (dot >= 0)
            {
                nameWithoutExtension = segment.Substring(0, dot);
            }

            if (ReservedDeviceNames.Contains(nameWithoutExtension))
            {
                return false;
            }

            char[] invalid = Path.GetInvalidFileNameChars();
            return segment.IndexOfAny(invalid) < 0;
        }
    }

    internal sealed class AlertDispatcher
    {
        private const int MaxDnsNameLength = 253;
        private const int MaxDnsPayloadCharacters = 160;
        private static readonly char[] Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".ToCharArray();

        private readonly ServiceSettings settings;
        private readonly ConcurrentDictionary<string, long> lastAlertByKey = new ConcurrentDictionary<string, long>(StringComparer.OrdinalIgnoreCase);

        public AlertDispatcher(ServiceSettings settings)
        {
            this.settings = settings;
        }

        public void AlertOnFileAccess(string filePath, string processImageFileName)
        {
            string safeFilePath = SanitizeForLog(filePath);
            string processName = ExtractFileNameOrUnknown(processImageFileName);
            string key = "file|" + safeFilePath + "|" + processName;

            if (!ShouldAlert(key))
            {
                return;
            }

            string message = "File accessed: " + safeFilePath + " | Process: " + processName;
            SafeLogger.Warning(message);

            if (settings.EnableDnsAlerts)
            {
                string fileName = ExtractFileNameOrUnknown(filePath);
                string payload = "f" + ToBase32(fileName) + ".i" + ToBase32(processName);
                SendDnsAlertAsync("u", payload);
            }
        }

        public void AlertOnSearch(string directoryPath, string searchPattern, string processImageFileName)
        {
            string safeDirectory = SanitizeForLog(directoryPath);
            string safePattern = SanitizeForLog(searchPattern);
            string processName = ExtractFileNameOrUnknown(processImageFileName);
            string key = "search|" + safeDirectory + "|" + safePattern + "|" + processName;

            if (!ShouldAlert(key))
            {
                return;
            }

            string message = "Search detected: Pattern=" + safePattern + " | Directory=" + safeDirectory + " | Process=" + processName;
            SafeLogger.Warning(message);

            if (settings.EnableDnsAlerts)
            {
                string payload = "q" + ToBase32(searchPattern) + ".d" + ToBase32(directoryPath) + ".i" + ToBase32(processName);
                SendDnsAlertAsync("s", payload);
            }
        }

        private bool ShouldAlert(string key)
        {
            long now = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
            long previous;
            if (lastAlertByKey.TryGetValue(key, out previous) && (now - previous) < settings.AlertMinSeconds)
            {
                return false;
            }

            lastAlertByKey[key] = now;
            return true;
        }

        private void SendDnsAlertAsync(string prefix, string payload)
        {
            if (string.IsNullOrEmpty(settings.AlertDomain))
            {
                return;
            }

            string alertName;
            try
            {
                alertName = BuildDnsAlertName(prefix, payload, settings.AlertDomain);
            }
            catch (Exception ex)
            {
                SafeLogger.Warning("DNS alert suppressed: " + ex.Message);
                return;
            }

            ThreadPool.QueueUserWorkItem(delegate
            {
                try
                {
                    Dns.GetHostEntry(alertName);
                }
                catch (Exception ex)
                {
                    SafeLogger.Info("DNS alert lookup failed: " + ex.Message, settings.DebugMode);
                }
            });
        }

        private static string BuildDnsAlertName(string prefix, string payload, string domain)
        {
            string id = prefix + NewAlertId();
            string boundedPayload = payload.Length > MaxDnsPayloadCharacters ? payload.Substring(0, MaxDnsPayloadCharacters) : payload;
            List<string> labels = new List<string>();
            labels.Add(id);
            labels.AddRange(SplitLabel(boundedPayload, 50));
            labels.Add(domain.Trim('.'));

            string name = string.Join(".", labels.ToArray());
            if (name.Length > MaxDnsNameLength)
            {
                throw new InvalidOperationException("DNS alert name exceeds maximum DNS length.");
            }

            return name;
        }

        private static IEnumerable<string> SplitLabel(string value, int size)
        {
            if (string.IsNullOrEmpty(value))
            {
                yield return "empty";
                yield break;
            }

            for (int i = 0; i < value.Length; i += size)
            {
                yield return value.Substring(i, Math.Min(size, value.Length - i));
            }
        }

        private static string NewAlertId()
        {
            byte[] bytes = new byte[8];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }

            StringBuilder sb = new StringBuilder(bytes.Length * 2);
            for (int i = 0; i < bytes.Length; i++)
            {
                sb.Append(bytes[i].ToString("x2"));
            }

            return sb.ToString();
        }

        private static string ToBase32(string value)
        {
            if (value == null)
            {
                value = string.Empty;
            }

            byte[] bytes = Encoding.UTF8.GetBytes(value);
            StringBuilder output = new StringBuilder((bytes.Length * 8 + 4) / 5);

            int buffer = 0;
            int bitsLeft = 0;
            foreach (byte b in bytes)
            {
                buffer = (buffer << 8) | b;
                bitsLeft += 8;
                while (bitsLeft >= 5)
                {
                    int index = (buffer >> (bitsLeft - 5)) & 0x1F;
                    output.Append(Base32Alphabet[index]);
                    bitsLeft -= 5;
                }
            }

            if (bitsLeft > 0)
            {
                int index = (buffer << (5 - bitsLeft)) & 0x1F;
                output.Append(Base32Alphabet[index]);
            }

            return output.ToString();
        }

        private static string ExtractFileNameOrUnknown(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return "unknown";
            }

            try
            {
                string name = Path.GetFileName(value);
                return string.IsNullOrWhiteSpace(name) ? SanitizeForLog(value) : SanitizeForLog(name);
            }
            catch (ArgumentException)
            {
                return "unknown";
            }
        }

        private static string SanitizeForLog(string value)
        {
            if (value == null)
            {
                return "unknown";
            }

            string cleaned = value.Replace("\r", " ").Replace("\n", " ").Replace("\t", " ");
            return cleaned.Length > 512 ? cleaned.Substring(0, 512) : cleaned;
        }
    }

    internal static class SafeLogger
    {
        public static void Info(string message, bool enabled)
        {
            if (!enabled)
            {
                return;
            }

            Write(message, EventLogEntryType.Information);
        }

        public static void Warning(string message)
        {
            Write(message, EventLogEntryType.Warning);
        }

        public static void Error(string message)
        {
            Write(message, EventLogEntryType.Error);
        }

        private static void Write(string message, EventLogEntryType type)
        {
            string safeMessage = Sanitize(message);
            try
            {
                if (EventLog.SourceExists(WindowsFakeFileSystemService.EventSourceName))
                {
                    EventLog.WriteEntry(WindowsFakeFileSystemService.EventSourceName, safeMessage, type);
                }
                else
                {
                    Console.WriteLine(type + ": " + safeMessage);
                }
            }
            catch
            {
                Console.WriteLine(type + ": " + safeMessage);
            }
        }

        private static string Sanitize(string value)
        {
            if (value == null)
            {
                return string.Empty;
            }

            string cleaned = value.Replace("\r", " ").Replace("\n", " ").Replace("\t", " ");
            return cleaned.Length > 30000 ? cleaned.Substring(0, 30000) : cleaned;
        }
    }

    internal static class ProjFSNative
    {
        public const int S_OK = 0;
        public const int ERROR_INSUFFICIENT_BUFFER = 122;
        public const int ERROR_FILE_NOT_FOUND = 2;

        [DllImport("ProjectedFSLib.dll")]
        public static extern IntPtr PrjAllocateAlignedBuffer(IntPtr namespaceVirtualizationContext, uint size);

        [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool PrjDoesNameContainWildCards(string fileName);

        [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode)]
        public static extern int PrjFileNameCompare(string fileName1, string fileName2);

        [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool PrjFileNameMatch(string fileNameToCheck, string pattern);

        [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode)]
        public static extern int PrjFillDirEntryBuffer(string fileName, ref PrjFileBasicInfo fileBasicInfo, IntPtr dirEntryBufferHandle);

        [DllImport("ProjectedFSLib.dll")]
        public static extern void PrjFreeAlignedBuffer(IntPtr buffer);

        [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode)]
        public static extern int PrjMarkDirectoryAsPlaceholder(string rootPathName, string targetPathName, IntPtr versionInfo, ref Guid virtualizationInstanceID);

        [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode)]
        public static extern int PrjStartVirtualizing(string virtualizationRootPath, ref PrjCallbacks callbacks, IntPtr instanceContext, IntPtr options, ref IntPtr namespaceVirtualizationContext);

        [DllImport("ProjectedFSLib.dll")]
        public static extern void PrjStopVirtualizing(IntPtr namespaceVirtualizationContext);

        [DllImport("ProjectedFSLib.dll")]
        public static extern int PrjWriteFileData(IntPtr namespaceVirtualizationContext, ref Guid dataStreamId, IntPtr buffer, ulong byteOffset, uint length);

        [DllImport("ProjectedFSLib.dll", CharSet = CharSet.Unicode)]
        public static extern int PrjWritePlaceholderInfo(IntPtr namespaceVirtualizationContext, string destinationFileName, ref PrjPlaceholderInfo placeholderInfo, uint placeholderInfoSize);

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
            [MarshalAs(UnmanagedType.LPWStr)]
            public string FilePathName;
            public IntPtr VersionInfo;
            public uint TriggeringProcessId;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string TriggeringProcessImageFileName;
            public IntPtr InstanceContext;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PrjFileBasicInfo
        {
            [MarshalAs(UnmanagedType.I1)]
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
            [MarshalAs(UnmanagedType.I1)]
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
            None = 0,
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
            None = 0,
            SuppressNotifications = 1,
            FileOpened = 2,
            NewFileCreated = 4,
            FileOverwritten = 8,
            PreDelete = 16,
            PreRename = 32,
            PreSetHardlink = 64,
            FileRenamed = 128,
            HardlinkCreated = 256,
            FileHandleClosedNoModification = 512,
            FileHandleClosedFileModified = 1024,
            FileHandleClosedFileDeleted = 2048,
            FilePreConvertToFull = 4096,
            UseExistingMask = 0xFFFFFFFF
        }

        public enum PrjPlaceholderID : uint
        {
            Length = 128
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public delegate int PrjCancelCommandCb(IntPtr callbackData);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public delegate int PrjEndDirectoryEnumerationCb(PrjCallbackData callbackData, ref Guid enumerationId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public delegate int PrjGetDirectoryEnumerationCb(PrjCallbackData callbackData, ref Guid enumerationId, string searchExpression, IntPtr dirEntryBufferHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public delegate int PrjGetFileDataCb(PrjCallbackData callbackData, ulong byteOffset, uint length);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public delegate int PrjGetPlaceholderInfoCb(PrjCallbackData callbackData);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public delegate int PrjNotificationCb(PrjCallbackData callbackData, bool isDirectory, PrjNotification notification, string destinationFileName, ref PrjNotificationParameters operationParameters);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public delegate int PrjStartDirectoryEnumerationCb(PrjCallbackData callbackData, ref Guid enumerationId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public delegate int PrjQueryFileNameCb(IntPtr callbackData);
    }

    [RunInstaller(true)]
    public class ProjectInstaller : Installer
    {
        private readonly ServiceProcessInstaller serviceProcessInstaller;
        private readonly ServiceInstaller serviceInstaller;
        private readonly EventLogInstaller eventLogInstaller;

        public ProjectInstaller()
        {
            serviceProcessInstaller = new ServiceProcessInstaller
            {
                Account = ServiceAccount.NetworkService,
                Username = null,
                Password = null
            };

            serviceInstaller = new ServiceInstaller
            {
                ServiceName = WindowsFakeFileSystemService.ServiceNameConst,
                DisplayName = "Windows Fake File System Service",
                Description = "Monitors virtual file system access using Windows Projected File System",
                StartType = ServiceStartMode.Automatic
            };

            eventLogInstaller = new EventLogInstaller
            {
                Source = WindowsFakeFileSystemService.EventSourceName,
                Log = "Application"
            };

            Installers.Add(serviceProcessInstaller);
            Installers.Add(serviceInstaller);
            Installers.Add(eventLogInstaller);
        }
    }

    public class FileListConfigSection : IConfigurationSectionHandler
    {
        public object Create(object parent, object configContext, XmlNode section)
        {
            return section == null ? string.Empty : section.InnerText;
        }
    }
}
