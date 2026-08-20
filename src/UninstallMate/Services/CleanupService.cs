using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using UninstallMate.Models;

namespace UninstallMate.Services;

public sealed class CleanupService
{
    private readonly string _dataRoot;

    public CleanupService(string? dataRoot = null)
    {
        _dataRoot = dataRoot ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "UninstallMate");
    }

    public async Task<(CleanupReport Report, string SessionFolder)> ExecuteAsync(
        InstalledApplication app,
        IEnumerable<CleanupCandidate> selected,
        bool preserveBackups,
        IProgress<string>? progress,
        CancellationToken token)
    {
        var sessionId = $"{DateTime.Now:yyyyMMdd-HHmmss}-{SafeName(app.DisplayName)}";
        var sessionFolder = Path.Combine(_dataRoot, preserveBackups ? "Quarantine" : "Logs", sessionId);
        Directory.CreateDirectory(sessionFolder);

        var report = new CleanupReport
        {
            SessionId = sessionId,
            ApplicationName = app.DisplayName,
            FinalStatus = "InProgress"
        };

        var selectedList = selected.ToList();
        var index = 0;
        var environmentModified = false;

        foreach (var item in selectedList)
        {
            token.ThrowIfCancellationRequested();
            progress?.Report($"Cleaning {++index}/{selectedList.Count}: {DisplayTarget(item)}");
            try
            {
                var (detail, recoverySource, payloadJson, verificationStatus) = await ExecuteItemAsync(
                    item, preserveBackups, sessionFolder, sessionId, index, token);

                if (item.Kind == CleanupKind.EnvironmentEntry)
                    environmentModified = true;

                if (verificationStatus == "PendingReboot")
                    report.RestartRequired = true;

                report.Items.Add(new(
                    item.Target, item.Kind, true, detail, recoverySource,
                    item.RegistryViewName, item.Auxiliary, item.EvidencePath,
                    item.Risk, item.Confidence, item.SourceProvider,
                    item.RegistryValueKindName, item.RegistryRawValueBase64,
                    payloadJson, VerificationStatus: verificationStatus));
            }
            catch (Exception ex)
            {
                report.Items.Add(new(
                    item.Target, item.Kind, false, ex.Message,
                    RegistryViewName: item.RegistryViewName, Auxiliary: item.Auxiliary,
                    EvidencePath: item.EvidencePath, Risk: item.Risk, Confidence: item.Confidence,
                    SourceProvider: item.SourceProvider, VerificationStatus: "Failed"));
            }
        }

        if (environmentModified && RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            BroadcastEnvironmentChange();
        }

        report.FinishedAt = DateTimeOffset.Now;
        await SaveReportAtomicallyAsync(report, sessionFolder, token);

        return (report, sessionFolder);
    }

    public static async Task SaveReportAtomicallyAsync(CleanupReport report, string sessionFolder, CancellationToken token)
    {
        var reportPath = Path.Combine(sessionFolder, "cleanup-report.json");
        var tmpPath = Path.Combine(sessionFolder, "cleanup-report.json.tmp");
        var json = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(tmpPath, json, token);
        File.Move(tmpPath, reportPath, overwrite: true);
    }

    private static async Task<(string Detail, string RecoverySource, string PayloadJson, string VerificationStatus)> ExecuteItemAsync(
        CleanupCandidate item,
        bool preserveBackups,
        string sessionFolder,
        string sessionId,
        int index,
        CancellationToken token)
    {
        switch (item.Kind)
        {
            case CleanupKind.File:
            case CleanupKind.Directory:
                {
                    if (IsWithinProtectedWindowsRoot(item.Target))
                        throw new CleanupSafetyException($"Target '{item.Target}' is within a protected Windows directory. Cleanup rejected.");

                    if (preserveBackups)
                    {
                        var quarantine = QuarantinePath(item.Target, sessionFolder, sessionId, index);
                        return (quarantine.Length == 0 ? "Already absent" : "Moved to quarantine", quarantine, "", "Deleted");
                    }

                    var deleted = DeletePathPermanently(item.Target);
                    return (deleted ? "Permanently deleted" : "Locked file scheduled for reboot removal", "", "", deleted ? "Deleted" : "PendingReboot");
                }

            case CleanupKind.RegistryKey:
                {
                    string backup = "";
                    if (preserveBackups)
                    {
                        backup = await ExportRegistryKeyAsync(item.Target, item.RegistryViewName, sessionFolder, token);
                        if (string.IsNullOrEmpty(backup) || (!File.Exists(backup) && !Directory.Exists(backup)))
                        {
                            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                                throw new CleanupSafetyException($"Failed to create registry key backup for '{item.Target}'. No destructive action performed.");
                        }
                    }
                    DeleteRegistryKey(item.Target, item.RegistryViewName);
                    return (preserveBackups ? "Registry key exported, then removed" : "Registry key permanently deleted", backup, "", "Deleted");
                }

            case CleanupKind.RegistryValue:
            case CleanupKind.FirewallRule:
                {
                    string backupFile = "";
                    string payloadJson = "";

                    if (preserveBackups)
                    {
                        if (item.RegistryViewName == "Both")
                        {
                            var bundle = CreateRegistryValueBundle(item.Target, item.Auxiliary);
                            if (bundle.Values.Count == 0 && RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                                throw new CleanupSafetyException($"Failed to backup registry value '{item.Auxiliary}' across views. No destructive action performed.");

                            payloadJson = JsonSerializer.Serialize(bundle, new JsonSerializerOptions { WriteIndented = true });
                            backupFile = Path.Combine(sessionFolder, $"regbundle-{index:D3}-{Guid.NewGuid():N}.json");
                            await File.WriteAllTextAsync(backupFile, payloadJson, token);
                        }
                        else
                        {
                            var backupData = CreateRegistryValueBackup(item.Target, item.RegistryViewName, item.Auxiliary);
                            if (backupData is null && RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                                throw new CleanupSafetyException($"Failed to backup registry value '{item.Auxiliary}'. No destructive action performed.");

                            if (backupData is not null)
                            {
                                payloadJson = JsonSerializer.Serialize(backupData, new JsonSerializerOptions { WriteIndented = true });
                                backupFile = Path.Combine(sessionFolder, $"regval-{index:D3}-{Guid.NewGuid():N}.json");
                                await File.WriteAllTextAsync(backupFile, payloadJson, token);
                            }
                        }
                    }

                    DeleteRegistryValue(item.Target, item.RegistryViewName, item.Auxiliary);
                    return (preserveBackups ? "Registry value saved to backup, then removed" : "Registry value permanently deleted", backupFile, payloadJson, "Deleted");
                }

            case CleanupKind.EnvironmentEntry:
                {
                    string backupFile = "";
                    string payloadJson = "";

                    var (hive, subKey) = CleanupScanner.SplitRegistryPath(item.Target);
                    var (originalIndex, prevSegment, nextSegment) = GetEnvironmentPathSegmentNeighbors(item.Target, item.RegistryViewName, item.Auxiliary, item.EvidencePath);

                    if (preserveBackups)
                    {
                        var pathBackup = new PathSegmentBackupData
                        {
                            Hive = hive.ToString(),
                            SubKey = subKey,
                            View = item.RegistryViewName,
                            ValueName = item.Auxiliary,
                            RemovedSegment = item.EvidencePath,
                            OriginalIndex = originalIndex,
                            PreviousSegment = prevSegment,
                            NextSegment = nextSegment
                        };
                        payloadJson = JsonSerializer.Serialize(pathBackup, new JsonSerializerOptions { WriteIndented = true });
                        backupFile = Path.Combine(sessionFolder, $"env-{index:D3}-{Guid.NewGuid():N}.json");
                        await File.WriteAllTextAsync(backupFile, payloadJson, token);
                    }

                    RemoveEnvironmentPathEntry(item.Target, item.RegistryViewName, item.Auxiliary, item.EvidencePath);
                    return (preserveBackups ? "PATH segment saved to backup, then removed" : "App path permanently removed from environment value", backupFile, payloadJson, "Deleted");
                }

            case CleanupKind.WindowsService:
                {
                    string backupFile = "";
                    string payloadJson = "";
                    if (preserveBackups)
                    {
                        var serviceBackup = CaptureServiceDefinition(item.Auxiliary);
                        if (serviceBackup is null && RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                            throw new CleanupSafetyException($"Failed to capture service definition for '{item.Auxiliary}'. No destructive action performed.");

                        if (serviceBackup is not null)
                        {
                            payloadJson = JsonSerializer.Serialize(serviceBackup, new JsonSerializerOptions { WriteIndented = true });
                            backupFile = Path.Combine(sessionFolder, $"svc-{index:D3}-{Guid.NewGuid():N}.json");
                            await File.WriteAllTextAsync(backupFile, payloadJson, token);
                        }
                    }

                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        await RunToolAsync("sc.exe", ["stop", item.Auxiliary], token, acceptFailure: true);
                        await Task.Delay(250, token);
                        await RunToolAsync("sc.exe", ["delete", item.Auxiliary], token);
                    }
                    return (preserveBackups ? "Service definition backed up, then service deleted" : "Service permanently deleted", backupFile, payloadJson, "Deleted");
                }

            case CleanupKind.ScheduledTask:
                {
                    var backup = "";
                    if (preserveBackups && RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        backup = await ExportScheduledTaskAsync(item.Target, sessionFolder, token);
                        if (string.IsNullOrEmpty(backup) || !File.Exists(backup))
                            throw new CleanupSafetyException($"Failed to export scheduled task '{item.Target}'. No destructive action performed.");
                    }

                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        await RunToolAsync("schtasks.exe", ["/delete", "/tn", item.Target, "/f"], token);
                    }
                    return (preserveBackups ? "Task definition exported, then task deleted" : "Scheduled task permanently deleted", backup, "", "Deleted");
                }

            default:
                throw new NotSupportedException($"Unsupported cleanup kind: {item.Kind}");
        }
    }

    public static bool PathEquals(string a, string b)
    {
        if (string.IsNullOrWhiteSpace(a) || string.IsNullOrWhiteSpace(b)) return false;
        var left = a.Trim().Trim('"', '\'').TrimEnd('\\', '/').Replace('/', '\\');
        var right = b.Trim().Trim('"', '\'').TrimEnd('\\', '/').Replace('/', '\\');
        return left.Equals(right, StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsWithin(string candidate, string root)
    {
        if (string.IsNullOrWhiteSpace(candidate) || string.IsNullOrWhiteSpace(root)) return false;
        var c = candidate.Trim().Trim('"', '\'').TrimEnd('\\', '/').Replace('/', '\\');
        var r = root.Trim().Trim('"', '\'').TrimEnd('\\', '/').Replace('/', '\\');
        return c.Equals(r, StringComparison.OrdinalIgnoreCase)
            || c.StartsWith(r + "\\", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsWithinProtectedWindowsRoot(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return true;
        try
        {
            var p = path.Trim().Trim('"', '\'').TrimEnd('\\', '/');

            // 1. Root-only protected locations (exact path match only - descendants are allowed if safe)
            var usersRoot = @"C:\Users";
            if (PathEquals(p, usersRoot)) return true;

            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (!string.IsNullOrEmpty(userProfile) && PathEquals(p, userProfile)) return true;

            var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            if (!string.IsNullOrEmpty(programData) && PathEquals(p, programData)) return true;

            var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            if (!string.IsNullOrEmpty(programFiles) && PathEquals(p, programFiles)) return true;

            var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            if (!string.IsNullOrEmpty(programFilesX86) && PathEquals(p, programFilesX86)) return true;

            // 2. Subtree protected locations (entire tree forbidden)
            var forbiddenSubtrees = new List<string>
            {
                @"C:\Windows",
                @"C:\Windows\System32",
                @"C:\Windows\SysWOW64",
                @"C:\Windows\WinSxS",
                @"C:\Windows\Installer",
                @"C:\Windows\System32\DriverStore",
                @"C:\ProgramData\Microsoft",
                @"/bin",
                @"/sbin",
                @"/usr",
                @"/etc",
                @"/var",
                @"/root"
            };

            var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (!string.IsNullOrEmpty(winDir))
            {
                forbiddenSubtrees.Add(winDir);
                forbiddenSubtrees.Add(Path.Combine(winDir, "System32"));
                forbiddenSubtrees.Add(Path.Combine(winDir, "SysWOW64"));
                forbiddenSubtrees.Add(Path.Combine(winDir, "WinSxS"));
                forbiddenSubtrees.Add(Path.Combine(winDir, "Installer"));
                forbiddenSubtrees.Add(Path.Combine(winDir, "System32", "DriverStore"));
            }

            if (!string.IsNullOrEmpty(programData))
            {
                forbiddenSubtrees.Add(Path.Combine(programData, "Microsoft"));
            }

            foreach (var r in forbiddenSubtrees)
            {
                if (IsWithin(p, r)) return true;
            }

            return false;
        }
        catch { return true; }
    }

    public static RegistryValueBackupData? CreateRegistryValueBackup(string path, string viewName, string valueName)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return null;
        try
        {
            var (hiveName, subKey) = CleanupScanner.SplitRegistryPath(path);
            using var hive = CleanupScanner.OpenHive(hiveName, viewName);
            using var key = hive.OpenSubKey(subKey);
            if (key is null) return null;

            var rawObj = key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            if (rawObj is null) return null;

            var kind = key.GetValueKind(valueName);

            string? stringVal = null;
            string[]? multiVal = null;
            int? dwordVal = null;
            long? qwordVal = null;
            byte[]? binaryVal = null;
            string rawBase64 = "";

            switch (kind)
            {
                case RegistryValueKind.String:
                case RegistryValueKind.ExpandString:
                    stringVal = rawObj.ToString();
                    break;
                case RegistryValueKind.MultiString:
                    multiVal = rawObj as string[];
                    break;
                case RegistryValueKind.DWord:
                    dwordVal = Convert.ToInt32(rawObj);
                    break;
                case RegistryValueKind.QWord:
                    qwordVal = Convert.ToInt64(rawObj);
                    break;
                case RegistryValueKind.Binary:
                    binaryVal = rawObj as byte[];
                    if (binaryVal is not null) rawBase64 = Convert.ToBase64String(binaryVal);
                    break;
                default:
                    stringVal = rawObj.ToString();
                    break;
            }

            return new RegistryValueBackupData
            {
                Hive = hiveName.ToString(),
                SubKey = subKey,
                View = viewName,
                ValueName = valueName,
                ValueKind = kind.ToString(),
                StringValue = stringVal,
                MultiStringValue = multiVal,
                DWordValue = dwordVal,
                QWordValue = qwordVal,
                BinaryValue = binaryVal,
                RawValueBase64 = rawBase64
            };
        }
        catch { return null; }
    }

    public static RegistryValueBackupBundle CreateRegistryValueBundle(string path, string valueName)
    {
        var bundle = new RegistryValueBackupBundle();
        foreach (var view in new[] { "64", "32" })
        {
            var data = CreateRegistryValueBackup(path, view, valueName);
            if (data is not null) bundle.Values.Add(data);
        }
        return bundle;
    }

    private static ServiceBackupData? CaptureServiceDefinition(string serviceName)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return null;
        try
        {
            using var hive = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var serviceKey = hive.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}");
            if (serviceKey is null) return null;

            var imagePath = Convert.ToString(serviceKey.GetValue("ImagePath", "", RegistryValueOptions.DoNotExpandEnvironmentNames)) ?? "";
            var displayName = Convert.ToString(serviceKey.GetValue("DisplayName")) ?? serviceName;
            var description = Convert.ToString(serviceKey.GetValue("Description")) ?? "";
            var serviceType = Convert.ToInt32(serviceKey.GetValue("Type") ?? 0x10);
            var startType = Convert.ToInt32(serviceKey.GetValue("Start") ?? 2);
            var errorControl = Convert.ToInt32(serviceKey.GetValue("ErrorControl") ?? 1);
            var objectName = Convert.ToString(serviceKey.GetValue("ObjectName")) ?? "";
            var delayed = Convert.ToInt32(serviceKey.GetValue("DelayedAutoStart") ?? 0) != 0;
            var dependOnService = serviceKey.GetValue("DependOnService") as string[] ?? [];

            var serviceDll = "";
            var paramDict = new Dictionary<string, string>();
            using (var paramsKey = serviceKey.OpenSubKey("Parameters"))
            {
                if (paramsKey is not null)
                {
                    serviceDll = Convert.ToString(paramsKey.GetValue("ServiceDll", "", RegistryValueOptions.DoNotExpandEnvironmentNames)) ?? "";
                    foreach (var val in paramsKey.GetValueNames())
                    {
                        var v = paramsKey.GetValue(val)?.ToString();
                        if (v is not null) paramDict[val] = v;
                    }
                }
            }

            return new ServiceBackupData
            {
                ServiceName = serviceName,
                DisplayName = displayName,
                ImagePath = imagePath,
                ServiceDll = serviceDll,
                ServiceType = serviceType,
                StartType = startType,
                ErrorControl = errorControl,
                ServiceAccount = objectName,
                Dependencies = dependOnService,
                DelayedAutoStart = delayed,
                Description = description,
                Parameters = paramDict
            };
        }
        catch { return null; }
    }

    private static string QuarantinePath(string path, string sessionFolder, string sessionId, int index)
    {
        if (!CleanupScanner.IsSafeSpecificPath(path)) throw new CleanupSafetyException("Safety check rejected this path.");
        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath) && !Directory.Exists(fullPath)) return "";
        var name = $"{index:D3}-{SafeName(Path.GetFileName(fullPath))}";
        var destinationRoot = sessionFolder;
        if (!string.Equals(Path.GetPathRoot(fullPath), Path.GetPathRoot(sessionFolder), StringComparison.OrdinalIgnoreCase))
        {
            destinationRoot = Path.Combine(Path.GetPathRoot(fullPath)!, ".UninstallMate-Quarantine", sessionId);
            Directory.CreateDirectory(destinationRoot);
            try { File.SetAttributes(Path.Combine(Path.GetPathRoot(fullPath)!, ".UninstallMate-Quarantine"), FileAttributes.Hidden); } catch { }
        }
        var destination = Path.Combine(destinationRoot, name);
        if (Directory.Exists(fullPath)) Directory.Move(fullPath, destination);
        else File.Move(fullPath, destination);
        return destination;
    }

    private static bool DeletePathPermanently(string path)
    {
        if (!CleanupScanner.IsSafeSpecificPath(path)) throw new CleanupSafetyException("Safety check rejected this path.");
        var fullPath = Path.GetFullPath(path);
        if (File.Exists(fullPath))
        {
            try
            {
                File.SetAttributes(fullPath, FileAttributes.Normal);
                File.Delete(fullPath);
                return true;
            }
            catch (IOException)
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    ScheduleRebootDeletion(fullPath);
                    return false;
                }
                throw;
            }
        }
        else if (Directory.Exists(fullPath))
        {
            ClearReadOnlyAttributes(fullPath);
            try
            {
                Directory.Delete(fullPath, recursive: true);
                return true;
            }
            catch (IOException)
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    ScheduleRebootDeletion(fullPath);
                    return false;
                }
                throw;
            }
        }
        return true;
    }

    private static void ScheduleRebootDeletion(string fullPath)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;

        if (File.Exists(fullPath))
        {
            if (!MoveFileEx(fullPath, null, MoveFileFlags.DelayUntilReboot))
            {
                var error = Marshal.GetLastWin32Error();
                throw new System.ComponentModel.Win32Exception(error, $"Could not schedule file '{fullPath}' for reboot deletion (Error {error}).");
            }
        }
        else if (Directory.Exists(fullPath))
        {
            var files = Directory.EnumerateFiles(fullPath, "*", new EnumerationOptions
            {
                RecurseSubdirectories = true,
                IgnoreInaccessible = true,
                AttributesToSkip = FileAttributes.ReparsePoint
            }).ToList();

            foreach (var file in files)
            {
                if (!MoveFileEx(file, null, MoveFileFlags.DelayUntilReboot))
                {
                    var error = Marshal.GetLastWin32Error();
                    throw new System.ComponentModel.Win32Exception(error, $"Could not schedule file '{file}' for reboot deletion (Error {error}).");
                }
            }

            var dirs = Directory.EnumerateDirectories(fullPath, "*", new EnumerationOptions
            {
                RecurseSubdirectories = true,
                IgnoreInaccessible = true,
                AttributesToSkip = FileAttributes.ReparsePoint
            }).OrderByDescending(d => d.Length).ToList();

            foreach (var dir in dirs)
            {
                MoveFileEx(dir, null, MoveFileFlags.DelayUntilReboot);
            }

            if (!MoveFileEx(fullPath, null, MoveFileFlags.DelayUntilReboot))
            {
                var error = Marshal.GetLastWin32Error();
                throw new System.ComponentModel.Win32Exception(error, $"Could not schedule directory '{fullPath}' for reboot deletion (Error {error}).");
            }
        }
    }

    private static void ClearReadOnlyAttributes(string path)
    {
        foreach (var file in Directory.EnumerateFiles(path, "*", new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.ReparsePoint
        }))
        {
            try { File.SetAttributes(file, FileAttributes.Normal); } catch { }
        }
    }

    private static async Task<string> ExportRegistryKeyAsync(
        string path, string viewName, string sessionFolder, CancellationToken token)
    {
        if (viewName == "Both")
        {
            var folder = Path.Combine(sessionFolder, $"registry-{Guid.NewGuid():N}");
            Directory.CreateDirectory(folder);
            await ExportRegistryViewAsync(path, "64", Path.Combine(folder, "64.reg"), token);
            await ExportRegistryViewAsync(path, "32", Path.Combine(folder, "32.reg"), token);
            return folder;
        }
        var backup = Path.Combine(sessionFolder, $"registry-{Guid.NewGuid():N}.reg");
        await ExportRegistryViewAsync(path, viewName, backup, token);
        return backup;
    }

    private static async Task ExportRegistryViewAsync(
        string path, string viewName, string backup, CancellationToken token)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;
        var arguments = new List<string> { "export", path, backup, "/y" };
        if (viewName is "32" or "64") arguments.Add($"/reg:{viewName}");
        await RunToolAsync("reg.exe", arguments, token);
    }

    private static void DeleteRegistryKey(string path, string viewName)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;
        if (viewName == "Both")
        {
            DeleteRegistryKey(path, "64");
            DeleteRegistryKey(path, "32");
            return;
        }
        var (hiveName, subKey) = CleanupScanner.SplitRegistryPath(path);
        using var hive = CleanupScanner.OpenHive(hiveName, viewName);
        hive.DeleteSubKeyTree(subKey, throwOnMissingSubKey: false);
    }

    private static void DeleteRegistryValue(string path, string viewName, string valueName)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;
        if (string.IsNullOrEmpty(valueName)) throw new InvalidOperationException("Registry value name is missing.");
        if (viewName == "Both")
        {
            DeleteRegistryValue(path, "64", valueName);
            DeleteRegistryValue(path, "32", valueName);
            return;
        }
        var (hiveName, subKey) = CleanupScanner.SplitRegistryPath(path);
        using var hive = CleanupScanner.OpenHive(hiveName, viewName);
        using var key = hive.OpenSubKey(subKey, writable: true);
        key?.DeleteValue(valueName, throwOnMissingValue: false);
    }

    private static (int Index, string Prev, string Next) GetEnvironmentPathSegmentNeighbors(string path, string viewName, string valueName, string evidencePath)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return (0, "", "");
        try
        {
            var (hiveName, subKey) = CleanupScanner.SplitRegistryPath(path);
            using var hive = CleanupScanner.OpenHive(hiveName, viewName);
            using var key = hive.OpenSubKey(subKey);
            var current = Convert.ToString(key?.GetValue(valueName, "", RegistryValueOptions.DoNotExpandEnvironmentNames)) ?? "";
            var segments = current.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            for (var i = 0; i < segments.Length; i++)
            {
                if (CleanupScanner.ReferencesEvidencePath(segments[i], [evidencePath]))
                {
                    var prev = i > 0 ? segments[i - 1] : "";
                    var next = i + 1 < segments.Length ? segments[i + 1] : "";
                    return (i, prev, next);
                }
            }
            return (0, "", "");
        }
        catch { return (0, "", ""); }
    }

    private static void RemoveEnvironmentPathEntry(
        string path, string viewName, string valueName, string evidencePath)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;
        if (string.IsNullOrEmpty(valueName) || string.IsNullOrWhiteSpace(evidencePath))
            throw new InvalidOperationException("Environment-entry cleanup metadata is missing.");
        var (hiveName, subKey) = CleanupScanner.SplitRegistryPath(path);
        using var hive = CleanupScanner.OpenHive(hiveName, viewName);
        using var key = hive.OpenSubKey(subKey, writable: true);
        if (key is null) return;
        var current = Convert.ToString(key.GetValue(valueName, "", RegistryValueOptions.DoNotExpandEnvironmentNames)) ?? "";
        var updated = RemoveEnvironmentPathSegments(current, evidencePath);
        if (updated.Equals(current, StringComparison.Ordinal)) return;
        if (updated.Length == 0) key.DeleteValue(valueName, throwOnMissingValue: false);
        else key.SetValue(valueName, updated, key.GetValueKind(valueName));
    }

    public static string RemoveEnvironmentPathSegments(string current, string evidencePath) =>
        string.Join(';', current.Split(';', StringSplitOptions.TrimEntries)
            .Where(segment => segment.Length > 0 && !CleanupScanner.ReferencesEvidencePath(segment, [evidencePath])));

    private static async Task<string> ExportScheduledTaskAsync(
        string taskPath, string sessionFolder, CancellationToken token)
    {
        var backup = Path.Combine(sessionFolder, $"scheduled-task-{Guid.NewGuid():N}.xml");
        var start = CreateToolStart("schtasks.exe", ["/query", "/tn", taskPath, "/xml"]);
        start.RedirectStandardOutput = true;
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start scheduled-task export.");
        var xmlTask = process.StandardOutput.ReadToEndAsync(token);
        await process.WaitForExitAsync(token);
        if (process.ExitCode != 0) throw new InvalidOperationException("Scheduled-task backup failed; the task was not deleted.");
        await File.WriteAllTextAsync(backup, await xmlTask, token);
        return backup;
    }

    public static async Task RunToolAsync(
        string executable, IEnumerable<string> arguments, CancellationToken token, bool acceptFailure = false)
    {
        using var process = Process.Start(CreateToolStart(executable, arguments))
            ?? throw new InvalidOperationException($"Could not start {executable}.");
        await process.WaitForExitAsync(token);
        if (!acceptFailure && process.ExitCode != 0)
            throw new InvalidOperationException($"{executable} failed with exit code {process.ExitCode}.");
    }

    private static ProcessStartInfo CreateToolStart(string executable, IEnumerable<string> arguments)
    {
        var start = new ProcessStartInfo { FileName = executable, UseShellExecute = false, CreateNoWindow = true };
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        return start;
    }

    private static void BroadcastEnvironmentChange()
    {
        try
        {
            SendMessageTimeout(
                new IntPtr(0xFFFF), // HWND_BROADCAST
                0x001A,             // WM_SETTINGCHANGE
                IntPtr.Zero,
                "Environment",
                2,                  // SMTO_ABORTIFHUNG
                5000,
                out _);
        }
        catch { }
    }

    [Flags]
    private enum MoveFileFlags : uint
    {
        DelayUntilReboot = 0x4
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool MoveFileEx(string? lpExistingFileName, string? lpNewFileName, MoveFileFlags dwFlags);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern IntPtr SendMessageTimeout(
        IntPtr hWnd,
        uint Msg,
        IntPtr wParam,
        string lParam,
        uint fuFlags,
        uint uTimeout,
        out IntPtr lpdwResult);

    private static string DisplayTarget(CleanupCandidate item) =>
        item.Auxiliary.Length == 0 ? item.Target : $"{item.Target} :: {item.Auxiliary}";

    private static string SafeName(string value)
    {
        var safe = string.Concat(value.Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c));
        return string.IsNullOrWhiteSpace(safe) ? "application" : safe[..Math.Min(60, safe.Length)];
    }
}
