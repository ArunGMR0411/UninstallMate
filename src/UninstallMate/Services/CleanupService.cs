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
            ApplicationName = app.DisplayName
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
                var (detail, recoverySource, payloadJson) = await ExecuteItemAsync(
                    item, preserveBackups, sessionFolder, sessionId, index, token);

                if (item.Kind == CleanupKind.EnvironmentEntry)
                    environmentModified = true;

                report.Items.Add(new(
                    item.Target, item.Kind, true, detail, recoverySource,
                    item.RegistryViewName, item.Auxiliary, item.EvidencePath,
                    item.Risk, item.Confidence, item.SourceProvider,
                    item.RegistryValueKindName, item.RegistryRawValueBase64,
                    payloadJson, VerificationStatus: "Deleted"));
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
        var reportPath = Path.Combine(sessionFolder, "cleanup-report.json");
        await File.WriteAllTextAsync(
            reportPath,
            JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }),
            token);

        return (report, sessionFolder);
    }

    private static async Task<(string Detail, string RecoverySource, string PayloadJson)> ExecuteItemAsync(
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
                if (preserveBackups)
                {
                    var quarantine = QuarantinePath(item.Target, sessionFolder, sessionId, index);
                    return (quarantine.Length == 0 ? "Already absent" : "Moved to quarantine", quarantine, "");
                }
                DeletePathPermanently(item.Target);
                return ("Permanently deleted", "", "");

            case CleanupKind.RegistryKey:
                {
                    var backup = preserveBackups
                        ? await ExportRegistryKeyAsync(item.Target, item.RegistryViewName, sessionFolder, token)
                        : "";
                    DeleteRegistryKey(item.Target, item.RegistryViewName);
                    return (preserveBackups ? "Registry key exported, then removed" : "Registry key permanently deleted", backup, "");
                }

            case CleanupKind.RegistryValue:
            case CleanupKind.FirewallRule:
                {
                    string backupFile = "";
                    string payloadJson = "";
                    if (preserveBackups)
                    {
                        var backupData = CreateRegistryValueBackup(item.Target, item.RegistryViewName, item.Auxiliary);
                        if (backupData is not null)
                        {
                            payloadJson = JsonSerializer.Serialize(backupData);
                            backupFile = Path.Combine(sessionFolder, $"regval-{index:D3}-{Guid.NewGuid():N}.json");
                            await File.WriteAllTextAsync(backupFile, payloadJson, token);
                        }
                    }

                    DeleteRegistryValue(item.Target, item.RegistryViewName, item.Auxiliary);
                    return (preserveBackups ? "Registry value saved to backup, then removed" : "Registry value permanently deleted", backupFile, payloadJson);
                }

            case CleanupKind.EnvironmentEntry:
                {
                    string backupFile = "";
                    string payloadJson = "";
                    if (preserveBackups)
                    {
                        var (hive, subKey) = CleanupScanner.SplitRegistryPath(item.Target);
                        var pathBackup = new PathSegmentBackupData
                        {
                            Hive = hive.ToString(),
                            SubKey = subKey,
                            View = item.RegistryViewName,
                            ValueName = item.Auxiliary,
                            RemovedSegment = item.EvidencePath
                        };
                        payloadJson = JsonSerializer.Serialize(pathBackup);
                        backupFile = Path.Combine(sessionFolder, $"env-{index:D3}-{Guid.NewGuid():N}.json");
                        await File.WriteAllTextAsync(backupFile, payloadJson, token);
                    }

                    RemoveEnvironmentPathEntry(item.Target, item.RegistryViewName, item.Auxiliary, item.EvidencePath);
                    return (preserveBackups ? "PATH segment saved to backup, then removed" : "App path permanently removed from environment value", backupFile, payloadJson);
                }

            case CleanupKind.WindowsService:
                {
                    string backupFile = "";
                    string payloadJson = "";
                    if (preserveBackups)
                    {
                        var serviceBackup = CaptureServiceDefinition(item.Auxiliary);
                        if (serviceBackup is not null)
                        {
                            payloadJson = JsonSerializer.Serialize(serviceBackup);
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
                    return (preserveBackups ? "Service definition backed up, then service deleted" : "Service permanently deleted", backupFile, payloadJson);
                }

            case CleanupKind.ScheduledTask:
                {
                    var backup = preserveBackups && RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                        ? await ExportScheduledTaskAsync(item.Target, sessionFolder, token)
                        : "";
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        await RunToolAsync("schtasks.exe", ["/delete", "/tn", item.Target, "/f"], token);
                    }
                    return (preserveBackups ? "Task definition exported, then task deleted" : "Scheduled task permanently deleted", backup, "");
                }

            default:
                throw new NotSupportedException($"Unsupported cleanup kind: {item.Kind}");
        }
    }

    private static RegistryValueBackupData? CreateRegistryValueBackup(string path, string viewName, string valueName)
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
            var rawBytes = rawObj as byte[] ?? (rawObj is string s ? System.Text.Encoding.Unicode.GetBytes(s) : []);
            var rawBase64 = Convert.ToBase64String(rawBytes);

            return new RegistryValueBackupData
            {
                Hive = hiveName.ToString(),
                SubKey = subKey,
                View = viewName,
                ValueName = valueName,
                ValueKind = kind.ToString(),
                RawValueBase64 = rawBase64,
                StringValue = rawObj.ToString() ?? ""
            };
        }
        catch { return null; }
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

            var serviceDll = "";
            using (var paramsKey = serviceKey.OpenSubKey("Parameters"))
            {
                if (paramsKey is not null)
                    serviceDll = Convert.ToString(paramsKey.GetValue("ServiceDll", "", RegistryValueOptions.DoNotExpandEnvironmentNames)) ?? "";
            }

            return new ServiceBackupData
            {
                ServiceName = serviceName,
                DisplayName = displayName,
                ImagePath = imagePath,
                ServiceDll = serviceDll,
                ServiceType = serviceType,
                StartType = startType,
                Description = description
            };
        }
        catch { return null; }
    }

    private static string QuarantinePath(string path, string sessionFolder, string sessionId, int index)
    {
        if (!CleanupScanner.IsSafeSpecificPath(path)) throw new InvalidOperationException("Safety check rejected this path.");
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

    private static void DeletePathPermanently(string path)
    {
        if (!CleanupScanner.IsSafeSpecificPath(path)) throw new InvalidOperationException("Safety check rejected this path.");
        var fullPath = Path.GetFullPath(path);
        if (File.Exists(fullPath))
        {
            File.SetAttributes(fullPath, FileAttributes.Normal);
            File.Delete(fullPath);
        }
        else if (Directory.Exists(fullPath))
        {
            ClearReadOnlyAttributes(fullPath);
            Directory.Delete(fullPath, recursive: true);
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

    private static async Task RunToolAsync(
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
