using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using UninstallMate.Models;

namespace UninstallMate.Services;

public static class QuarantineService
{
    public static string DefaultQuarantineRoot => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "UninstallMate",
        "Quarantine");

    public static string? FindLatestRestorableSession(string? quarantineRoot = null)
    {
        var root = quarantineRoot ?? DefaultQuarantineRoot;
        if (!Directory.Exists(root)) return null;
        try
        {
            return Directory.EnumerateDirectories(root)
                .Select(path => new { Path = path, Report = Path.Combine(path, "cleanup-report.json") })
                .Where(x => File.Exists(x.Report) && HasRestorablePayload(x.Report))
                .OrderByDescending(x => File.GetLastWriteTimeUtc(x.Report))
                .Select(x => x.Path)
                .FirstOrDefault();
        }
        catch { return null; }
    }

    private static bool HasRestorablePayload(string reportPath)
    {
        try
        {
            var report = JsonSerializer.Deserialize<CleanupReport>(File.ReadAllText(reportPath));
            return report?.Items.Any(x => x.Success
                && ((x.RecoverySource.Length > 0 && (File.Exists(x.RecoverySource) || Directory.Exists(x.RecoverySource)))
                    || !string.IsNullOrEmpty(x.StructuredPayloadJson))) == true;
        }
        catch { return false; }
    }

    public static async Task<(int Restored, int Failed)> RestoreAsync(string sessionFolder, CancellationToken token)
    {
        var reportPath = Path.Combine(sessionFolder, "cleanup-report.json");
        if (!File.Exists(reportPath)) throw new FileNotFoundException("The cleanup report is missing.", reportPath);
        var report = JsonSerializer.Deserialize<CleanupReport>(await File.ReadAllTextAsync(reportPath, token))
            ?? throw new InvalidDataException("The cleanup report is invalid.");

        var restored = 0;
        var failed = 0;
        var details = new List<string>();

        foreach (var item in report.Items.Where(x => x.Success).Reverse())
        {
            token.ThrowIfCancellationRequested();
            try
            {
                switch (item.Kind)
                {
                    case CleanupKind.RegistryValue:
                    case CleanupKind.FirewallRule:
                        await RestoreRegistryValueAsync(item, token);
                        break;

                    case CleanupKind.EnvironmentEntry:
                        await RestoreEnvironmentEntryAsync(item, token);
                        break;

                    case CleanupKind.WindowsService:
                        await RestoreServiceAsync(item, token);
                        break;

                    case CleanupKind.RegistryKey:
                        if (item.RecoverySource.Length > 0)
                            await ImportRegistryKeyAsync(item.RecoverySource, item.RegistryViewName, token);
                        break;

                    case CleanupKind.ScheduledTask:
                        if (item.RecoverySource.Length > 0)
                            await ImportScheduledTaskAsync(item.Target, item.RecoverySource, token);
                        break;

                    case CleanupKind.File:
                    case CleanupKind.Directory:
                        if (item.RecoverySource.Length > 0)
                        {
                            if (File.Exists(item.Target) || Directory.Exists(item.Target))
                                throw new IOException("The original location is no longer empty.");
                            var parent = Path.GetDirectoryName(item.Target);
                            if (!string.IsNullOrWhiteSpace(parent)) Directory.CreateDirectory(parent);
                            if (Directory.Exists(item.RecoverySource)) Directory.Move(item.RecoverySource, item.Target);
                            else if (File.Exists(item.RecoverySource)) File.Move(item.RecoverySource, item.Target);
                            else throw new FileNotFoundException("The quarantined item is missing.");
                        }
                        break;
                }

                restored++;
                details.Add($"RESTORED: {item.Target} :: {item.Auxiliary}");
            }
            catch (Exception ex)
            {
                failed++;
                details.Add($"FAILED: {item.Target} — {ex.Message}");
            }
        }

        await File.WriteAllLinesAsync(Path.Combine(sessionFolder, $"restore-{DateTime.Now:yyyyMMdd-HHmmss}.log"), details, token);
        return (restored, failed);
    }

    private static async Task RestoreRegistryValueAsync(CleanupReportItem item, CancellationToken token)
    {
        string? json = null;
        if (!string.IsNullOrEmpty(item.StructuredPayloadJson))
        {
            json = item.StructuredPayloadJson;
        }
        else if (item.RecoverySource.Length > 0 && File.Exists(item.RecoverySource) && item.RecoverySource.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
        {
            json = await File.ReadAllTextAsync(item.RecoverySource, token);
        }

        if (!string.IsNullOrEmpty(json))
        {
            // Try bundle first
            try
            {
                var bundle = JsonSerializer.Deserialize<RegistryValueBackupBundle>(json);
                if (bundle is not null && bundle.Values.Count > 0)
                {
                    foreach (var val in bundle.Values)
                    {
                        RestoreExactValue(val);
                    }
                    return;
                }
            }
            catch { }

            // Try single value
            try
            {
                var backupData = JsonSerializer.Deserialize<RegistryValueBackupData>(json);
                if (backupData is not null)
                {
                    RestoreExactValue(backupData);
                    return;
                }
            }
            catch { }
        }

        // Fallback for legacy .reg exports
        if (item.RecoverySource.Length > 0 && File.Exists(item.RecoverySource) && item.RecoverySource.EndsWith(".reg", StringComparison.OrdinalIgnoreCase))
        {
            await ImportRegistryKeyAsync(item.RecoverySource, item.RegistryViewName, token);
        }
    }

    public static void RestoreRegistryValueBundle(RegistryValueBackupBundle bundle)
    {
        foreach (var val in bundle.Values)
        {
            RestoreExactValue(val);
        }
    }

    public static void RestoreExactValue(RegistryValueBackupData data)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;

        var hive = data.Hive.Equals("CurrentUser", StringComparison.OrdinalIgnoreCase) || data.Hive.Equals("HKEY_CURRENT_USER", StringComparison.OrdinalIgnoreCase)
            ? RegistryHive.CurrentUser : RegistryHive.LocalMachine;

        var view = data.View == "32" ? RegistryView.Registry32 : RegistryView.Registry64;

        using var baseKey = RegistryKey.OpenBaseKey(hive, view);
        using var key = baseKey.CreateSubKey(data.SubKey);
        if (key is null) throw new InvalidOperationException($"Could not open or create subkey: {data.SubKey}");

        var kind = Enum.TryParse<RegistryValueKind>(data.ValueKind, out var parsedKind) ? parsedKind : RegistryValueKind.String;

        switch (kind)
        {
            case RegistryValueKind.Binary:
                var bytes = data.BinaryValue ?? (string.IsNullOrEmpty(data.RawValueBase64) ? [] : Convert.FromBase64String(data.RawValueBase64));
                key.SetValue(data.ValueName, bytes, RegistryValueKind.Binary);
                break;
            case RegistryValueKind.DWord:
                var dword = data.DWordValue ?? (int.TryParse(data.StringValue, out var dw) ? dw : 0);
                key.SetValue(data.ValueName, dword, RegistryValueKind.DWord);
                break;
            case RegistryValueKind.QWord:
                var qword = data.QWordValue ?? (long.TryParse(data.StringValue, out var qw) ? qw : 0L);
                key.SetValue(data.ValueName, qword, RegistryValueKind.QWord);
                break;
            case RegistryValueKind.MultiString:
                var multi = data.MultiStringValue ?? data.StringValue?.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries) ?? [];
                key.SetValue(data.ValueName, multi, RegistryValueKind.MultiString);
                break;
            case RegistryValueKind.ExpandString:
                key.SetValue(data.ValueName, data.StringValue ?? "", RegistryValueKind.ExpandString);
                break;
            default:
                key.SetValue(data.ValueName, data.StringValue ?? "", RegistryValueKind.String);
                break;
        }
    }

    private static async Task RestoreEnvironmentEntryAsync(CleanupReportItem item, CancellationToken token)
    {
        PathSegmentBackupData? pathData = null;
        if (!string.IsNullOrEmpty(item.StructuredPayloadJson))
        {
            pathData = JsonSerializer.Deserialize<PathSegmentBackupData>(item.StructuredPayloadJson);
        }
        else if (item.RecoverySource.Length > 0 && File.Exists(item.RecoverySource))
        {
            pathData = JsonSerializer.Deserialize<PathSegmentBackupData>(await File.ReadAllTextAsync(item.RecoverySource, token));
        }

        if (pathData is not null)
        {
            MergeRestorePathSegment(pathData);
        }
    }

    public static void MergeRestorePathSegment(PathSegmentBackupData data)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;

        var hive = data.Hive.Equals("CurrentUser", StringComparison.OrdinalIgnoreCase) || data.Hive.Equals("HKEY_CURRENT_USER", StringComparison.OrdinalIgnoreCase)
            ? RegistryHive.CurrentUser : RegistryHive.LocalMachine;

        var view = data.View == "32" ? RegistryView.Registry32 : RegistryView.Registry64;

        using var baseKey = RegistryKey.OpenBaseKey(hive, view);
        using var key = baseKey.OpenSubKey(data.SubKey, writable: true);
        if (key is null) return;

        var current = Convert.ToString(key.GetValue(data.ValueName, "", RegistryValueOptions.DoNotExpandEnvironmentNames)) ?? "";
        var merged = MergePathSegment(current, data.RemovedSegment, data.OriginalIndex, data.PreviousSegment, data.NextSegment);
        if (!merged.Equals(current, StringComparison.Ordinal))
        {
            key.SetValue(data.ValueName, merged, key.GetValueKind(data.ValueName));
        }
    }

    public static string MergePathSegment(string currentPath, string segmentToRestore, int originalIndex = -1, string previousSegment = "", string nextSegment = "")
    {
        if (string.IsNullOrWhiteSpace(segmentToRestore)) return currentPath;
        var segments = currentPath.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).ToList();
        if (segments.Any(s => s.Equals(segmentToRestore, StringComparison.OrdinalIgnoreCase)))
            return currentPath;

        // 1. Previous anchor exists -> insert after it
        if (!string.IsNullOrWhiteSpace(previousSegment))
        {
            var prevIdx = segments.FindIndex(s => s.Equals(previousSegment, StringComparison.OrdinalIgnoreCase));
            if (prevIdx >= 0)
            {
                segments.Insert(prevIdx + 1, segmentToRestore);
                return string.Join(';', segments);
            }
        }

        // 2. Next anchor exists -> insert before it
        if (!string.IsNullOrWhiteSpace(nextSegment))
        {
            var nextIdx = segments.FindIndex(s => s.Equals(nextSegment, StringComparison.OrdinalIgnoreCase));
            if (nextIdx >= 0)
            {
                segments.Insert(nextIdx, segmentToRestore);
                return string.Join(';', segments);
            }
        }

        // 3. Bounded original index fallback
        if (originalIndex >= 0 && originalIndex <= segments.Count)
        {
            segments.Insert(originalIndex, segmentToRestore);
        }
        else
        {
            segments.Add(segmentToRestore);
        }
        return string.Join(';', segments);
    }

    private static async Task RestoreServiceAsync(CleanupReportItem item, CancellationToken token)
    {
        ServiceBackupData? serviceData = null;
        if (!string.IsNullOrEmpty(item.StructuredPayloadJson))
        {
            serviceData = JsonSerializer.Deserialize<ServiceBackupData>(item.StructuredPayloadJson);
        }
        else if (item.RecoverySource.Length > 0 && File.Exists(item.RecoverySource))
        {
            serviceData = JsonSerializer.Deserialize<ServiceBackupData>(await File.ReadAllTextAsync(item.RecoverySource, token));
        }

        if (serviceData is not null && RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            using var hive = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var serviceKey = hive.CreateSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceData.ServiceName}");
            if (serviceKey is not null)
            {
                serviceKey.SetValue("DisplayName", serviceData.DisplayName, RegistryValueKind.String);
                serviceKey.SetValue("ImagePath", serviceData.ImagePath, RegistryValueKind.ExpandString);
                serviceKey.SetValue("Type", serviceData.ServiceType, RegistryValueKind.DWord);
                serviceKey.SetValue("Start", serviceData.StartType, RegistryValueKind.DWord);
                serviceKey.SetValue("ErrorControl", serviceData.ErrorControl, RegistryValueKind.DWord);

                if (!string.IsNullOrEmpty(serviceData.ServiceAccount))
                    serviceKey.SetValue("ObjectName", serviceData.ServiceAccount, RegistryValueKind.String);

                if (serviceData.Dependencies.Length > 0)
                    serviceKey.SetValue("DependOnService", serviceData.Dependencies, RegistryValueKind.MultiString);

                if (serviceData.DelayedAutoStart)
                    serviceKey.SetValue("DelayedAutoStart", 1, RegistryValueKind.DWord);

                if (!string.IsNullOrEmpty(serviceData.Description))
                    serviceKey.SetValue("Description", serviceData.Description, RegistryValueKind.String);

                if (!string.IsNullOrEmpty(serviceData.ServiceDll) || serviceData.Parameters.Count > 0)
                {
                    using var paramsKey = serviceKey.CreateSubKey("Parameters");
                    if (!string.IsNullOrEmpty(serviceData.ServiceDll))
                        paramsKey.SetValue("ServiceDll", serviceData.ServiceDll, RegistryValueKind.ExpandString);

                    foreach (var (k, v) in serviceData.Parameters)
                    {
                        paramsKey.SetValue(k, v, RegistryValueKind.String);
                    }
                }
            }
        }
    }

    private static async Task ImportRegistryKeyAsync(string backup, string viewName, CancellationToken token)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;

        if (viewName == "Both")
        {
            if (!Directory.Exists(backup)) throw new DirectoryNotFoundException("Registry backup folder is missing.");
            await ImportRegistryKeyAsync(Path.Combine(backup, "64.reg"), "64", token);
            await ImportRegistryKeyAsync(Path.Combine(backup, "32.reg"), "32", token);
            return;
        }
        if (!File.Exists(backup)) throw new FileNotFoundException("Registry backup is missing.", backup);
        var start = new ProcessStartInfo { FileName = "reg.exe", UseShellExecute = false, CreateNoWindow = true };
        start.ArgumentList.Add("import");
        start.ArgumentList.Add(backup);
        if (viewName is "32" or "64") start.ArgumentList.Add($"/reg:{viewName}");
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start registry restore.");
        await process.WaitForExitAsync(token);
        if (process.ExitCode != 0) throw new InvalidOperationException($"Registry import failed with code {process.ExitCode}.");
    }

    private static async Task ImportScheduledTaskAsync(string taskPath, string backup, CancellationToken token)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;
        if (!File.Exists(backup)) throw new FileNotFoundException("Scheduled-task backup is missing.", backup);
        var start = new ProcessStartInfo { FileName = "schtasks.exe", UseShellExecute = false, CreateNoWindow = true };
        start.ArgumentList.Add("/create");
        start.ArgumentList.Add("/tn");
        start.ArgumentList.Add(taskPath);
        start.ArgumentList.Add("/xml");
        start.ArgumentList.Add(backup);
        start.ArgumentList.Add("/f");
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start scheduled-task restore.");
        await process.WaitForExitAsync(token);
        if (process.ExitCode != 0) throw new InvalidOperationException($"Scheduled-task restore failed with code {process.ExitCode}.");
    }
}
