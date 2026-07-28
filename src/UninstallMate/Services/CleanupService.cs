using Microsoft.Win32;
using System.Diagnostics;
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
        var report = new CleanupReport { ApplicationName = app.DisplayName };
        var index = 0;
        foreach (var item in selected)
        {
            token.ThrowIfCancellationRequested();
            progress?.Report($"Cleaning {++index}: {DisplayTarget(item)}");
            try
            {
                var (detail, recoverySource) = await ExecuteItemAsync(
                    item, preserveBackups, sessionFolder, sessionId, index, token);
                report.Items.Add(new(
                    item.Target, item.Kind, true, detail, recoverySource,
                    item.RegistryViewName, item.Auxiliary, item.EvidencePath));
            }
            catch (Exception ex)
            {
                report.Items.Add(new(
                    item.Target, item.Kind, false, ex.Message,
                    RegistryViewName: item.RegistryViewName, Auxiliary: item.Auxiliary,
                    EvidencePath: item.EvidencePath));
            }
        }

        report.FinishedAt = DateTimeOffset.Now;
        var reportPath = Path.Combine(sessionFolder, "cleanup-report.json");
        await File.WriteAllTextAsync(
            reportPath,
            JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }),
            token);
        return (report, sessionFolder);
    }

    private static async Task<(string Detail, string RecoverySource)> ExecuteItemAsync(
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
                    return (quarantine.Length == 0 ? "Already absent" : "Moved to quarantine", quarantine);
                }
                DeletePathPermanently(item.Target);
                return ("Permanently deleted", "");

            case CleanupKind.RegistryKey:
                {
                    var backup = preserveBackups
                        ? await ExportRegistryAsync(item.Target, item.RegistryViewName, sessionFolder, token)
                        : "";
                    DeleteRegistryKey(item.Target, item.RegistryViewName);
                    return (preserveBackups ? "Registry key exported, then removed" : "Registry key permanently deleted", backup);
                }

            case CleanupKind.RegistryValue:
                {
                    var backup = preserveBackups
                        ? await ExportRegistryAsync(item.Target, item.RegistryViewName, sessionFolder, token)
                        : "";
                    DeleteRegistryValue(item.Target, item.RegistryViewName, item.Auxiliary);
                    return (preserveBackups ? "Parent key exported, then value removed" : "Registry value permanently deleted", backup);
                }

            case CleanupKind.EnvironmentEntry:
                {
                    var backup = preserveBackups
                        ? await ExportRegistryAsync(item.Target, item.RegistryViewName, sessionFolder, token)
                        : "";
                    RemoveEnvironmentPathEntry(item.Target, item.RegistryViewName, item.Auxiliary, item.EvidencePath);
                    return (preserveBackups ? "Environment key exported, then app path removed" : "App path permanently removed from environment value", backup);
                }

            case CleanupKind.WindowsService:
                {
                    var backup = preserveBackups
                        ? await ExportRegistryAsync(item.Target, item.RegistryViewName, sessionFolder, token)
                        : "";
                    await RunToolAsync("sc.exe", ["stop", item.Auxiliary], token, acceptFailure: true);
                    await RunToolAsync("sc.exe", ["delete", item.Auxiliary], token);
                    return (preserveBackups ? "Service definition exported, then service deleted" : "Service permanently deleted", backup);
                }

            case CleanupKind.ScheduledTask:
                {
                    var backup = preserveBackups
                        ? await ExportScheduledTaskAsync(item.Target, sessionFolder, token)
                        : "";
                    await RunToolAsync("schtasks.exe", ["/delete", "/tn", item.Target, "/f"], token);
                    return (preserveBackups ? "Task definition exported, then task deleted" : "Scheduled task permanently deleted", backup);
                }

            default:
                throw new NotSupportedException($"Unsupported cleanup kind: {item.Kind}");
        }
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

    private static async Task<string> ExportRegistryAsync(
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
        var arguments = new List<string> { "export", path, backup, "/y" };
        if (viewName is "32" or "64") arguments.Add($"/reg:{viewName}");
        await RunToolAsync("reg.exe", arguments, token);
    }

    private static void DeleteRegistryKey(string path, string viewName)
    {
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

    internal static string RemoveEnvironmentPathSegments(string current, string evidencePath) =>
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

    private static string DisplayTarget(CleanupCandidate item) =>
        item.Auxiliary.Length == 0 ? item.Target : $"{item.Target} :: {item.Auxiliary}";

    private static string SafeName(string value)
    {
        var safe = string.Concat(value.Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c));
        return string.IsNullOrWhiteSpace(safe) ? "application" : safe[..Math.Min(60, safe.Length)];
    }
}
