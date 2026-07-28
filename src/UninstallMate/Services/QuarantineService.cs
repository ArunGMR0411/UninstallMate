using System.Diagnostics;
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
                && x.RecoverySource.Length > 0
                && (File.Exists(x.RecoverySource) || Directory.Exists(x.RecoverySource))) == true;
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

        foreach (var item in report.Items.Where(x => x.Success && x.RecoverySource.Length > 0).Reverse())
        {
            token.ThrowIfCancellationRequested();
            try
            {
                if (item.Kind is CleanupKind.RegistryKey or CleanupKind.RegistryValue or CleanupKind.EnvironmentEntry or CleanupKind.WindowsService)
                {
                    await ImportRegistryAsync(item.RecoverySource, item.RegistryViewName, token);
                }
                else if (item.Kind == CleanupKind.ScheduledTask)
                {
                    await ImportScheduledTaskAsync(item.Target, item.RecoverySource, token);
                }
                else
                {
                    if (File.Exists(item.Target) || Directory.Exists(item.Target))
                        throw new IOException("The original location is no longer empty.");
                    var parent = Path.GetDirectoryName(item.Target);
                    if (!string.IsNullOrWhiteSpace(parent)) Directory.CreateDirectory(parent);
                    if (Directory.Exists(item.RecoverySource)) Directory.Move(item.RecoverySource, item.Target);
                    else if (File.Exists(item.RecoverySource)) File.Move(item.RecoverySource, item.Target);
                    else throw new FileNotFoundException("The quarantined item is missing.");
                }
                restored++;
                details.Add($"RESTORED: {item.Target}");
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

    private static async Task ImportRegistryAsync(string backup, string viewName, CancellationToken token)
    {
        if (viewName == "Both")
        {
            if (!Directory.Exists(backup)) throw new DirectoryNotFoundException("Registry backup folder is missing.");
            await ImportRegistryAsync(Path.Combine(backup, "64.reg"), "64", token);
            await ImportRegistryAsync(Path.Combine(backup, "32.reg"), "32", token);
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
