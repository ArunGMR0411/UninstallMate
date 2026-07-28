using System.Diagnostics;

namespace UninstallMate.Services;

public static class RestorePointService
{
    public static async Task<string> TryCreateAsync(string appName, CancellationToken token)
    {
        var description = "Before removing " + new string(appName.Where(c => !char.IsControl(c)).Take(60).ToArray());
        var start = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardError = true
        };
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-NonInteractive");
        start.ArgumentList.Add("-Command");
        start.ArgumentList.Add("Checkpoint-Computer -Description $args[0] -RestorePointType MODIFY_SETTINGS -ErrorAction Stop");
        start.ArgumentList.Add(description);
        try
        {
            using var process = Process.Start(start);
            if (process is null) return "Restore point could not be started.";
            var errorTask = process.StandardError.ReadToEndAsync(token);
            await process.WaitForExitAsync(token);
            if (process.ExitCode == 0) return "Restore point created.";
            var error = (await errorTask).Trim();
            return "Restore point unavailable" + (error.Length > 0 ? $": {error.Split('\n')[0].Trim()}" : ".");
        }
        catch (Exception ex) { return $"Restore point unavailable: {ex.Message}"; }
    }
}
