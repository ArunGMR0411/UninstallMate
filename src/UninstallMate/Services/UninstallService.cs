using Microsoft.Win32;
using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using UninstallMate.Models;

namespace UninstallMate.Services;

public sealed partial class UninstallService
{
    public async Task<bool?> IsApplicationRegisteredAsync(
        InstalledApplication app,
        CancellationToken token)
    {
        if (app.Kind == ApplicationKind.MicrosoftStore)
        {
            if (string.IsNullOrWhiteSpace(app.PackageFullName)) return null;
            return await IsStorePackageRegisteredAsync(app.PackageFullName, token);
        }
        if (string.IsNullOrWhiteSpace(app.RegistryKeyPath)) return null;
        return IsDesktopRegistrationPresent(app);
    }

    public async Task<OperationResult> UninstallAsync(InstalledApplication app, bool quiet, CancellationToken token)
    {
        if (app.IsProtected)
            return new(false, "Windows marks this application as non-removable.");

        if (app.Kind == ApplicationKind.MicrosoftStore)
            return await RemoveStoreAppAsync(app, token);

        var command = quiet && !string.IsNullOrWhiteSpace(app.QuietUninstallString)
            ? app.QuietUninstallString : app.UninstallString;
        if (string.IsNullOrWhiteSpace(command))
            return new(false, "No registered uninstaller was found. You can use cleanup-only mode.");

        command = NormalizeMsiCommand(command);
        if (!CommandLineParser.TrySplit(command, out var fileName, out var arguments))
            return new(false, "The registered uninstall command is invalid.");

        try
        {
            var start = new ProcessStartInfo
            {
                FileName = Environment.ExpandEnvironmentVariables(fileName),
                Arguments = arguments,
                UseShellExecute = true,
                WorkingDirectory = SafeWorkingDirectory(app.InstallLocation)
            };
            using var process = Process.Start(start);
            if (process is null) return new(false, "Windows could not start the registered uninstaller.");
            await process.WaitForExitAsync(token);

            var initialResult = InterpretDesktopExit(process.ExitCode, registrationStillPresent: true);
            if (initialResult.Success) return initialResult;

            // A surprising number of vendor uninstallers return 1/1603 even after successfully
            // removing their registration. The registry is the authoritative inventory source.
            if (await WaitForDesktopRegistrationRemovalAsync(app, token))
            {
                return new(true,
                    $"The application was removed. Its uninstaller reported code {process.ExitCode}, but Windows confirms the registration is gone.",
                    process.ExitCode);
            }
            return initialResult;
        }
        catch (Exception ex) { return new(false, $"Could not run the uninstaller: {ex.Message}"); }
    }

    private static async Task<OperationResult> RemoveStoreAppAsync(InstalledApplication app, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(app.PackageFullName)) return new(false, "Package identity is missing.");
        try
        {
            var (exitCode, error) = await RunPowerShellAsync(BuildStoreRemovalScript(app.PackageFullName), token);
            if (exitCode == 0) return new(true, "The Store application was removed.");

            // Deployment APIs occasionally report a nonzero result after completing the removal.
            // Re-query package registration before showing a failure to the user.
            for (var attempt = 0; attempt < 4; attempt++)
            {
                var registered = await IsStorePackageRegisteredAsync(app.PackageFullName, token);
                if (registered == false)
                {
                    return new(true,
                        $"The Store application was removed. Package deployment reported code {exitCode}, but Windows confirms the package is gone.",
                        exitCode);
                }
                if (registered is null) break;
                await Task.Delay(500, token);
            }

            var detail = FirstDiagnosticLine(error);
            var message = $"Package removal failed with exit code {exitCode}.";
            if (detail.Length > 0) message += $"\n\nWindows reported: {detail}";
            return new(false, message, exitCode);
        }
        catch (Exception ex) { return new(false, $"Package removal failed: {ex.Message}"); }
    }

    internal static OperationResult InterpretDesktopExit(int exitCode, bool registrationStillPresent)
    {
        if (!registrationStillPresent && exitCode != 0)
            return new(true, $"The application registration was removed despite uninstaller code {exitCode}.", exitCode);
        return exitCode switch
        {
            0 => new(true, "The registered uninstaller completed successfully."),
            1605 => new(true, "Windows Installer reports that the product is already absent.", exitCode),
            1614 => new(true, "Windows Installer reports that the product is already removed.", exitCode),
            1641 or 3010 => new(true, "Uninstall completed; Windows requests a restart.", exitCode),
            _ => new(false, $"The uninstaller exited with code {exitCode}, and the application is still registered.", exitCode)
        };
    }

    private static async Task<bool> WaitForDesktopRegistrationRemovalAsync(
        InstalledApplication app, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(app.RegistryKeyPath)) return false;
        for (var attempt = 0; attempt < 8; attempt++)
        {
            if (!IsDesktopRegistrationPresent(app)) return true;
            await Task.Delay(500, token);
        }
        return !IsDesktopRegistrationPresent(app);
    }

    private static bool IsDesktopRegistrationPresent(InstalledApplication app)
    {
        try
        {
            var view = app.Architecture == "32-bit" ? RegistryView.Registry32
                : app.Architecture == "64-bit" ? RegistryView.Registry64
                : RegistryView.Default;
            var slash = app.RegistryKeyPath.IndexOf('\\');
            if (slash < 0) return true;
            var hiveName = app.RegistryKeyPath[..slash];
            var hive = hiveName.Equals("HKEY_CURRENT_USER", StringComparison.OrdinalIgnoreCase)
                ? RegistryHive.CurrentUser : RegistryHive.LocalMachine;
            using var baseKey = RegistryKey.OpenBaseKey(hive, view);
            using var key = baseKey.OpenSubKey(app.RegistryKeyPath[(slash + 1)..]);
            return key is not null;
        }
        catch { return true; } // A failed verification must never be presented as successful removal.
    }

    private static async Task<bool?> IsStorePackageRegisteredAsync(string packageFullName, CancellationToken token)
    {
        var package = EscapePowerShellLiteral(packageFullName);
        var script = $"$ProgressPreference='SilentlyContinue'; try {{ $found = Get-AppxPackage -ErrorAction Stop | Where-Object {{ $_.PackageFullName -eq '{package}' }}; if ($null -eq $found) {{ exit 0 }} else {{ exit 1 }} }} catch {{ exit 2 }}";
        var (exitCode, _) = await RunPowerShellAsync(script, token);
        return exitCode switch { 0 => false, 1 => true, _ => null };
    }

    internal static string BuildStoreRemovalScript(string packageFullName)
    {
        var package = EscapePowerShellLiteral(packageFullName);
        return "$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Stop'; " +
            $"$package='{package}'; $removeError=''; " +
            "try { Remove-AppxPackage -Package $package -ErrorAction Stop } catch { $removeError=$_.Exception.Message }; " +
            "Start-Sleep -Milliseconds 350; " +
            "$remaining=Get-AppxPackage -ErrorAction SilentlyContinue | Where-Object { $_.PackageFullName -eq $package }; " +
            "if ($null -eq $remaining) { exit 0 }; " +
            "if ($removeError) { [Console]::Error.WriteLine($removeError) } else { [Console]::Error.WriteLine('Windows still reports the package as installed.') }; exit 1";
    }

    internal static async Task<(int ExitCode, string Error)> RunPowerShellAsync(string script, CancellationToken token)
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var start = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-NonInteractive");
        start.ArgumentList.Add("-EncodedCommand");
        start.ArgumentList.Add(encoded);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start Windows PowerShell.");
        var outputTask = process.StandardOutput.ReadToEndAsync(token);
        var errorTask = process.StandardError.ReadToEndAsync(token);
        await process.WaitForExitAsync(token);
        _ = await outputTask;
        return (process.ExitCode, await errorTask);
    }

    private static string EscapePowerShellLiteral(string value) => value.Replace("'", "''", StringComparison.Ordinal);

    private static string FirstDiagnosticLine(string error)
    {
        var line = error.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .Select(x => x.Trim()).FirstOrDefault(x => x.Length > 0) ?? "";
        return line.Length <= 300 ? line : line[..300] + "…";
    }

    internal static string NormalizeMsiCommand(string command)
    {
        if (!MsiExecRegex().IsMatch(command)) return command;
        return InstallSwitchRegex().Replace(command, "$1/X$2", 1);
    }

    private static string SafeWorkingDirectory(string installLocation) =>
        Directory.Exists(installLocation) ? installLocation : Environment.GetFolderPath(Environment.SpecialFolder.System);

    [GeneratedRegex(@"(?i)^\s*""?msiexec(?:\.exe)?""?\s")]
    private static partial Regex MsiExecRegex();
    [GeneratedRegex(@"(?i)(\s)/I(?=\s*\{)(\s*)")]
    private static partial Regex InstallSwitchRegex();
}
