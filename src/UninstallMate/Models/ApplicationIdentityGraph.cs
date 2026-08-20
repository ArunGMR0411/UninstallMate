using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.RegularExpressions;
using UninstallMate.Services;

namespace UninstallMate.Models;

public enum StartupSourceKind
{
    Run,
    RunOnce,
    StartupFolder
}

public sealed record StartupCorrelationKey(
    RegistryHive Hive,
    RegistryView View,
    StartupSourceKind Kind,
    string ValueName);

public sealed record CapturedStartupSource(
    StartupCorrelationKey CorrelationKey,
    string RegistryPath,
    string CommandOrShortcutPath,
    string? ResolvedTarget,
    OwnershipConfidence Confidence,
    IReadOnlyList<string> Evidence);

public sealed record CapturedStartupApproval(
    StartupCorrelationKey CorrelationKey,
    string RegistryPath,
    byte[] RawData);

public sealed record CapturedServiceEntry(
    string ServiceName,
    string DisplayName,
    string ImagePath,
    string ServiceDll,
    bool IsDriver);

public sealed record CapturedTaskEntry(
    string TaskName,
    string TaskPath,
    string Execute,
    string Arguments,
    string WorkingDirectory,
    OwnershipConfidence Confidence,
    IReadOnlyList<string> Evidence);

public sealed record CapturedAppPathEntry(
    string Hive,
    string View,
    string ExeName,
    string TargetPath);

public sealed class ApplicationIdentityCaptureResult
{
    public required ApplicationIdentityGraph Identity { get; init; }
    public required ScanStatus Status { get; init; }
    public IReadOnlyList<ScanDiagnostic> Diagnostics { get; init; } = [];
}

public sealed partial class ApplicationIdentityGraph
{
    private static readonly IShortcutResolver ShortcutResolver = new WindowsShortcutResolver();

    public required InstalledApplication Application { get; init; }
    public string DisplayName => Application.DisplayName;
    public string Publisher => Application.Publisher;
    public string Version => Application.Version;
    public string InstallLocation => Application.InstallLocation;
    public ApplicationKind Kind => Application.Kind;
    public InstallScope Scope => Application.Scope;
    public string RegistryKeyPath => Application.RegistryKeyPath;
    public string PackageFullName => Application.PackageFullName;
    public string PackageFamilyName => Application.PackageFamilyName;

    public List<string> EvidenceRoots { get; init; } = [];
    public List<string> ExecutableNames { get; init; } = [];
    public List<string> ExecutablePaths { get; init; } = [];
    public List<string> CandidateNames { get; init; } = [];
    public List<CapturedStartupSource> CapturedStartupSources { get; init; } = [];
    public List<CapturedStartupApproval> CapturedStartupApprovedEntries { get; init; } = [];
    public List<CapturedServiceEntry> CapturedServices { get; init; } = [];
    public List<CapturedTaskEntry> CapturedTasks { get; init; } = [];
    public List<CapturedAppPathEntry> CapturedAppPaths { get; init; } = [];

    public static async Task<ApplicationIdentityCaptureResult> CaptureWithDiagnosticsAsync(
        InstalledApplication app, CancellationToken token)
    {
        var graph = Create(app);
        var diagnostics = new List<ScanDiagnostic>();
        var status = ScanStatus.Complete;

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            await Task.Run(() =>
            {
                CaptureWindowsPreUninstallState(graph, diagnostics, ref status, token);
            }, token);
        }

        return new ApplicationIdentityCaptureResult
        {
            Identity = graph,
            Status = status,
            Diagnostics = diagnostics
        };
    }

    public static async Task<ApplicationIdentityGraph> CaptureAsync(
        InstalledApplication app, CancellationToken token)
    {
        var result = await CaptureWithDiagnosticsAsync(app, token);
        return result.Identity;
    }

    public static ApplicationIdentityGraph Create(InstalledApplication app)
    {
        var evidenceRoots = CollectEvidenceRoots(app).ToList();
        var candidateNames = CollectCandidateNames(app).ToList();
        var (executables, paths) = CollectDiscoveredExecutables(app);

        return new ApplicationIdentityGraph
        {
            Application = app,
            EvidenceRoots = evidenceRoots,
            CandidateNames = candidateNames,
            ExecutableNames = executables,
            ExecutablePaths = paths
        };
    }

    private static void CaptureWindowsPreUninstallState(
        ApplicationIdentityGraph graph,
        List<ScanDiagnostic> diagnostics,
        ref ScanStatus status,
        CancellationToken token)
    {
        try { CaptureStartupState(graph, diagnostics, ref status, token); }
        catch (Exception ex)
        {
            diagnostics.Add(new ScanDiagnostic("PreUninstallIdentity", $"Startup capture error: {ex.Message}", IsWarning: true));
            if (status == ScanStatus.Complete) status = ScanStatus.CompleteWithWarnings;
        }

        try { CaptureServices(graph, diagnostics, ref status, token); }
        catch (Exception ex)
        {
            diagnostics.Add(new ScanDiagnostic("PreUninstallIdentity", $"Services capture error: {ex.Message}", IsWarning: true));
            if (status == ScanStatus.Complete) status = ScanStatus.CompleteWithWarnings;
        }

        try { CaptureTasks(graph, diagnostics, ref status, token); }
        catch (Exception ex)
        {
            diagnostics.Add(new ScanDiagnostic("PreUninstallIdentity", $"Task capture error: {ex.Message}", IsWarning: true));
            if (status == ScanStatus.Complete) status = ScanStatus.CompleteWithWarnings;
        }

        try { CaptureAppPaths(graph, diagnostics, ref status, token); }
        catch (Exception ex)
        {
            diagnostics.Add(new ScanDiagnostic("PreUninstallIdentity", $"AppPaths capture error: {ex.Message}", IsWarning: true));
            if (status == ScanStatus.Complete) status = ScanStatus.CompleteWithWarnings;
        }
    }

    private static void CaptureStartupState(
        ApplicationIdentityGraph graph,
        List<ScanDiagnostic> diagnostics,
        ref ScanStatus status,
        CancellationToken token)
    {
        var runLocations = new[]
        {
            (RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", StartupSourceKind.Run),
            (RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", StartupSourceKind.RunOnce),
            (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", StartupSourceKind.Run),
            (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", StartupSourceKind.RunOnce)
        };

        // 1. Capture Run and RunOnce values
        foreach (var (hiveName, subKey, kind) in runLocations)
        {
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                token.ThrowIfCancellationRequested();
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(hiveName, view);
                    using var key = baseKey.OpenSubKey(subKey);
                    if (key is null) continue;

                    foreach (var valueName in key.GetValueNames())
                    {
                        var value = Convert.ToString(key.GetValue(valueName, "", RegistryValueOptions.DoNotExpandEnvironmentNames)) ?? "";
                        var pathMatch = graph.ReferencesEvidence(value);
                        var nameMatch = graph.CandidateNames.Any(c => c.Equals(valueName, StringComparison.OrdinalIgnoreCase));

                        if (pathMatch || nameMatch)
                        {
                            // Path evidence produces Certain/High confidence; Name-only match is strictly Medium confidence
                            var confidence = pathMatch ? OwnershipConfidence.Certain : OwnershipConfidence.Medium;
                            var evidence = new List<string>();
                            if (pathMatch) evidence.Add($"Command points into app installation: {value}");
                            if (nameMatch) evidence.Add($"Value name matches candidate name '{valueName}'");

                            var correlationKey = new StartupCorrelationKey(hiveName, view, kind, valueName);
                            var hiveText = hiveName == RegistryHive.CurrentUser ? "HKEY_CURRENT_USER" : "HKEY_LOCAL_MACHINE";
                            var regPath = $@"{hiveText}\{subKey}";

                            graph.CapturedStartupSources.Add(new CapturedStartupSource(
                                correlationKey, regPath, value, null, confidence, evidence));
                        }
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    diagnostics.Add(new ScanDiagnostic("PreUninstallIdentity", $"Access denied reading startup key {hiveName}\\{subKey}: {ex.Message}", IsWarning: true));
                    if (status == ScanStatus.Complete) status = ScanStatus.CompleteWithWarnings;
                }
                catch (Exception ex)
                {
                    diagnostics.Add(new ScanDiagnostic("PreUninstallIdentity", $"Error reading startup key {hiveName}\\{subKey}: {ex.Message}", IsWarning: true));
                    if (status == ScanStatus.Complete) status = ScanStatus.CompleteWithWarnings;
                }
            }
        }

        // 2. Capture Startup folder shortcuts with resolved targets
        var startupFolders = new[]
        {
            (Environment.GetFolderPath(Environment.SpecialFolder.Startup), RegistryHive.CurrentUser, "UserStartupFolder"),
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), RegistryHive.LocalMachine, "CommonStartupFolder")
        };

        foreach (var (folder, hiveName, kindLabel) in startupFolders)
        {
            if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(folder, "*.*", SearchOption.TopDirectoryOnly))
                {
                    var name = Path.GetFileNameWithoutExtension(file);
                    var resolution = file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)
                        ? ShortcutResolver.Resolve(file)
                        : ShortcutResolution.Empty;

                    var targetPath = resolution.HasTarget ? resolution.TargetPath : file;
                    var pathMatch = graph.ReferencesEvidence(targetPath);
                    var nameMatch = graph.CandidateNames.Any(c => c.Equals(name, StringComparison.OrdinalIgnoreCase));

                    if (pathMatch || nameMatch)
                    {
                        var confidence = pathMatch ? OwnershipConfidence.Certain : OwnershipConfidence.Medium;
                        var evidence = new List<string>();
                        if (pathMatch) evidence.Add($"Shortcut target resolves to app installation: {targetPath}");
                        if (nameMatch) evidence.Add($"Shortcut name matches candidate name '{name}'");

                        var correlationKey = new StartupCorrelationKey(hiveName, RegistryView.Default, StartupSourceKind.StartupFolder, name);
                        graph.CapturedStartupSources.Add(new CapturedStartupSource(
                            correlationKey, folder, file, targetPath, confidence, evidence));
                    }
                }
            }
            catch { }
        }

        // 3. Capture StartupApproved entries in HKCU and HKLM
        var approvedLocations = new[]
        {
            (RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run", StartupSourceKind.Run),
            (RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32", StartupSourceKind.Run),
            (RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder", StartupSourceKind.StartupFolder),
            (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run", StartupSourceKind.Run),
            (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32", StartupSourceKind.Run),
            (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder", StartupSourceKind.StartupFolder)
        };

        foreach (var (hiveName, subKey, kind) in approvedLocations)
        {
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                token.ThrowIfCancellationRequested();
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(hiveName, view);
                    using var key = baseKey.OpenSubKey(subKey);
                    if (key is null) continue;

                    foreach (var valueName in key.GetValueNames())
                    {
                        var rawBytes = key.GetValue(valueName) as byte[] ?? [];
                        var correlationKey = new StartupCorrelationKey(hiveName, view, kind, valueName);
                        var hiveText = hiveName == RegistryHive.CurrentUser ? "HKEY_CURRENT_USER" : "HKEY_LOCAL_MACHINE";
                        var regPath = $@"{hiveText}\{subKey}";

                        graph.CapturedStartupApprovedEntries.Add(new CapturedStartupApproval(
                            correlationKey, regPath, rawBytes));
                    }
                }
                catch { }
            }
        }
    }

    private static void CaptureServices(
        ApplicationIdentityGraph graph,
        List<ScanDiagnostic> diagnostics,
        ref ScanStatus status,
        CancellationToken token)
    {
        const string servicesSubKey = @"SYSTEM\CurrentControlSet\Services";
        try
        {
            using var hive = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var services = hive.OpenSubKey(servicesSubKey);
            if (services is null) return;

            foreach (var serviceName in services.GetSubKeyNames())
            {
                token.ThrowIfCancellationRequested();
                using var service = services.OpenSubKey(serviceName);
                if (service is null) continue;

                var imagePath = Convert.ToString(service.GetValue("ImagePath", "", RegistryValueOptions.DoNotExpandEnvironmentNames)) ?? "";
                var serviceDll = "";
                using (var paramsKey = service.OpenSubKey("Parameters"))
                {
                    if (paramsKey is not null)
                        serviceDll = Convert.ToString(paramsKey.GetValue("ServiceDll", "", RegistryValueOptions.DoNotExpandEnvironmentNames)) ?? "";
                }

                if (graph.ReferencesEvidence(imagePath) || graph.ReferencesEvidence(serviceDll) || graph.CandidateNames.Any(c => c.Equals(serviceName, StringComparison.OrdinalIgnoreCase)))
                {
                    var type = Convert.ToInt32(service.GetValue("Type") ?? 0);
                    var displayName = Convert.ToString(service.GetValue("DisplayName")) ?? serviceName;
                    graph.CapturedServices.Add(new CapturedServiceEntry(
                        serviceName, displayName, imagePath, serviceDll, (type & 0x3) != 0));
                }
            }
        }
        catch (Exception ex)
        {
            diagnostics.Add(new ScanDiagnostic("PreUninstallIdentity", $"Error capturing services: {ex.Message}", IsWarning: true));
        }
    }

    private static void CaptureTasks(
        ApplicationIdentityGraph graph,
        List<ScanDiagnostic> diagnostics,
        ref ScanStatus status,
        CancellationToken token)
    {
        try
        {
            const string script = "$ProgressPreference='SilentlyContinue'; Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object { $t=$_; foreach($a in $_.Actions) { [pscustomobject]@{TaskName=$t.TaskName;TaskPath=$t.TaskPath;Execute=$a.Execute;Arguments=$a.Arguments;WorkingDirectory=$a.WorkingDirectory} } } | ConvertTo-Json -Compress";
            var start = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            start.ArgumentList.Add("-NoProfile");
            start.ArgumentList.Add("-NonInteractive");
            start.ArgumentList.Add("-Command");
            start.ArgumentList.Add(script);

            using var process = Process.Start(start);
            if (process is not null)
            {
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit(4000);
                if (!string.IsNullOrWhiteSpace(output))
                {
                    using var document = JsonDocument.Parse(output);
                    var items = document.RootElement.ValueKind == JsonValueKind.Array
                        ? document.RootElement.EnumerateArray().ToArray()
                        : [document.RootElement];

                    foreach (var item in items)
                    {
                        var taskName = JsonString(item, "TaskName");
                        var taskPath = JsonString(item, "TaskPath");
                        var execute = JsonString(item, "Execute");
                        var args = JsonString(item, "Arguments");
                        var workDir = JsonString(item, "WorkingDirectory");
                        var action = string.Join(';', execute, args, workDir);

                        var pathMatch = graph.ReferencesEvidence(action);
                        var nameMatch = graph.CandidateNames.Any(x => taskName.Equals(x, StringComparison.CurrentCultureIgnoreCase));

                        if (pathMatch || nameMatch)
                        {
                            var confidence = pathMatch ? OwnershipConfidence.Certain : OwnershipConfidence.Medium;
                            var evidence = new List<string>();
                            if (pathMatch) evidence.Add($"Task action launches application binary: {execute}");
                            if (nameMatch) evidence.Add($"Task name matches candidate name '{taskName}'");

                            graph.CapturedTasks.Add(new CapturedTaskEntry(
                                taskName, taskPath, execute, args, workDir, confidence, evidence));
                        }
                    }
                }
            }
        }
        catch { }
    }

    private static void CaptureAppPaths(
        ApplicationIdentityGraph graph,
        List<ScanDiagnostic> diagnostics,
        ref ScanStatus status,
        CancellationToken token)
    {
        const string appPathsSubKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths";
        foreach (var hiveName in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
        {
            var hiveText = hiveName == RegistryHive.CurrentUser ? "HKEY_CURRENT_USER" : "HKEY_LOCAL_MACHINE";
            foreach (var viewName in new[] { "64", "32" })
            {
                token.ThrowIfCancellationRequested();
                try
                {
                    var view = viewName == "32" ? RegistryView.Registry32 : RegistryView.Registry64;
                    using var baseKey = RegistryKey.OpenBaseKey(hiveName, view);
                    using var appPaths = baseKey.OpenSubKey(appPathsSubKey);
                    if (appPaths is null) continue;
                    foreach (var exeName in appPaths.GetSubKeyNames())
                    {
                        using var key = appPaths.OpenSubKey(exeName);
                        if (key is null) continue;
                        var defaultVal = Convert.ToString(key.GetValue(null)) ?? "";
                        var pathVal = Convert.ToString(key.GetValue("Path")) ?? "";
                        if (graph.ReferencesEvidence(defaultVal + ";" + pathVal) || graph.ExecutableNames.Any(e => e.Equals(exeName, StringComparison.OrdinalIgnoreCase)))
                        {
                            graph.CapturedAppPaths.Add(new CapturedAppPathEntry(
                                hiveText, viewName, exeName, defaultVal));
                        }
                    }
                }
                catch { }
            }
        }
    }

    public bool ReferencesEvidence(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        var expanded = Environment.ExpandEnvironmentVariables(value)
            .Replace(@"\??\", "", StringComparison.Ordinal)
            .Replace('/', '\\');

        foreach (var root in EvidenceRoots)
        {
            var index = expanded.IndexOf(root, StringComparison.OrdinalIgnoreCase);
            while (index >= 0)
            {
                var beforeOkay = index == 0 || expanded[index - 1] is '"' or '\'' or ' ' or '=' or ';' or ',';
                var end = index + root.Length;
                var afterOkay = end == expanded.Length || expanded[end] is '\\' or '/' or '"' or '\'' or ' ' or ';' or ',';
                if (beforeOkay && afterOkay) return true;
                index = expanded.IndexOf(root, index + 1, StringComparison.OrdinalIgnoreCase);
            }
        }

        foreach (var exePath in ExecutablePaths)
        {
            if (expanded.Contains(exePath, StringComparison.OrdinalIgnoreCase)) return true;
        }

        return false;
    }

    public bool MatchesExecutableName(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        var clean = ExtractFileName(name);
        return ExecutableNames.Any(e => e.Equals(clean, StringComparison.OrdinalIgnoreCase));
    }

    private static IEnumerable<string> CollectEvidenceRoots(InstalledApplication app)
    {
        if (TryNormalizeEvidencePath(app.InstallLocation, out var install)) yield return install;
        var icon = IconIndexRegex().Replace(app.DisplayIconPath, "").Trim().Trim('"');
        if (TryNormalizeEvidencePath(ExtractDirectoryName(icon), out var iconDir)
            && !iconDir.Equals(install, StringComparison.OrdinalIgnoreCase))
            yield return iconDir;
    }

    private static IEnumerable<string> CollectCandidateNames(InstalledApplication app)
    {
        var raw = SafeSegment(app.DisplayName);
        if (raw.Length >= 3) yield return raw;
        var withoutVersion = SafeSegment(VersionSuffixRegex().Replace(app.DisplayName, "").Trim());
        if (withoutVersion.Length >= 3 && !withoutVersion.Equals(raw, StringComparison.OrdinalIgnoreCase)) yield return withoutVersion;
    }

    private static (List<string> Executables, List<string> Paths) CollectDiscoveredExecutables(InstalledApplication app)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var paths = new List<string>();

        var icon = IconIndexRegex().Replace(app.DisplayIconPath, "").Trim().Trim('"');
        var ext = ExtractExtension(icon);
        if (ext.Equals(".exe", StringComparison.OrdinalIgnoreCase))
        {
            names.Add(ExtractFileName(icon));
            paths.Add(icon);
        }

        if (!string.IsNullOrWhiteSpace(app.InstallLocation) && Directory.Exists(app.InstallLocation))
        {
            try
            {
                foreach (var file in Directory.EnumerateFiles(app.InstallLocation, "*.exe", SearchOption.TopDirectoryOnly).Take(60))
                {
                    names.Add(Path.GetFileName(file));
                    paths.Add(file);
                }
            }
            catch { }
        }

        return (names.ToList(), paths);
    }

    private static bool TryNormalizeEvidencePath(string raw, out string path)
    {
        path = "";
        if (string.IsNullOrWhiteSpace(raw)) return false;
        try
        {
            var cleaned = Environment.ExpandEnvironmentVariables(raw.Trim().Trim('"'))
                .TrimEnd('\\', '/');
            if (cleaned.Length >= 4)
            {
                path = cleaned;
                return true;
            }
            return false;
        }
        catch { return false; }
    }

    private static string ExtractFileName(string path)
    {
        var lastSlash = Math.Max(path.LastIndexOf('\\'), path.LastIndexOf('/'));
        return lastSlash >= 0 ? path[(lastSlash + 1)..] : path;
    }

    private static string ExtractDirectoryName(string path)
    {
        var lastSlash = Math.Max(path.LastIndexOf('\\'), path.LastIndexOf('/'));
        return lastSlash >= 0 ? path[..lastSlash] : "";
    }

    private static string ExtractExtension(string path)
    {
        var lastDot = path.LastIndexOf('.');
        var lastSlash = Math.Max(path.LastIndexOf('\\'), path.LastIndexOf('/'));
        return lastDot > lastSlash ? path[lastDot..] : "";
    }

    private static string SafeSegment(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Equals("Unknown publisher", StringComparison.OrdinalIgnoreCase)) return "";
        var invalid = Path.GetInvalidFileNameChars();
        return string.Concat(value.Trim().Where(c => !invalid.Contains(c))).TrimEnd('.');
    }

    private static string JsonString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) ? value.ToString() : "";

    [GeneratedRegex(@"(?i)\s+(?:v(?:ersion)?\s*)?\d+(?:\.\d+){0,3}(?:\s*\([^)]*\))?$")]
    private static partial Regex VersionSuffixRegex();
    [GeneratedRegex(@",\s*-?\d+$")]
    private static partial Regex IconIndexRegex();
}
