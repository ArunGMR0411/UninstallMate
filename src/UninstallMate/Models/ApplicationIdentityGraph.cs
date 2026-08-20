using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace UninstallMate.Models;

public sealed record CapturedStartupEntry(
    string Hive,
    string SubKey,
    string View,
    string ValueName,
    string Command,
    string SourceKind); // "Run", "RunOnce", "StartupFolder", "ScheduledTask"

public sealed record CapturedStartupApprovedEntry(
    string Hive,
    string SubKey,
    string View,
    string ValueName,
    string RawBytesBase64,
    string? CorrelatedSource);

public sealed record CapturedServiceEntry(
    string ServiceName,
    string DisplayName,
    string ImagePath,
    string ServiceDll,
    bool IsDriver);

public sealed record CapturedTaskEntry(
    string TaskName,
    string TaskPath,
    string Action);

public sealed record CapturedAppPathEntry(
    string Hive,
    string View,
    string ExeName,
    string TargetPath);

public sealed partial class ApplicationIdentityGraph
{
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
    public List<CapturedStartupEntry> CapturedStartupSources { get; init; } = [];
    public List<CapturedStartupApprovedEntry> CapturedStartupApprovedEntries { get; init; } = [];
    public List<CapturedServiceEntry> CapturedServices { get; init; } = [];
    public List<CapturedTaskEntry> CapturedTasks { get; init; } = [];
    public List<CapturedAppPathEntry> CapturedAppPaths { get; init; } = [];

    public static async Task<ApplicationIdentityGraph> CaptureAsync(
        InstalledApplication app, CancellationToken token)
    {
        var graph = Create(app);
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            await Task.Run(() => CaptureWindowsPreUninstallState(graph, token), token);
        }
        return graph;
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

    private static void CaptureWindowsPreUninstallState(ApplicationIdentityGraph graph, CancellationToken token)
    {
        try
        {
            CaptureStartupState(graph, token);
            CaptureServices(graph, token);
            CaptureAppPaths(graph, token);
        }
        catch { /* Failure to inspect one subsystem must not block snapshot */ }
    }

    private static void CaptureStartupState(ApplicationIdentityGraph graph, CancellationToken token)
    {
        var runLocations = new[]
        {
            (RegistryHive.CurrentUser, "HKEY_CURRENT_USER", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Run"),
            (RegistryHive.CurrentUser, "HKEY_CURRENT_USER", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce"),
            (RegistryHive.LocalMachine, "HKEY_LOCAL_MACHINE", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Run"),
            (RegistryHive.LocalMachine, "HKEY_LOCAL_MACHINE", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce")
        };

        var startupNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // 1. Capture Run and RunOnce values that reference app evidence
        foreach (var (hive, hiveText, subKey, kind) in runLocations)
        {
            foreach (var viewName in new[] { "64", "32" })
            {
                token.ThrowIfCancellationRequested();
                try
                {
                    var view = viewName == "32" ? RegistryView.Registry32 : RegistryView.Registry64;
                    using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                    using var key = baseKey.OpenSubKey(subKey);
                    if (key is null) continue;
                    foreach (var valueName in key.GetValueNames())
                    {
                        var value = Convert.ToString(key.GetValue(valueName, "", RegistryValueOptions.DoNotExpandEnvironmentNames)) ?? "";
                        if (graph.ReferencesEvidence(value) || graph.CandidateNames.Any(c => c.Equals(valueName, StringComparison.OrdinalIgnoreCase)))
                        {
                            graph.CapturedStartupSources.Add(new CapturedStartupEntry(
                                hiveText, subKey, viewName, valueName, value, kind));
                            startupNames.Add(valueName);
                        }
                    }
                }
                catch { }
            }
        }

        // 2. Capture Startup folder shortcuts
        var startupFolders = new[]
        {
            (Environment.GetFolderPath(Environment.SpecialFolder.Startup), "UserStartupFolder"),
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "CommonStartupFolder")
        };

        foreach (var (folder, kind) in startupFolders)
        {
            if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(folder, "*.*", SearchOption.TopDirectoryOnly))
                {
                    var name = Path.GetFileNameWithoutExtension(file);
                    if (graph.CandidateNames.Any(c => c.Equals(name, StringComparison.OrdinalIgnoreCase)) || graph.ReferencesEvidence(file))
                    {
                        graph.CapturedStartupSources.Add(new CapturedStartupEntry(
                            "FileSystem", folder, "Default", name, file, kind));
                        startupNames.Add(name);
                    }
                }
            }
            catch { }
        }

        // 3. Capture StartupApproved entries in HKCU and HKLM
        var approvedLocations = new[]
        {
            (RegistryHive.CurrentUser, "HKEY_CURRENT_USER", @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"),
            (RegistryHive.CurrentUser, "HKEY_CURRENT_USER", @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32"),
            (RegistryHive.CurrentUser, "HKEY_CURRENT_USER", @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder"),
            (RegistryHive.LocalMachine, "HKEY_LOCAL_MACHINE", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"),
            (RegistryHive.LocalMachine, "HKEY_LOCAL_MACHINE", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32"),
            (RegistryHive.LocalMachine, "HKEY_LOCAL_MACHINE", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder")
        };

        foreach (var (hive, hiveText, subKey) in approvedLocations)
        {
            foreach (var viewName in new[] { "64", "32" })
            {
                token.ThrowIfCancellationRequested();
                try
                {
                    var view = viewName == "32" ? RegistryView.Registry32 : RegistryView.Registry64;
                    using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                    using var key = baseKey.OpenSubKey(subKey);
                    if (key is null) continue;

                    foreach (var valueName in key.GetValueNames())
                    {
                        // Check if value name matches any startup name or candidate name
                        var matchesStartup = startupNames.Contains(valueName);
                        var matchesCandidate = graph.CandidateNames.Any(c => c.Equals(valueName, StringComparison.OrdinalIgnoreCase));

                        if (matchesStartup || matchesCandidate)
                        {
                            var rawBytes = key.GetValue(valueName) as byte[] ?? [];
                            var base64 = Convert.ToBase64String(rawBytes);
                            graph.CapturedStartupApprovedEntries.Add(new CapturedStartupApprovedEntry(
                                hiveText, subKey, viewName, valueName, base64, matchesStartup ? valueName : null));
                        }
                    }
                }
                catch { }
            }
        }
    }

    private static void CaptureServices(ApplicationIdentityGraph graph, CancellationToken token)
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
        catch { }
    }

    private static void CaptureAppPaths(ApplicationIdentityGraph graph, CancellationToken token)
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

        // Also check if matches discovered executable paths
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

    [GeneratedRegex(@"(?i)\s+(?:v(?:ersion)?\s*)?\d+(?:\.\d+){0,3}(?:\s*\([^)]*\))?$")]
    private static partial Regex VersionSuffixRegex();
    [GeneratedRegex(@",\s*-?\d+$")]
    private static partial Regex IconIndexRegex();
}
