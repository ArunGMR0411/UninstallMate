using Microsoft.Win32;
using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using UninstallMate.Models;

namespace UninstallMate.Services;

public sealed partial class CleanupScanner
{
    public async Task<IReadOnlyList<CleanupCandidate>> ScanAsync(InstalledApplication app, CancellationToken token)
    {
        var candidates = await Task.Run(() => ScanLocalArtifacts(app, token), token);
        await AddScheduledTasksAsync(app, candidates, token);
        return candidates.Values
            .OrderBy(x => x.Risk)
            .ThenBy(x => x.Kind)
            .ThenBy(x => x.Target, StringComparer.CurrentCultureIgnoreCase)
            .ToList();
    }

    private static Dictionary<string, CleanupCandidate> ScanLocalArtifacts(
        InstalledApplication app, CancellationToken token)
    {
        var candidates = new Dictionary<string, CleanupCandidate>(StringComparer.OrdinalIgnoreCase);
        AddInstallLocation(app, candidates);
        AddKnownDataFolders(app, candidates, token);
        AddShortcuts(app, candidates, token);
        AddCrashDumps(app, candidates, token);
        AddRegistryKeys(app, candidates, token);
        AddPathBackedRegistryArtifacts(app, candidates, token);
        AddWindowsServices(app, candidates, token);
        RemoveNestedFilesystemCandidates(candidates);
        return candidates;
    }

    private static void AddInstallLocation(InstalledApplication app, Dictionary<string, CleanupCandidate> candidates)
    {
        if (app.Kind == ApplicationKind.MicrosoftStore) return; // Windows owns and ACL-protects the package payload.
        AddDirectoryCandidate(
            app.InstallLocation, RiskLevel.Medium,
            "Application installation folder remaining after removal", candidates,
            CleanupScope.Application);
    }

    private static void AddKnownDataFolders(
        InstalledApplication app, Dictionary<string, CleanupCandidate> candidates, CancellationToken token)
    {
        var names = CandidateNames(app).ToArray();
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var lowRiskRoots = new[]
        {
            localAppData,
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            Path.Combine(userProfile, "AppData", "LocalLow"),
            Path.Combine(localAppData, "Temp")
        };

        foreach (var root in lowRiskRoots.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            foreach (var name in names)
            {
                token.ThrowIfCancellationRequested();
                AddExactDirectory(root, name, RiskLevel.Low, "Exact app-named data, cache, log, or temporary folder", candidates);
            }
            AddPublisherNestedFolders(app, root, names, candidates, token);
        }

        var programRoots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonProgramFilesX86)
        };
        foreach (var root in programRoots.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            foreach (var name in names)
            {
                token.ThrowIfCancellationRequested();
                AddExactDirectory(
                    root, name, RiskLevel.Medium,
                    "Exact app-named program folder remaining after removal", candidates,
                    CleanupScope.Application);
            }
            AddPublisherNestedFolders(
                app, root, names, candidates, token, RiskLevel.Medium, CleanupScope.Application);
        }

        if (app.Kind == ApplicationKind.MicrosoftStore && app.PackageFamilyName.Length >= 3)
        {
            AddExactDirectory(
                Path.Combine(localAppData, "Packages"), app.PackageFamilyName, RiskLevel.Low,
                "Store application's private data folder", candidates);
        }

        // These can contain saves, projects, presets, or other user-created data, so keep them high risk.
        // The UI's single-panel review workflow may select them, but preserves this warning level.
        var personalRoots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.Combine(userProfile, "Saved Games")
        };
        foreach (var root in personalRoots.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase))
            foreach (var name in names)
                AddExactDirectory(root, name, RiskLevel.High, "Possible app data that may contain personal files", candidates);

        foreach (var name in names)
        {
            var dotName = "." + SlugRegex().Replace(name.ToLowerInvariant(), "");
            if (dotName.Length >= 4)
                AddExactDirectory(userProfile, dotName, RiskLevel.High, "Hidden per-user configuration that may contain valuable settings", candidates);
        }
    }

    private static void AddPublisherNestedFolders(
        InstalledApplication app,
        string root,
        IEnumerable<string> names,
        Dictionary<string, CleanupCandidate> candidates,
        CancellationToken token,
        RiskLevel risk = RiskLevel.Low,
        CleanupScope? scope = null)
    {
        var publisher = SafeSegment(app.Publisher);
        if (publisher.Length < 3) return;
        var publisherPath = Path.Combine(root, publisher);
        if (!Directory.Exists(publisherPath)) return;
        foreach (var name in names)
        {
            token.ThrowIfCancellationRequested();
            AddExactDirectory(
                publisherPath, name, risk,
                risk == RiskLevel.Low
                    ? "App folder inside its publisher's data folder"
                    : "App folder inside a publisher program folder (publisher folder may be shared)",
                candidates,
                scope);
        }
    }

    private static void AddExactDirectory(
        string root,
        string name,
        RiskLevel risk,
        string reason,
        Dictionary<string, CleanupCandidate> candidates,
        CleanupScope? scope = null)
    {
        if (name.Length < 3 || !Directory.Exists(root)) return;
        AddDirectoryCandidate(Path.Combine(root, name), risk, reason, candidates, scope);
    }

    private static void AddDirectoryCandidate(
        string path,
        RiskLevel risk,
        string reason,
        Dictionary<string, CleanupCandidate> candidates,
        CleanupScope? scope = null)
    {
        if (!Directory.Exists(path) || !IsSafeSpecificPath(path)) return;
        path = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar);
        candidates[path] = new CleanupCandidate
        {
            Target = path,
            Kind = CleanupKind.Directory,
            Risk = risk,
            Reason = reason,
            SizeBytes = GetDirectorySize(path),
            Scope = scope ?? ClassifyFileScope(path),
            IsSelected = risk == RiskLevel.Low
        };
    }

    private static void AddShortcuts(
        InstalledApplication app, Dictionary<string, CleanupCandidate> candidates, CancellationToken token)
    {
        var names = CandidateNames(app).ToArray();
        var roots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), "Programs"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu), "Programs"),
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
        }.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase);

        foreach (var root in roots)
        {
            foreach (var name in names)
                AddExactDirectory(root, name, RiskLevel.Low, "App-specific shortcut folder", candidates);

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*", new EnumerationOptions
                {
                    RecurseSubdirectories = true,
                    IgnoreInaccessible = true,
                    AttributesToSkip = FileAttributes.ReparsePoint
                }).Where(x => Path.GetExtension(x).Equals(".lnk", StringComparison.OrdinalIgnoreCase)
                    || Path.GetExtension(x).Equals(".url", StringComparison.OrdinalIgnoreCase));
            }
            catch { continue; }

            foreach (var file in files)
            {
                token.ThrowIfCancellationRequested();
                var shortcutName = Path.GetFileNameWithoutExtension(file);
                if (!names.Any(name => ShortcutNameMatches(shortcutName, name))) continue;
                AddFileCandidate(file, RiskLevel.Low, "App-named desktop, Start menu, or startup shortcut", candidates);
            }
        }
    }

    private static bool ShortcutNameMatches(string shortcutName, string appName) =>
        shortcutName.Equals(appName, StringComparison.CurrentCultureIgnoreCase)
        || shortcutName.Equals($"Uninstall {appName}", StringComparison.CurrentCultureIgnoreCase)
        || shortcutName.Equals($"{appName} Uninstall", StringComparison.CurrentCultureIgnoreCase);

    private static void AddCrashDumps(
        InstalledApplication app, Dictionary<string, CleanupCandidate> candidates, CancellationToken token)
    {
        var crashRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CrashDumps");
        if (!Directory.Exists(crashRoot)) return;
        var executableNames = GetExecutableNames(app).ToArray();
        if (executableNames.Length == 0) return;
        try
        {
            foreach (var file in Directory.EnumerateFiles(crashRoot, "*.dmp", SearchOption.TopDirectoryOnly))
            {
                token.ThrowIfCancellationRequested();
                if (executableNames.Any(exe => Path.GetFileName(file).StartsWith(exe + ".", StringComparison.OrdinalIgnoreCase)))
                    AddFileCandidate(file, RiskLevel.Low, "Crash dump produced by an application executable", candidates);
            }
        }
        catch { }
    }

    private static void AddFileCandidate(
        string path, RiskLevel risk, string reason, Dictionary<string, CleanupCandidate> candidates)
    {
        if (!File.Exists(path) || !IsSafeSpecificPath(path)) return;
        long size = 0;
        try { size = new FileInfo(path).Length; } catch { }
        candidates[path] = new CleanupCandidate
        {
            Target = path,
            Kind = CleanupKind.File,
            Risk = risk,
            Reason = reason,
            SizeBytes = size,
            Scope = ClassifyFileScope(path),
            IsSelected = risk == RiskLevel.Low
        };
    }

    private static void AddRegistryKeys(
        InstalledApplication app, Dictionary<string, CleanupCandidate> candidates, CancellationToken token)
    {
        var appRegistryView = app.Architecture == "32-bit" ? "32" : app.Architecture == "64-bit" ? "64" : "Default";
        if (!string.IsNullOrWhiteSpace(app.RegistryKeyPath) && RegistryPathExists(app.RegistryKeyPath, appRegistryView))
        {
            AddRegistryKeyCandidate(
                app.RegistryKeyPath, appRegistryView, RiskLevel.Low,
                "The application's registered uninstall entry", candidates);
        }

        AddEquivalentUninstallEntries(app, candidates, token);

        var names = CandidateNames(app).ToArray();
        foreach (var hive in new[] { "HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE" })
        {
            foreach (var name in names)
            {
                token.ThrowIfCancellationRequested();
                AddRegistryIfPresent($@"{hive}\SOFTWARE\{name}", "Exact app-named software key", candidates);
            }
            var publisher = SafeSegment(app.Publisher);
            if (publisher.Length < 3 || publisher.Equals("Microsoft Corporation", StringComparison.OrdinalIgnoreCase)) continue;
            foreach (var name in names)
                AddRegistryIfPresent($@"{hive}\SOFTWARE\{publisher}\{name}", "App key below its publisher key", candidates);
        }
    }

    private static void AddEquivalentUninstallEntries(
        InstalledApplication app,
        Dictionary<string, CleanupCandidate> candidates,
        CancellationToken token)
    {
        if (app.Kind == ApplicationKind.MicrosoftStore) return;
        const string uninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        foreach (var hiveName in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
        {
            var hiveText = hiveName == RegistryHive.CurrentUser ? "HKEY_CURRENT_USER" : "HKEY_LOCAL_MACHINE";
            foreach (var view in new[] { "64", "32" })
            {
                try
                {
                    using var hive = OpenHive(hiveName, view);
                    using var root = hive.OpenSubKey(uninstallPath);
                    if (root is null) continue;
                    foreach (var keyName in root.GetSubKeyNames())
                    {
                        token.ThrowIfCancellationRequested();
                        using var key = root.OpenSubKey(keyName);
                        if (key is null || !EquivalentRegistration(app, key)) continue;
                        var path = $@"{hiveText}\{uninstallPath}\{keyName}";
                        AddRegistryKeyCandidate(
                            path, view, RiskLevel.Low,
                            path.Equals(app.RegistryKeyPath, StringComparison.OrdinalIgnoreCase)
                                ? "The application's registered uninstall entry"
                                : "Duplicate registration for the same application in another registry scope/view",
                            candidates);
                    }
                }
                catch { }
            }
        }
    }

    private static bool EquivalentRegistration(InstalledApplication app, RegistryKey key)
    {
        static string Read(RegistryKey source, string name) => (Convert.ToString(source.GetValue(name)) ?? "").Trim();
        if (!Read(key, "DisplayName").Equals(app.DisplayName.Trim(), StringComparison.CurrentCultureIgnoreCase)) return false;
        var publisher = Read(key, "Publisher");
        if (publisher.Length > 0 && app.Publisher.Length > 0
            && !publisher.Equals(app.Publisher.Trim(), StringComparison.CurrentCultureIgnoreCase)) return false;
        var version = Read(key, "DisplayVersion");
        if (version.Length > 0 && app.Version.Length > 0
            && !version.Equals(app.Version.Trim(), StringComparison.CurrentCultureIgnoreCase)) return false;
        var location = Environment.ExpandEnvironmentVariables(Read(key, "InstallLocation")).Trim().Trim('"');
        if (location.Length > 0 && app.InstallLocation.Length > 0)
        {
            try
            {
                if (!Path.GetFullPath(location).TrimEnd('\\').Equals(
                    Path.GetFullPath(app.InstallLocation).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) return false;
            }
            catch { return false; }
        }
        return true;
    }

    private static void AddPathBackedRegistryArtifacts(
        InstalledApplication app, Dictionary<string, CleanupCandidate> candidates, CancellationToken token)
    {
        var evidenceRoots = EvidenceRoots(app).ToArray();
        if (evidenceRoots.Length == 0) return;

        var valueLocations = new[]
        {
            (RegistryHive.CurrentUser, "HKEY_CURRENT_USER", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", RiskLevel.Medium, "Startup entry points into the app's installation"),
            (RegistryHive.CurrentUser, "HKEY_CURRENT_USER", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", RiskLevel.Medium, "One-time startup entry points into the app's installation"),
            (RegistryHive.LocalMachine, "HKEY_LOCAL_MACHINE", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", RiskLevel.Medium, "Machine startup entry points into the app's installation"),
            (RegistryHive.LocalMachine, "HKEY_LOCAL_MACHINE", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", RiskLevel.Medium, "Machine one-time startup entry points into the app's installation")
        };
        foreach (var (hive, hiveText, path, risk, reason) in valueLocations)
        {
            foreach (var view in ViewsFor(hive))
            {
                token.ThrowIfCancellationRequested();
                AddMatchingRegistryValues(hive, hiveText, path, view, evidenceRoots, risk, reason, candidates);
            }
        }

        AddEnvironmentReferences(
            RegistryHive.CurrentUser, "HKEY_CURRENT_USER", @"Environment", evidenceRoots, candidates);
        AddEnvironmentReferences(
            RegistryHive.LocalMachine, "HKEY_LOCAL_MACHINE",
            @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", evidenceRoots, candidates);

        foreach (var hive in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
        {
            var hiveText = hive == RegistryHive.CurrentUser ? "HKEY_CURRENT_USER" : "HKEY_LOCAL_MACHINE";
            foreach (var view in ViewsFor(hive))
            {
                token.ThrowIfCancellationRequested();
                AddAppPathKeys(hive, hiveText, view, evidenceRoots, candidates, token);
                AddComKeys(hive, hiveText, view, evidenceRoots, candidates, token);
                AddApplicationClassKeys(hive, hiveText, view, evidenceRoots, candidates, token);
                AddProtocolAndProgIdKeys(hive, hiveText, view, evidenceRoots, candidates, token);
            }
        }
    }

    private static void AddEnvironmentReferences(
        RegistryHive hiveName,
        string hiveText,
        string subKey,
        string[] evidenceRoots,
        Dictionary<string, CleanupCandidate> candidates)
    {
        foreach (var view in ViewsFor(hiveName))
        {
            try
            {
                using var hive = OpenHive(hiveName, view);
                using var key = hive.OpenSubKey(subKey);
                if (key is null) continue;
                foreach (var valueName in key.GetValueNames())
                {
                    var value = Convert.ToString(key.GetValue(valueName, "", RegistryValueOptions.DoNotExpandEnvironmentNames)) ?? "";
                    var evidence = evidenceRoots.FirstOrDefault(root => ReferencesEvidencePath(value, [root]));
                    if (evidence is null) continue;
                    var target = $@"{hiveText}\{subKey}";
                    if (valueName.Equals("Path", StringComparison.OrdinalIgnoreCase))
                    {
                        candidates[$"environment:{target}|{view}|{valueName}"] = new CleanupCandidate
                        {
                            Target = target,
                            Auxiliary = valueName,
                            EvidencePath = evidence,
                            Kind = CleanupKind.EnvironmentEntry,
                            RegistryViewName = view,
                            Risk = RiskLevel.High,
                            Scope = hiveName == RegistryHive.CurrentUser ? CleanupScope.User : CleanupScope.System,
                            Reason = "An app installation directory remains in PATH; cleanup removes only matching PATH segments",
                            IsSelected = false
                        };
                    }
                    else
                    {
                        candidates[$"value:{target}|{view}|{valueName}"] = new CleanupCandidate
                        {
                            Target = target,
                            Auxiliary = valueName,
                            Kind = CleanupKind.RegistryValue,
                            RegistryViewName = view,
                            Risk = RiskLevel.High,
                            Scope = hiveName == RegistryHive.CurrentUser ? CleanupScope.User : CleanupScope.System,
                            Reason = "Environment variable points into the app's installation",
                            IsSelected = false
                        };
                    }
                }
            }
            catch { }
        }
    }

    private static void AddMatchingRegistryValues(
        RegistryHive hiveName,
        string hiveText,
        string subKey,
        string view,
        string[] evidenceRoots,
        RiskLevel risk,
        string reason,
        Dictionary<string, CleanupCandidate> candidates)
    {
        try
        {
            using var hive = OpenHive(hiveName, view);
            using var key = hive.OpenSubKey(subKey);
            if (key is null) return;
            foreach (var valueName in key.GetValueNames())
            {
                var value = Convert.ToString(key.GetValue(valueName, "", RegistryValueOptions.DoNotExpandEnvironmentNames)) ?? "";
                if (!ReferencesEvidencePath(value, evidenceRoots)) continue;
                var target = $@"{hiveText}\{subKey}";
                var candidateKey = $"value:{target}|{valueName}";
                var existing = candidates.TryGetValue(candidateKey, out var found) ? found : null;
                var mergedView = existing is null || existing.RegistryViewName == view ? view : "Both";
                candidates[candidateKey] = new CleanupCandidate
                {
                    Target = target,
                    Auxiliary = valueName,
                    Kind = CleanupKind.RegistryValue,
                    RegistryViewName = mergedView,
                    Risk = risk,
                    Scope = hiveName == RegistryHive.CurrentUser ? CleanupScope.User : CleanupScope.System,
                    Reason = mergedView == "Both"
                        ? $"{reason} (shared by both registry views)"
                        : $"{reason} ({view}-bit view)",
                    IsSelected = false
                };
            }
        }
        catch { }
    }

    private static void AddAppPathKeys(
        RegistryHive hiveName,
        string hiveText,
        string view,
        string[] evidenceRoots,
        Dictionary<string, CleanupCandidate> candidates,
        CancellationToken token)
    {
        const string rootPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths";
        try
        {
            using var hive = OpenHive(hiveName, view);
            using var root = hive.OpenSubKey(rootPath);
            if (root is null) return;
            foreach (var name in root.GetSubKeyNames())
            {
                token.ThrowIfCancellationRequested();
                using var key = root.OpenSubKey(name);
                var value = Convert.ToString(key?.GetValue(null)) ?? "";
                var pathValue = Convert.ToString(key?.GetValue("Path")) ?? "";
                if (!ReferencesEvidencePath(value + ";" + pathValue, evidenceRoots)) continue;
                AddRegistryKeyCandidate(
                    $@"{hiveText}\{rootPath}\{name}", view, RiskLevel.Low,
                    "Windows App Paths registration points into the app's installation", candidates);
            }
        }
        catch { }
    }

    private static void AddComKeys(
        RegistryHive hiveName,
        string hiveText,
        string view,
        string[] evidenceRoots,
        Dictionary<string, CleanupCandidate> candidates,
        CancellationToken token)
    {
        const string rootPath = @"SOFTWARE\Classes\CLSID";
        try
        {
            using var hive = OpenHive(hiveName, view);
            using var root = hive.OpenSubKey(rootPath);
            if (root is null) return;
            foreach (var clsid in root.GetSubKeyNames())
            {
                token.ThrowIfCancellationRequested();
                using var key = root.OpenSubKey(clsid);
                using var inprocKey = key?.OpenSubKey("InprocServer32");
                using var localKey = key?.OpenSubKey("LocalServer32");
                var inproc = Convert.ToString(inprocKey?.GetValue(null)) ?? "";
                var local = Convert.ToString(localKey?.GetValue(null)) ?? "";
                if (!ReferencesEvidencePath(inproc + ";" + local, evidenceRoots)) continue;
                AddRegistryKeyCandidate(
                    $@"{hiveText}\{rootPath}\{clsid}", view, RiskLevel.Medium,
                    "COM registration loads a component from the app's installation", candidates);
            }
        }
        catch { }
    }

    private static void AddApplicationClassKeys(
        RegistryHive hiveName,
        string hiveText,
        string view,
        string[] evidenceRoots,
        Dictionary<string, CleanupCandidate> candidates,
        CancellationToken token)
    {
        const string rootPath = @"SOFTWARE\Classes\Applications";
        try
        {
            using var hive = OpenHive(hiveName, view);
            using var root = hive.OpenSubKey(rootPath);
            if (root is null) return;
            foreach (var appKey in root.GetSubKeyNames())
            {
                token.ThrowIfCancellationRequested();
                using var command = root.OpenSubKey($@"{appKey}\shell\open\command");
                var value = Convert.ToString(command?.GetValue(null)) ?? "";
                if (!ReferencesEvidencePath(value, evidenceRoots)) continue;
                AddRegistryKeyCandidate(
                    $@"{hiveText}\{rootPath}\{appKey}", view, RiskLevel.Medium,
                    "File-association application registration points into the app's installation", candidates);
            }
        }
        catch { }
    }

    private static void AddProtocolAndProgIdKeys(
        RegistryHive hiveName,
        string hiveText,
        string view,
        string[] evidenceRoots,
        Dictionary<string, CleanupCandidate> candidates,
        CancellationToken token)
    {
        const string rootPath = @"SOFTWARE\Classes";
        var excluded = new HashSet<string>(["CLSID", "Applications", "Installer", "Interface", "TypeLib", "WOW6432Node"], StringComparer.OrdinalIgnoreCase);
        try
        {
            using var hive = OpenHive(hiveName, view);
            using var root = hive.OpenSubKey(rootPath);
            if (root is null) return;
            foreach (var className in root.GetSubKeyNames())
            {
                token.ThrowIfCancellationRequested();
                if (className.StartsWith('.') || excluded.Contains(className)) continue;
                using var command = root.OpenSubKey($@"{className}\shell\open\command");
                using var icon = root.OpenSubKey($@"{className}\DefaultIcon");
                var values = (Convert.ToString(command?.GetValue(null)) ?? "") + ";" +
                    (Convert.ToString(icon?.GetValue(null)) ?? "");
                if (!ReferencesEvidencePath(values, evidenceRoots)) continue;
                AddRegistryKeyCandidate(
                    $@"{hiveText}\{rootPath}\{className}", view, RiskLevel.Medium,
                    "Protocol or file-type class registration points into the app's installation", candidates);
            }
        }
        catch { }
    }

    private static void AddWindowsServices(
        InstalledApplication app, Dictionary<string, CleanupCandidate> candidates, CancellationToken token)
    {
        var evidenceRoots = EvidenceRoots(app).ToArray();
        if (evidenceRoots.Length == 0) return;
        const string servicesPath = @"SYSTEM\CurrentControlSet\Services";
        try
        {
            using var hive = OpenHive(RegistryHive.LocalMachine, "64");
            using var services = hive.OpenSubKey(servicesPath);
            if (services is null) return;
            foreach (var serviceName in services.GetSubKeyNames())
            {
                token.ThrowIfCancellationRequested();
                using var service = services.OpenSubKey(serviceName);
                var imagePath = Convert.ToString(service?.GetValue("ImagePath", "", RegistryValueOptions.DoNotExpandEnvironmentNames)) ?? "";
                if (!ReferencesEvidencePath(imagePath, evidenceRoots)) continue;
                var type = Convert.ToInt32(service?.GetValue("Type") ?? 0);
                var isDriver = (type & 0x3) != 0;
                var target = $@"HKEY_LOCAL_MACHINE\{servicesPath}\{serviceName}";
                candidates[$"service:{serviceName}"] = new CleanupCandidate
                {
                    Target = target,
                    Auxiliary = serviceName,
                    Kind = CleanupKind.WindowsService,
                    RegistryViewName = "64",
                    Risk = RiskLevel.High,
                    Scope = CleanupScope.System,
                    Reason = isDriver
                        ? "Driver service loads a binary from the app's installation; remove only if the vendor uninstaller left it orphaned"
                        : "Windows service runs a binary from the app's installation",
                    IsSelected = false
                };
            }
        }
        catch { }
    }

    private static async Task AddScheduledTasksAsync(
        InstalledApplication app,
        Dictionary<string, CleanupCandidate> candidates,
        CancellationToken token)
    {
        var evidenceRoots = EvidenceRoots(app).ToArray();
        var names = CandidateNames(app).ToArray();
        if (evidenceRoots.Length == 0 && names.Length == 0) return;
        const string script = "$ProgressPreference='SilentlyContinue'; Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object { $t=$_; foreach($a in $_.Actions) { [pscustomobject]@{TaskName=$t.TaskName;TaskPath=$t.TaskPath;Execute=$a.Execute;Arguments=$a.Arguments;WorkingDirectory=$a.WorkingDirectory} } } | ConvertTo-Json -Compress";
        var start = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            CreateNoWindow = true
        };
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-NonInteractive");
        start.ArgumentList.Add("-Command");
        start.ArgumentList.Add(script);
        try
        {
            using var process = Process.Start(start);
            if (process is null) return;
            var outputTask = process.StandardOutput.ReadToEndAsync(token);
            await process.WaitForExitAsync(token);
            if (process.ExitCode != 0) return;
            var json = await outputTask;
            if (string.IsNullOrWhiteSpace(json)) return;
            using var document = JsonDocument.Parse(json);
            var items = document.RootElement.ValueKind == JsonValueKind.Array
                ? document.RootElement.EnumerateArray().ToArray()
                : [document.RootElement];
            foreach (var item in items)
            {
                token.ThrowIfCancellationRequested();
                var taskName = JsonString(item, "TaskName");
                var taskPath = JsonString(item, "TaskPath");
                var action = string.Join(';', JsonString(item, "Execute"), JsonString(item, "Arguments"), JsonString(item, "WorkingDirectory"));
                var pathMatch = ReferencesEvidencePath(action, evidenceRoots);
                var exactNameMatch = names.Any(x => taskName.Equals(x, StringComparison.CurrentCultureIgnoreCase));
                if (!pathMatch && !exactNameMatch) continue;
                var fullTaskName = (taskPath.EndsWith('\\') ? taskPath : taskPath + "\\") + taskName;
                candidates[$"task:{fullTaskName}"] = new CleanupCandidate
                {
                    Target = fullTaskName,
                    Kind = CleanupKind.ScheduledTask,
                    Risk = pathMatch ? RiskLevel.Medium : RiskLevel.High,
                    Scope = CleanupScope.System,
                    Reason = pathMatch
                        ? "Scheduled task launches a program from the app's installation"
                        : "Scheduled task exactly matches the app name; review its actions",
                    IsSelected = false
                };
            }
        }
        catch { }
    }

    private static void AddRegistryIfPresent(
        string path, string reason, Dictionary<string, CleanupCandidate> candidates)
    {
        foreach (var view in new[] { "64", "32" })
        {
            if (!RegistryPathExists(path, view)) continue;
            AddRegistryKeyCandidate(
                path, view, RiskLevel.Medium,
                $"{reason} ({view}-bit view; may contain shared settings)", candidates);
        }
    }

    private static void AddRegistryKeyCandidate(
        string path,
        string view,
        RiskLevel risk,
        string reason,
        Dictionary<string, CleanupCandidate> candidates)
    {
        var matchingEntries = candidates
            .Where(pair => pair.Value.Kind == CleanupKind.RegistryKey
                && pair.Value.Target.Equals(path, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        var existing = matchingEntries.Select(x => x.Value).FirstOrDefault();
        if (existing is not null && existing.RegistryViewName == view) return;
        foreach (var entry in matchingEntries) candidates.Remove(entry.Key);

        var mergedView = existing is null || existing.RegistryViewName == view
            ? view
            : "Both";
        var mergedRisk = existing is null || risk < existing.Risk ? risk : existing.Risk;
        candidates[$"key:{path}|{mergedView}"] = new CleanupCandidate
        {
            Target = path,
            Kind = CleanupKind.RegistryKey,
            Risk = mergedRisk,
            Scope = path.StartsWith("HKEY_CURRENT_USER", StringComparison.OrdinalIgnoreCase)
                ? CleanupScope.User : CleanupScope.System,
            Reason = mergedView == "Both" ? reason + " (present in both registry views)" : reason,
            RegistryViewName = mergedView,
            IsSelected = mergedRisk == RiskLevel.Low
        };
    }

    private static IEnumerable<string> CandidateNames(InstalledApplication app)
    {
        var raw = SafeSegment(app.DisplayName);
        if (raw.Length >= 3) yield return raw;
        var withoutVersion = SafeSegment(VersionSuffixRegex().Replace(app.DisplayName, "").Trim());
        if (withoutVersion.Length >= 3 && !withoutVersion.Equals(raw, StringComparison.OrdinalIgnoreCase)) yield return withoutVersion;
    }

    private static IEnumerable<string> EvidenceRoots(InstalledApplication app)
    {
        if (TryNormalizeEvidencePath(app.InstallLocation, out var install)) yield return install;
        var icon = IconIndexRegex().Replace(app.DisplayIconPath, "").Trim().Trim('"');
        if (TryNormalizeEvidencePath(Path.GetDirectoryName(icon) ?? "", out var iconDirectory)
            && !iconDirectory.Equals(install, StringComparison.OrdinalIgnoreCase))
            yield return iconDirectory;
    }

    private static IEnumerable<string> GetExecutableNames(InstalledApplication app)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var icon = IconIndexRegex().Replace(app.DisplayIconPath, "").Trim().Trim('"');
        if (Path.GetExtension(icon).Equals(".exe", StringComparison.OrdinalIgnoreCase) && seen.Add(Path.GetFileName(icon)))
            yield return Path.GetFileName(icon);
        if (!Directory.Exists(app.InstallLocation)) yield break;
        IEnumerable<string> files;
        try { files = Directory.EnumerateFiles(app.InstallLocation, "*.exe", SearchOption.TopDirectoryOnly); }
        catch { yield break; }
        foreach (var file in files.Take(30))
            if (seen.Add(Path.GetFileName(file))) yield return Path.GetFileName(file);
    }

    internal static bool ReferencesEvidencePath(string value, IEnumerable<string> evidenceRoots)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        value = Environment.ExpandEnvironmentVariables(value)
            .Replace(@"\??\", "", StringComparison.Ordinal)
            .Replace('/', '\\');
        foreach (var root in evidenceRoots)
        {
            var index = value.IndexOf(root, StringComparison.OrdinalIgnoreCase);
            while (index >= 0)
            {
                var beforeOkay = index == 0 || value[index - 1] is '"' or '\'' or ' ' or '=' or ';';
                var end = index + root.Length;
                var afterOkay = end == value.Length || value[end] is '\\' or '/' or '"' or '\'' or ' ' or ';' or ',';
                if (beforeOkay && afterOkay) return true;
                index = value.IndexOf(root, index + 1, StringComparison.OrdinalIgnoreCase);
            }
        }
        return false;
    }

    private static bool TryNormalizeEvidencePath(string raw, out string path)
    {
        path = "";
        if (string.IsNullOrWhiteSpace(raw)) return false;
        try
        {
            path = Path.GetFullPath(Environment.ExpandEnvironmentVariables(raw.Trim().Trim('"')))
                .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var root = Path.GetPathRoot(path)?.TrimEnd(Path.DirectorySeparatorChar);
            return path.Length >= 4 && !string.Equals(path, root, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    internal static bool IsSafeSpecificPath(string rawPath)
    {
        if (string.IsNullOrWhiteSpace(rawPath)) return false;
        try
        {
            var path = Path.GetFullPath(Environment.ExpandEnvironmentVariables(rawPath)).TrimEnd(Path.DirectorySeparatorChar);
            var rawRoot = Path.GetPathRoot(path);
            if (string.IsNullOrEmpty(rawRoot) || path.Equals(rawRoot, StringComparison.OrdinalIgnoreCase)) return false;
            var root = rawRoot.TrimEnd(Path.DirectorySeparatorChar);
            if (path.Equals(root, StringComparison.OrdinalIgnoreCase)) return false;
            var forbidden = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
            }.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => Path.GetFullPath(x).TrimEnd(Path.DirectorySeparatorChar));
            return !forbidden.Contains(path, StringComparer.OrdinalIgnoreCase)
                && path.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries).Length >= 2;
        }
        catch { return false; }
    }

    private static bool RegistryPathExists(string fullPath, string viewName = "Default")
    {
        try
        {
            var (hiveName, subKey) = SplitRegistryPath(fullPath);
            using var hive = OpenHive(hiveName, viewName);
            using var key = hive.OpenSubKey(subKey);
            return key is not null;
        }
        catch { return false; }
    }

    internal static (RegistryHive Hive, string SubKey) SplitRegistryPath(string path)
    {
        var slash = path.IndexOf('\\');
        if (slash < 0) throw new ArgumentException("Registry path has no subkey.", nameof(path));
        var hiveName = path[..slash];
        var hive = hiveName.ToUpperInvariant() switch
        {
            "HKEY_LOCAL_MACHINE" or "HKLM" => RegistryHive.LocalMachine,
            "HKEY_CURRENT_USER" or "HKCU" => RegistryHive.CurrentUser,
            _ => throw new ArgumentException("Only HKLM and HKCU cleanup is supported.", nameof(path))
        };
        return (hive, path[(slash + 1)..]);
    }

    internal static RegistryKey OpenHive(RegistryHive hive, string viewName) => RegistryKey.OpenBaseKey(hive, viewName switch
    {
        "32" => RegistryView.Registry32,
        "64" => RegistryView.Registry64,
        _ => RegistryView.Default
    });

    private static IEnumerable<string> ViewsFor(RegistryHive hive) => ["64", "32"];

    private static void RemoveNestedFilesystemCandidates(Dictionary<string, CleanupCandidate> candidates)
    {
        var directories = candidates.Values
            .Where(x => x.Kind == CleanupKind.Directory)
            .Select(x => Path.GetFullPath(x.Target).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar)
            .ToArray();
        var nestedKeys = candidates
            .Where(pair => pair.Value.Kind is CleanupKind.File or CleanupKind.Directory)
            .Where(pair =>
            {
                var target = Path.GetFullPath(pair.Value.Target).TrimEnd(Path.DirectorySeparatorChar);
                return directories.Any(directory =>
                    target.StartsWith(directory, StringComparison.OrdinalIgnoreCase)
                    && !target.Equals(directory.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase));
            })
            .Select(pair => pair.Key)
            .ToArray();
        foreach (var key in nestedKeys) candidates.Remove(key);
    }

    internal static CleanupScope ClassifyFileScope(string path, string applicationRoot = "")
    {
        try
        {
            var fullPath = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar);
            if (!string.IsNullOrWhiteSpace(applicationRoot))
            {
                var fullApplicationRoot = Path.GetFullPath(applicationRoot)
                    .TrimEnd(Path.DirectorySeparatorChar);
                if (fullPath.Equals(fullApplicationRoot, StringComparison.OrdinalIgnoreCase)
                    || fullPath.StartsWith(
                        fullApplicationRoot + Path.DirectorySeparatorChar,
                        StringComparison.OrdinalIgnoreCase))
                    return CleanupScope.Application;
            }
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
                .TrimEnd(Path.DirectorySeparatorChar);
            return userProfile.Length > 0
                && (fullPath.Equals(userProfile, StringComparison.OrdinalIgnoreCase)
                    || fullPath.StartsWith(userProfile + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                ? CleanupScope.User
                : CleanupScope.System;
        }
        catch { return CleanupScope.System; }
    }

    private static string SafeSegment(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Equals("Unknown publisher", StringComparison.OrdinalIgnoreCase)) return "";
        var invalid = Path.GetInvalidFileNameChars();
        return string.Concat(value.Trim().Where(c => !invalid.Contains(c))).TrimEnd('.');
    }

    private static long GetDirectorySize(string path)
    {
        try
        {
            long total = 0;
            foreach (var file in Directory.EnumerateFiles(path, "*", new EnumerationOptions
            {
                RecurseSubdirectories = true,
                IgnoreInaccessible = true,
                AttributesToSkip = FileAttributes.ReparsePoint
            }))
            {
                try { total += new FileInfo(file).Length; } catch { }
            }
            return total;
        }
        catch { return 0; }
    }

    private static string JsonString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) ? value.ToString() : "";

    [GeneratedRegex(@"(?i)\s+(?:v(?:ersion)?\s*)?\d+(?:\.\d+){0,3}(?:\s*\([^)]*\))?$")]
    private static partial Regex VersionSuffixRegex();
    [GeneratedRegex(@",\s*-?\d+$")]
    private static partial Regex IconIndexRegex();
    [GeneratedRegex(@"[^a-z0-9._-]+")]
    private static partial Regex SlugRegex();
}
