using Microsoft.Win32;
using System.Diagnostics;
using System.Text.Json;
using UninstallMate.Models;

namespace UninstallMate.Services;

public sealed partial class AppDiscoveryService
{
    private const string UninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

    public async Task<IReadOnlyList<InstalledApplication>> DiscoverAsync(bool includeSystem, CancellationToken token)
    {
        var desktopTask = Task.Run(() => DiscoverDesktopApps(includeSystem, token), token);
        var storeTask = DiscoverStoreAppsAsync(includeSystem, token);
        var discovered = await Task.WhenAll(desktopTask, storeTask);

        return Deduplicate(discovered.SelectMany(apps => apps))
            .OrderBy(x => x.DisplayName, StringComparer.CurrentCultureIgnoreCase)
            .ToList();
    }

    internal static IEnumerable<InstalledApplication> Deduplicate(IEnumerable<InstalledApplication> applications)
    {
        var storeApps = applications.Where(x => x.Kind == ApplicationKind.MicrosoftStore)
            .GroupBy(x => x.PackageFullName.Length > 0 ? x.PackageFullName : x.Id, StringComparer.OrdinalIgnoreCase)
            .Select(ChooseBest);
        var desktopApps = applications.Where(x => x.Kind != ApplicationKind.MicrosoftStore)
            .GroupBy(BasicIdentityKey, StringComparer.OrdinalIgnoreCase)
            .SelectMany(group =>
            {
                var knownLocations = group.Select(x => NormalizeLocation(x.InstallLocation))
                    .Where(x => x.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
                return knownLocations.Length <= 1
                    ? [ChooseBest(group)]
                    : group.GroupBy(x => NormalizeLocation(x.InstallLocation), StringComparer.OrdinalIgnoreCase).Select(ChooseBest);
            });
        return desktopApps.Concat(storeApps);
    }

    private static InstalledApplication ChooseBest(IEnumerable<InstalledApplication> group) => group
        .OrderByDescending(x => x.HasUninstaller)
        .ThenByDescending(x => !string.IsNullOrWhiteSpace(x.InstallLocation))
        .ThenByDescending(x => x.EstimatedSizeBytes)
        .ThenByDescending(x => x.Scope == InstallScope.AllUsers)
        .First();

    private static string BasicIdentityKey(InstalledApplication app)
    {
        static string Normalize(string value) => WhitespaceRegex().Replace(value.Trim(), " ").ToUpperInvariant();
        return string.Join('|', Normalize(app.DisplayName), Normalize(app.Publisher), Normalize(app.Version));
    }

    internal static bool SameApplicationIdentity(InstalledApplication left, InstalledApplication right) =>
        left.Kind == right.Kind
        && BasicIdentityKey(left).Equals(BasicIdentityKey(right), StringComparison.OrdinalIgnoreCase);

    private static string NormalizeLocation(string location)
    {
        if (string.IsNullOrWhiteSpace(location)) return "";
        try { return Path.GetFullPath(location).TrimEnd(Path.DirectorySeparatorChar); }
        catch { return location.Trim().TrimEnd('\\', '/'); }
    }

    private static List<InstalledApplication> DiscoverDesktopApps(bool includeSystem, CancellationToken token)
    {
        var result = new List<InstalledApplication>();
        var locations = new[]
        {
            (RegistryHive.LocalMachine, RegistryView.Registry64, InstallScope.AllUsers, "64-bit"),
            (RegistryHive.LocalMachine, RegistryView.Registry32, InstallScope.AllUsers, "32-bit"),
            (RegistryHive.CurrentUser, RegistryView.Registry64, InstallScope.CurrentUser, "64-bit"),
            (RegistryHive.CurrentUser, RegistryView.Registry32, InstallScope.CurrentUser, "32-bit")
        };

        foreach (var (hive, view, scope, architecture) in locations)
        {
            token.ThrowIfCancellationRequested();
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var uninstall = baseKey.OpenSubKey(UninstallPath);
                if (uninstall is null) continue;
                foreach (var keyName in uninstall.GetSubKeyNames())
                {
                    token.ThrowIfCancellationRequested();
                    using var key = uninstall.OpenSubKey(keyName);
                    if (key is null) continue;
                    var name = ReadString(key, "DisplayName");
                    if (string.IsNullOrWhiteSpace(name)) continue;
                    var noRemove = ReadInt(key, "NoRemove") == 1;
                    var system = ReadInt(key, "SystemComponent") == 1
                        || ReadString(key, "ParentKeyName").Length > 0
                        || noRemove
                        || ReadString(key, "ReleaseType").Length > 0
                        || IsLikelySystemDesktopComponent(name, ReadString(key, "Publisher"));
                    if (!includeSystem && system) continue;

                    var windowsInstaller = ReadInt(key, "WindowsInstaller") == 1;
                    var hiveName = hive == RegistryHive.LocalMachine ? "HKEY_LOCAL_MACHINE" : "HKEY_CURRENT_USER";
                    var installLocation = Environment.ExpandEnvironmentVariables(ReadString(key, "InstallLocation")).Trim().Trim('"');
                    var uninstallString = ReadString(key, "UninstallString");
                    result.Add(new InstalledApplication
                    {
                        Id = $"reg:{hiveName}:{view}:{keyName}",
                        DisplayName = name.Trim(),
                        Publisher = EmptyAs(ReadString(key, "Publisher"), "Unknown publisher"),
                        Version = ReadString(key, "DisplayVersion"),
                        InstallLocation = installLocation,
                        DisplayIconPath = ResolveDesktopIconPath(
                            name, ReadString(key, "DisplayIcon"), installLocation, uninstallString),
                        UninstallString = uninstallString,
                        QuietUninstallString = ReadString(key, "QuietUninstallString"),
                        RegistryHive = hiveName,
                        RegistryKeyPath = $@"{hiveName}\{UninstallPath}\{keyName}",
                        Architecture = architecture,
                        InstallDate = ReadString(key, "InstallDate"),
                        EstimatedSizeBytes = Math.Max(0, ReadLong(key, "EstimatedSize")) * 1024,
                        Kind = windowsInstaller ? ApplicationKind.Msi : ApplicationKind.Desktop,
                        Scope = scope,
                        IsSystemComponent = system,
                        IsProtected = noRemove
                    });
                }
            }
            catch (Exception) { /* A damaged or inaccessible registry view must not stop discovery. */ }
        }
        return result;
    }

    private static async Task<List<InstalledApplication>> DiscoverStoreAppsAsync(bool includeSystem, CancellationToken token)
    {
        var script = BuildStoreDiscoveryScript();
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
        try
        {
            using var process = Process.Start(start);
            if (process is null) return [];
            using var cancellationRegistration = token.Register(() =>
            {
                try
                {
                    if (!process.HasExited) process.Kill(entireProcessTree: true);
                }
                catch { /* The process may have exited between the check and kill. */ }
            });
            var jsonTask = process.StandardOutput.ReadToEndAsync(token);
            var errorTask = process.StandardError.ReadToEndAsync(token);
            await process.WaitForExitAsync(token);
            var json = await jsonTask;
            _ = await errorTask;
            if (process.ExitCode != 0) return [];
            if (string.IsNullOrWhiteSpace(json)) return [];
            using var document = JsonDocument.Parse(json);
            var elements = document.RootElement.ValueKind == JsonValueKind.Array
                ? document.RootElement.EnumerateArray().ToList()
                : [document.RootElement];
            return elements.Select(e =>
            {
                var name = GetString(e, "Name");
                var publisher = ResolvePackagePublisher(
                    GetString(e, "Publisher"), GetString(e, "PublisherDisplayName"));
                var displayName = ResolvePackageDisplayName(
                    name,
                    GetString(e, "ManifestDisplayName"),
                    GetString(e, "ShellDisplayName"),
                    GetString(e, "ApplicationDisplayName"),
                    GetString(e, "ApplicationId"),
                    GetString(e, "ApplicationExecutable"));
                var isFramework = GetBool(e, "IsFramework");
                var isResource = GetBool(e, "IsResourcePackage");
                var nonRemovable = GetBool(e, "NonRemovable");
                var hasShellEntry = GetBool(e, "HasShellEntry");
                var system = IsLikelySystemStorePackage(
                    name, publisher, GetString(e, "SignatureKindText"), isFramework, isResource, nonRemovable, hasShellEntry);
                var installLocation = GetString(e, "InstallLocation");
                var relativeLogo = GetString(e, "ApplicationLogo");
                if (string.IsNullOrWhiteSpace(relativeLogo)) relativeLogo = GetString(e, "ApplicationLargeLogo");
                return new InstalledApplication
                {
                    Id = "appx:" + GetString(e, "PackageFullName"),
                    DisplayName = displayName,
                    Publisher = EmptyAs(publisher, "Microsoft Store"),
                    Version = GetString(e, "Version"),
                    InstallLocation = installLocation,
                    DisplayIconPath = ResolvePackageLogoPath(
                        installLocation, relativeLogo),
                    PackageFullName = GetString(e, "PackageFullName"),
                    PackageFamilyName = GetString(e, "PackageFamilyName"),
                    Architecture = GetString(e, "Architecture"),
                    Kind = ApplicationKind.MicrosoftStore,
                    Scope = InstallScope.CurrentUser,
                    IsSystemComponent = system,
                    IsProtected = nonRemovable
                };
            }).Where(x => !string.IsNullOrWhiteSpace(x.DisplayName) && (includeSystem || !x.IsSystemComponent)).ToList();
        }
        catch (OperationCanceledException) { throw; }
        catch { return []; }
    }

    private static string ReadString(RegistryKey key, string name) => Convert.ToString(key.GetValue(name)) ?? "";
    private static int ReadInt(RegistryKey key, string name) => int.TryParse(Convert.ToString(key.GetValue(name)), out var value) ? value : 0;
    private static long ReadLong(RegistryKey key, string name) => long.TryParse(Convert.ToString(key.GetValue(name)), out var value) ? value : 0;
    private static string GetString(JsonElement e, string name) => e.TryGetProperty(name, out var p) ? p.ToString() : "";
    private static bool GetBool(JsonElement e, string name) => e.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.True;
    private static string EmptyAs(string value, string fallback) => string.IsNullOrWhiteSpace(value) ? fallback : value;

    internal static bool IsLikelySystemDesktopComponent(string name, string publisher)
    {
        var text = (name + " " + publisher).ToLowerInvariant();
        var dependencyTerms = new[]
        {
            " driver", "driver ", "runtime", "redistributable", "framework", " sdk", "firmware",
            "chipset", "physx", "opencl", "vulkan", "webview2", "update service"
        };
        if (dependencyTerms.Any(text.Contains)) return true;

        var hardwareVendor = new[]
        {
            "nvidia", "intel", "realtek", "advanced micro devices", "amd ", "asustek", "asus",
            "dell", "lenovo", "hewlett-packard", "hp inc", "qualcomm", "synaptics", "thunderbolt"
        }.Any(text.Contains);
        if (!hardwareVendor) return false;
        return new[] { "control", "audio", "graphics", "display", "monitor", "assistant", "service", "component", "extension", "hotplug" }
            .Any(text.Contains);
    }

    internal static bool IsLikelySystemStorePackage(
        string name,
        string publisher,
        string signatureKind,
        bool isFramework,
        bool isResourcePackage,
        bool nonRemovable,
        bool hasShellEntry = true)
    {
        if (isFramework || isResourcePackage || nonRemovable
            || signatureKind.Equals("System", StringComparison.OrdinalIgnoreCase)) return true;
        if (!hasShellEntry) return true;

        var loweredName = name.ToLowerInvariant();
        var loweredPublisher = publisher.ToLowerInvariant();
        if (signatureKind.Equals("Developer", StringComparison.OrdinalIgnoreCase)
            && loweredPublisher.Contains("microsoft")) return true;

        var infrastructurePrefixes = new[]
        {
            "microsoft.net.native", "microsoft.vclibs", "microsoft.ui.xaml", "microsoft.windowsappruntime",
            "microsoft.services.store", "microsoft.aad.", "microsoft.accountscontrol", "microsoft.bioenrollment",
            "microsoft.creddialoghost", "microsoft.lockapp", "microsoft.sechealthui", "microsoft.win32webviewhost",
            "microsoftwindows.client", "microsoft.windows.startmenuexperiencehost", "microsoft.windows.shell"
        };
        if (infrastructurePrefixes.Any(loweredName.StartsWith)) return true;

        var inboxPackages = new[]
        {
            "microsoft.windowsstore", "microsoft.windowscalculator", "microsoft.windows.photos", "microsoft.paint",
            "microsoft.screensketch", "microsoft.gethelp", "microsoft.getstarted", "microsoft.windowsnotepad"
        };
        if (inboxPackages.Contains(loweredName, StringComparer.OrdinalIgnoreCase)) return true;

        if (loweredName.StartsWith("appup.")) return true;
        var hardwareIdentity = new[]
        {
            "nvidia", "intel", "realtek", "thunderbolt", "asus", "dolby", "dts", "nahimic", "radeon"
        }.Any(loweredName.Contains);
        return hardwareIdentity && new[]
        {
            "control", "audio", "graphics", "display", "monitor", "assistant", "service", "component", "extension", "hotplug"
        }.Any(loweredName.Contains);
    }

    internal static string BuildStoreDiscoveryScript() =>
        "$ProgressPreference='SilentlyContinue'; " +
        "$shellNames=@{}; " +
        "try { $appsFolder=(New-Object -ComObject Shell.Application).Namespace('shell:AppsFolder'); " +
        "foreach($item in $appsFolder.Items()) { $path=[string]$item.Path; $bang=$path.IndexOf('!'); " +
        "if($bang -gt 0) { $family=$path.Substring(0,$bang); if(!$shellNames.ContainsKey($family) -or $path.EndsWith('!App')) { $shellNames[$family]=[string]$item.Name } } } } catch {}; " +
        "Get-AppxPackage | ForEach-Object { $pkg=$_; $manifest=$null; " +
        "try { $manifest=Get-AppxPackageManifest $pkg -ErrorAction Stop } catch {}; " +
        "$application=$null; if($null -ne $manifest) { $application=$manifest.Package.Applications.Application | Select-Object -First 1 }; " +
        "$shellName=''; if($shellNames.ContainsKey($pkg.PackageFamilyName)) { $shellName=$shellNames[$pkg.PackageFamilyName] }; " +
        "[pscustomobject]@{Name=$pkg.Name;PackageFullName=$pkg.PackageFullName;PackageFamilyName=$pkg.PackageFamilyName;" +
        "Publisher=$pkg.Publisher;Version=$pkg.Version;InstallLocation=$pkg.InstallLocation;Architecture=$pkg.Architecture;" +
        "IsFramework=$pkg.IsFramework;IsResourcePackage=$pkg.IsResourcePackage;NonRemovable=$pkg.NonRemovable;" +
        "SignatureKindText=$pkg.SignatureKind.ToString();ManifestDisplayName=[string]$manifest.Package.Properties.DisplayName;" +
        "PublisherDisplayName=[string]$manifest.Package.Properties.PublisherDisplayName;ShellDisplayName=$shellName;" +
        "ApplicationDisplayName=[string]$application.VisualElements.DisplayName;ApplicationId=[string]$application.Id;" +
        "ApplicationExecutable=[string]$application.Executable;ApplicationLogo=[string]$application.VisualElements.Square44x44Logo;" +
        "ApplicationLargeLogo=[string]$application.VisualElements.Square150x150Logo;" +
        "HasShellEntry=($shellName.Length -gt 0)} } | ConvertTo-Json -Compress";

    internal static string ResolveDesktopIconPath(
        string displayName, string registeredIcon, string installLocation, string uninstallString)
    {
        var icon = Environment.ExpandEnvironmentVariables(registeredIcon).Trim();
        if (icon.Length > 0) return icon;
        try
        {
            if (Directory.Exists(installLocation))
            {
                var nameWords = new string(VersionSuffixRegex().Replace(displayName, " ")
                    .Where(char.IsLetterOrDigit).ToArray());
                var executable = Directory.EnumerateFiles(installLocation, "*.exe", SearchOption.TopDirectoryOnly)
                    .Take(60)
                    .OrderBy(path => ExecutableIconScore(path, nameWords))
                    .ThenBy(path => path.Length)
                    .FirstOrDefault();
                if (executable is not null) return executable;
            }
            if (CommandLineParser.TrySplit(uninstallString, out var uninstaller, out _))
            {
                uninstaller = Environment.ExpandEnvironmentVariables(uninstaller);
                if (File.Exists(uninstaller)) return uninstaller;
            }
        }
        catch { }
        return "";
    }

    private static int ExecutableIconScore(string path, string normalizedDisplayName)
    {
        var name = Path.GetFileNameWithoutExtension(path);
        var normalized = new string(name.Where(char.IsLetterOrDigit).ToArray());
        if (normalizedDisplayName.Length > 2
            && (normalized.Contains(normalizedDisplayName, StringComparison.OrdinalIgnoreCase)
                || normalizedDisplayName.Contains(normalized, StringComparison.OrdinalIgnoreCase))) return 0;
        var lowered = name.ToLowerInvariant();
        if (new[] { "unins", "uninstall", "update", "helper", "service", "crash", "report" }.Any(lowered.Contains)) return 3;
        return 1;
    }

    internal static string ResolvePackageLogoPath(string installLocation, string relativeLogo)
    {
        if (string.IsNullOrWhiteSpace(installLocation) || string.IsNullOrWhiteSpace(relativeLogo)) return "";
        try
        {
            var root = Path.GetFullPath(installLocation).TrimEnd(Path.DirectorySeparatorChar);
            var relative = relativeLogo.Replace('\\', Path.DirectorySeparatorChar)
                .Replace('/', Path.DirectorySeparatorChar)
                .TrimStart(Path.DirectorySeparatorChar);
            var declared = Path.GetFullPath(Path.Combine(root, relative));
            if (!declared.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) return "";
            if (File.Exists(declared)) return declared;

            var directory = Path.GetDirectoryName(declared);
            if (directory is null || !Directory.Exists(directory)) return "";
            var stem = Path.GetFileNameWithoutExtension(declared);
            var extension = Path.GetExtension(declared);
            return Directory.EnumerateFiles(directory, stem + "*" + extension, SearchOption.TopDirectoryOnly)
                .OrderBy(LogoVariantScore)
                .ThenBy(x => x.Length)
                .FirstOrDefault() ?? "";
        }
        catch { return ""; }
    }

    private static int LogoVariantScore(string path)
    {
        var name = Path.GetFileName(path);
        if (name.Contains("targetsize-48", StringComparison.OrdinalIgnoreCase)) return 0;
        if (name.Contains("targetsize-44", StringComparison.OrdinalIgnoreCase)) return 1;
        if (name.Contains("scale-200", StringComparison.OrdinalIgnoreCase)) return 2;
        if (name.Contains("scale-100", StringComparison.OrdinalIgnoreCase)) return 3;
        return 4;
    }

    internal static string ResolvePackageDisplayName(
        string identityName,
        string manifestName,
        string shellName,
        string applicationDisplayName = "",
        string applicationId = "",
        string applicationExecutable = "")
    {
        if (IsResolvedDisplayText(shellName)) return shellName.Trim();
        if (IsResolvedDisplayText(manifestName)) return manifestName.Trim();
        if (IsResolvedDisplayText(applicationDisplayName)) return applicationDisplayName.Trim();

        foreach (var fallback in new[] { applicationId, Path.GetFileNameWithoutExtension(applicationExecutable) })
        {
            var friendly = HumanizePackageIdentity(fallback);
            if (friendly.Length > 0) return friendly;
        }

        var identityFallback = HumanizePackageIdentity(identityName);
        return identityFallback.Length > 0 ? identityFallback : "Windows system component";
    }

    private static string HumanizePackageIdentity(string identity)
    {
        if (string.IsNullOrWhiteSpace(identity)
            || Guid.TryParse(identity.Trim(), out _)
            || GuidLikeRegex().IsMatch(identity.Trim())) return "";
        var segments = identity.Split('.', StringSplitOptions.RemoveEmptyEntries);
        var segment = segments.LastOrDefault() ?? identity;
        if (segment.Equals("App", StringComparison.OrdinalIgnoreCase)
            || segment.Equals("Application", StringComparison.OrdinalIgnoreCase)) return "";
        if (segments.Length > 2 && (NumericPackageSegmentRegex().IsMatch(segment)
            || segment.Equals("Framework", StringComparison.OrdinalIgnoreCase)
            || segment.Equals("Runtime", StringComparison.OrdinalIgnoreCase)
            || segment.Equals("Desktop", StringComparison.OrdinalIgnoreCase)))
            segment = string.Join(' ', segments.Skip(1));
        segment = segment.Replace('_', ' ');
        var spaced = AcronymBoundaryRegex().Replace(CamelCaseBoundaryRegex().Replace(segment, "$1 $2"), "$1 $2");
        return WhitespaceRegex().Replace(spaced, " ").Trim();
    }

    internal static string ResolvePackagePublisher(string certificatePublisher, string manifestPublisher)
    {
        if (IsResolvedDisplayText(manifestPublisher)) return manifestPublisher.Trim();
        var match = PublisherCnRegex().Match(certificatePublisher);
        if (!match.Success) return EmptyAs(certificatePublisher, "Microsoft Store");
        var commonName = match.Groups[1].Value.Trim();
        return Guid.TryParse(commonName, out _) || GuidLikeRegex().IsMatch(commonName)
            ? "Microsoft Store"
            : EmptyAs(commonName, "Microsoft Store");
    }

    private static bool IsResolvedDisplayText(string value) =>
        !string.IsNullOrWhiteSpace(value)
        && !value.StartsWith("ms-resource:", StringComparison.OrdinalIgnoreCase)
        && !value.StartsWith("@{", StringComparison.OrdinalIgnoreCase);

    [System.Text.RegularExpressions.GeneratedRegex(@"\s+")]
    private static partial System.Text.RegularExpressions.Regex WhitespaceRegex();
    [System.Text.RegularExpressions.GeneratedRegex(@"([a-z0-9])([A-Z])")]
    private static partial System.Text.RegularExpressions.Regex CamelCaseBoundaryRegex();
    [System.Text.RegularExpressions.GeneratedRegex(@"([A-Z]+)([A-Z][a-z])")]
    private static partial System.Text.RegularExpressions.Regex AcronymBoundaryRegex();
    [System.Text.RegularExpressions.GeneratedRegex(@"(?:^|,)\s*CN=([^,]+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase)]
    private static partial System.Text.RegularExpressions.Regex PublisherCnRegex();
    [System.Text.RegularExpressions.GeneratedRegex(@"^[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}$", System.Text.RegularExpressions.RegexOptions.IgnoreCase)]
    private static partial System.Text.RegularExpressions.Regex GuidLikeRegex();
    [System.Text.RegularExpressions.GeneratedRegex(@"^\d+(?:\.\d+)*$")]
    private static partial System.Text.RegularExpressions.Regex NumericPackageSegmentRegex();
    [System.Text.RegularExpressions.GeneratedRegex(@"\s+(?:version\s*)?\d+(?:\.\d+)*(?:\s*\([^)]*\))?$", System.Text.RegularExpressions.RegexOptions.IgnoreCase)]
    private static partial System.Text.RegularExpressions.Regex VersionSuffixRegex();
}
