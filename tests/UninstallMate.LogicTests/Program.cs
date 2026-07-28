using System.Runtime.InteropServices;
using Microsoft.Win32;
using UninstallMate.Models;
using UninstallMate.Services;

var tests = new List<(string Name, Action Run)>
{
    ("MSI /I becomes /X", () => Equal("MsiExec.exe /X{12345678-1234-1234-1234-123456789012}",
        UninstallService.NormalizeMsiCommand("MsiExec.exe /I{12345678-1234-1234-1234-123456789012}"))),
    ("Existing MSI /X is unchanged", () => Equal("msiexec /X {12345678-1234-1234-1234-123456789012}",
        UninstallService.NormalizeMsiCommand("msiexec /X {12345678-1234-1234-1234-123456789012}"))),
    ("Nonzero exit is accepted when app registration is gone", () =>
        True(UninstallService.InterpretDesktopExit(1, registrationStillPresent: false).Success)),
    ("Nonzero exit remains a failure while app is registered", () =>
        False(UninstallService.InterpretDesktopExit(1, registrationStillPresent: true).Success)),
    ("Store removal script safely escapes package identity", () =>
        True(UninstallService.BuildStoreRemovalScript("Publisher.O'Brien_1.0_x64").Contains("O''Brien", StringComparison.Ordinal))),
    ("Non-MSI command is unchanged", () => Equal("C:\\Tools\\remove.exe /uninstall",
        UninstallService.NormalizeMsiCommand("C:\\Tools\\remove.exe /uninstall"))),
    ("Unquoted executable path is recovered", () =>
    {
        True(CommandLineParser.TrySplit("C:\\Program Files\\Example\\uninstall.exe /remove /user", out var file, out var args));
        Equal("C:\\Program Files\\Example\\uninstall.exe", file);
        Equal("/remove /user", args);
    }),
    ("Install-path evidence matches a contained executable", () =>
        True(CleanupScanner.ReferencesEvidencePath(
            "\"C:\\Program Files\\Acme\\bin\\agent.exe\" --startup",
            ["C:\\Program Files\\Acme"]))),
    ("Install-path evidence rejects a similarly prefixed folder", () =>
        False(CleanupScanner.ReferencesEvidencePath(
            "\"C:\\Program Files\\AcmeOther\\agent.exe\"",
            ["C:\\Program Files\\Acme"]))),
    ("PATH cleanup removes only the app's segments", () =>
        Equal(
            @"C:\Windows;C:\Tools",
            CleanupService.RemoveEnvironmentPathSegments(
                @"C:\Windows;C:\Program Files\Acme;C:\Program Files\Acme\bin;C:\Tools",
                @"C:\Program Files\Acme"))),
    ("Duplicate registry views collapse to one app", () =>
    {
        var duplicate32 = TestApplicationWith("acme:32", "1.0", @"C:\Program Files\Acme", "32-bit");
        var duplicate64 = TestApplicationWith("acme:64", "1.0", @"C:\Program Files\Acme", "64-bit");
        EqualInt(1, AppDiscoveryService.Deduplicate([duplicate32, duplicate64]).Count());
    }),
    ("Different app versions remain separate", () =>
        EqualInt(2, AppDiscoveryService.Deduplicate([
            TestApplicationWith("acme:1", "1.0", @"C:\Program Files\Acme 1"),
            TestApplicationWith("acme:2", "2.0", @"C:\Program Files\Acme 2")]).Count())),
    ("Declared and OEM Store components are classified as system", () =>
    {
        True(AppDiscoveryService.IsLikelySystemStorePackage(
            "Microsoft.Windows.StartMenuExperienceHost", "CN=Microsoft Corporation", "System", false, false, true));
        True(AppDiscoveryService.IsLikelySystemStorePackage(
            "AppUp.IntelGraphicsExperience", "CN=Intel", "Store", false, false, false));
        True(AppDiscoveryService.IsLikelySystemStorePackage(
            "aimgr", "CN=Microsoft Corporation", "Developer", false, false, false));
    }),
    ("Ordinary Store applications remain visible", () =>
        False(AppDiscoveryService.IsLikelySystemStorePackage(
            "OpenAI.Codex", "CN=OpenAI", "Store", false, false, false))),
    ("Store identities resolve to human-facing names", () =>
    {
        Equal("Microsoft Clipchamp", AppDiscoveryService.ResolvePackageDisplayName(
            "Clipchamp.Clipchamp", "ms-resource:Clipchamp/AppName", "Microsoft Clipchamp"));
        Equal("Dolby Digital Plus decoder for PC OEMs", AppDiscoveryService.ResolvePackageDisplayName(
            "DolbyLaboratories.DolbyDigitalPlusDecoderOEM", "Dolby Digital Plus decoder for PC OEMs", ""));
        Equal("Dolby Digital Plus Decoder OEM", AppDiscoveryService.ResolvePackageDisplayName(
            "DolbyLaboratories.DolbyDigitalPlusDecoderOEM", "ms-resource:AppName", ""));
        Equal("App Resolver UX", AppDiscoveryService.ResolvePackageDisplayName(
            "E2A4F912-2574-4A75-9BB0-0D023378592B", "ms-resource:AppxManifest_DisplayName", "",
            "ms-resource:AppxManifest_DisplayName", "Microsoft.Windows.AppResolverUX", "AppResolverUX.exe"));
        Equal("Add Suggested Folders To Library Dialog", AppDiscoveryService.ResolvePackageDisplayName(
            "F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE", "ms-resource:AppxManifest_DisplayName", "",
            "ms-resource:AppxManifest_DisplayName", "App", "AddSuggestedFoldersToLibraryDialog.exe"));
        Equal("Windows system component", AppDiscoveryService.ResolvePackageDisplayName(
            "F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE", "ms-resource:AppxManifest_DisplayName", ""));
    }),
    ("Packaged app logo resolves to the preferred asset variant", () =>
    {
        var root = Path.Combine(Path.GetTempPath(), "UninstallMateTests", Guid.NewGuid().ToString("N"));
        var assets = Path.Combine(root, "Assets");
        Directory.CreateDirectory(assets);
        var logo = Path.Combine(assets, "AppLogo.targetsize-48_altform-unplated.png");
        File.WriteAllText(logo, "test");
        try
        {
            Equal(logo, AppDiscoveryService.ResolvePackageLogoPath(root, @"Assets\AppLogo.png"));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }),
    ("Desktop app icon falls back to its primary executable", () =>
    {
        var root = Path.Combine(Path.GetTempPath(), "UninstallMateTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var primary = Path.Combine(root, "Acme.exe");
        File.WriteAllText(primary, "test");
        File.WriteAllText(Path.Combine(root, "uninstall.exe"), "test");
        try
        {
            Equal(primary, AppDiscoveryService.ResolveDesktopIconPath("Acme", "", root, ""));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }),
    ("Certificate publishers resolve to readable text", () =>
    {
        Equal("Dolby Laboratories", AppDiscoveryService.ResolvePackagePublisher(
            "CN=58D26209-1D57-48C2-B403-B65500000000", "Dolby Laboratories"));
        Equal("Microsoft Store", AppDiscoveryService.ResolvePackagePublisher(
            "CN=58D26209-1D57-48C2-B403-B65500000000", "ms-resource:Publisher"));
    }),
    ("Drivers are system components but ordinary desktop apps are not", () =>
    {
        True(AppDiscoveryService.IsLikelySystemDesktopComponent("NVIDIA Graphics Driver 610.62", "NVIDIA Corporation"));
        True(AppDiscoveryService.IsLikelySystemDesktopComponent("ASUS Smart Display Control", "ASUSTeK COMPUTER INC."));
        False(AppDiscoveryService.IsLikelySystemDesktopComponent("7-Zip 25.00 (x64)", "Igor Pavlov"));
    }),
    ("Application, user, and system leftovers are classified separately", () =>
    {
        EqualScope(CleanupScope.User, CleanupScanner.ClassifyFileScope(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "AppData", "Local", "Acme")));
        var applicationRoot = Path.Combine(Path.GetTempPath(), "UninstallMateTests", "Acme");
        EqualScope(CleanupScope.Application, CleanupScanner.ClassifyFileScope(
            Path.Combine(applicationRoot, "bin", "app.exe"), applicationRoot));
        var systemPath = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Acme")
            : "/opt/Acme";
        EqualScope(CleanupScope.System, CleanupScanner.ClassifyFileScope(systemPath));
    }),
    ("Permanent cleanup creates no recovery payload", () =>
    {
        var root = Path.Combine(Path.GetTempPath(), "UninstallMateTests", Guid.NewGuid().ToString("N"));
        var target = Path.Combine(root, "payload", "AcmeCache");
        Directory.CreateDirectory(target);
        File.WriteAllText(Path.Combine(target, "cache.bin"), "test");
        try
        {
            var service = new CleanupService(Path.Combine(root, "app-data"));
            var app = TestApplication();
            var candidate = TestDirectoryCandidate(target);
            var (report, session) = service.ExecuteAsync(app, [candidate], false, null, CancellationToken.None).GetAwaiter().GetResult();
            False(Directory.Exists(target));
            Equal("", report.Items.Single().RecoverySource);
            True(File.Exists(Path.Combine(session, "cleanup-report.json")));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }),
    ("Quarantined cleanup can be restored", () =>
    {
        var root = Path.Combine(Path.GetTempPath(), "UninstallMateTests", Guid.NewGuid().ToString("N"));
        var target = Path.Combine(root, "payload", "AcmeCache");
        Directory.CreateDirectory(target);
        File.WriteAllText(Path.Combine(target, "cache.bin"), "test");
        try
        {
            var service = new CleanupService(Path.Combine(root, "app-data"));
            var (report, session) = service.ExecuteAsync(
                TestApplication(), [TestDirectoryCandidate(target)], true, null, CancellationToken.None).GetAwaiter().GetResult();
            False(Directory.Exists(target));
            True(Directory.Exists(report.Items.Single().RecoverySource));
            Equal(session, QuarantineService.FindLatestRestorableSession(
                Path.Combine(root, "app-data", "Quarantine")) ?? "");
            var restored = QuarantineService.RestoreAsync(session, CancellationToken.None).GetAwaiter().GetResult();
            EqualInt(1, restored.Restored);
            EqualInt(0, restored.Failed);
            True(File.Exists(Path.Combine(target, "cache.bin")));
            True(QuarantineService.FindLatestRestorableSession(
                Path.Combine(root, "app-data", "Quarantine")) is null);
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    })
};

if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
{
    tests.Add(("Quoted executable is parsed", () =>
    {
        True(CommandLineParser.TrySplit("\"C:\\Program Files\\Example\\uninstall.exe\" /remove", out var file, out var args));
        Equal("C:\\Program Files\\Example\\uninstall.exe", file);
        Equal("/remove", args);
    }));
    tests.Add(("Missing Store package is verified as already absent", () =>
    {
        var result = UninstallService.RunPowerShellAsync(
            UninstallService.BuildStoreRemovalScript("UninstallMate.NonexistentPackage_0.0.0.0_x64__doesnotexist"),
            CancellationToken.None).GetAwaiter().GetResult();
        EqualInt(0, result.ExitCode);
    }));
    tests.Add(("Equivalent uninstall registrations are all offered for cleanup", () =>
    {
        const string uninstallRoot = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        var suffix = Guid.NewGuid().ToString("N");
        var displayName = "UninstallMate Registration Test " + suffix;
        var key64 = "UninstallMateTest64-" + suffix;
        var key32 = "UninstallMateTest32-" + suffix;
        try
        {
            CreateTestRegistration(RegistryView.Registry64, uninstallRoot, key64, displayName);
            CreateTestRegistration(RegistryView.Registry32, uninstallRoot, key32, displayName);
            var app = new InstalledApplication
            {
                Id = "reg-test:" + suffix,
                DisplayName = displayName,
                Publisher = "UninstallMate Tests",
                Version = "1.0",
                Architecture = "64-bit",
                RegistryKeyPath = $@"HKEY_CURRENT_USER\{uninstallRoot}\{key64}"
            };
            var results = new CleanupScanner().ScanAsync(app, CancellationToken.None).GetAwaiter().GetResult();
            EqualInt(2, results.Count(x => x.Reason.Contains("registered uninstall entry", StringComparison.OrdinalIgnoreCase)
                || x.Reason.Contains("Duplicate registration", StringComparison.OrdinalIgnoreCase)));
        }
        finally
        {
            DeleteTestRegistration(RegistryView.Registry64, uninstallRoot, key64);
            DeleteTestRegistration(RegistryView.Registry32, uninstallRoot, key32);
        }
    }));
    tests.Add(("Live desktop registration is detected before leftover scanning", () =>
    {
        const string uninstallRoot = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        var suffix = Guid.NewGuid().ToString("N");
        var keyName = "UninstallMateLiveScanTest-" + suffix;
        var app = new InstalledApplication
        {
            Id = "live-scan-test:" + suffix,
            DisplayName = "UninstallMate Live Scan Test " + suffix,
            Publisher = "UninstallMate Tests",
            Version = "1.0",
            Architecture = "64-bit",
            UninstallString = @"C:\UninstallMateTests\uninstall.exe",
            RegistryKeyPath = $@"HKEY_CURRENT_USER\{uninstallRoot}\{keyName}"
        };
        try
        {
            CreateTestRegistration(RegistryView.Registry64, uninstallRoot, keyName, app.DisplayName);
            True(new UninstallService().IsApplicationRegisteredAsync(app, CancellationToken.None)
                .GetAwaiter().GetResult() == true);
            DeleteTestRegistration(RegistryView.Registry64, uninstallRoot, keyName);
            True(new UninstallService().IsApplicationRegisteredAsync(app, CancellationToken.None)
                .GetAwaiter().GetResult() == false);
        }
        finally
        {
            DeleteTestRegistration(RegistryView.Registry64, uninstallRoot, keyName);
        }
    }));
    tests.Add(("Shared startup registry values appear only once", () =>
    {
        const string runPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        var suffix = Guid.NewGuid().ToString("N");
        var valueName = "UninstallMateRunTest-" + suffix;
        var installRoot = Path.Combine(Path.GetTempPath(), "UninstallMateTests", suffix);
        Directory.CreateDirectory(installRoot);
        try
        {
            using (var hive = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64))
            using (var key = hive.CreateSubKey(runPath))
                key.SetValue(valueName, $"\"{Path.Combine(installRoot, "app.exe")}\" --startup");

            var app = TestApplicationWith("run-test:" + suffix, "1.0", installRoot);
            var matches = new CleanupScanner().ScanAsync(app, CancellationToken.None).GetAwaiter().GetResult()
                .Where(x => x.Kind == CleanupKind.RegistryValue && x.Auxiliary == valueName).ToArray();
            EqualInt(1, matches.Length);
            Equal("Both", matches[0].RegistryViewName);
        }
        finally
        {
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                using var hive = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, view);
                using var key = hive.OpenSubKey(runPath, writable: true);
                key?.DeleteValue(valueName, throwOnMissingValue: false);
            }
            if (Directory.Exists(installRoot)) Directory.Delete(installRoot, true);
        }
    }));
    tests.Add(("Discovery excludes classified system components when requested", () =>
    {
        var service = new AppDiscoveryService();
        var all = service.DiscoverAsync(includeSystem: true, CancellationToken.None).GetAwaiter().GetResult();
        var filtered = service.DiscoverAsync(includeSystem: false, CancellationToken.None).GetAwaiter().GetResult();
        True(all.Any(x => x.IsSystemComponent));
        False(filtered.Any(x => x.IsSystemComponent));
        True(filtered.Count < all.Count);
    }));
    tests.Add(("Discovered Store apps contain no raw resource or certificate labels", () =>
    {
        var packages = new AppDiscoveryService().DiscoverAsync(includeSystem: true, CancellationToken.None)
            .GetAwaiter().GetResult().Where(x => x.Kind == ApplicationKind.MicrosoftStore).ToArray();
        False(packages.Any(x => x.DisplayName.StartsWith("ms-resource:", StringComparison.OrdinalIgnoreCase)));
        False(packages.Any(x => x.Publisher.StartsWith("CN=", StringComparison.OrdinalIgnoreCase)));
    }));
    tests.Add(("Discovered Store icon sources resolve to existing files", () =>
    {
        var packages = new AppDiscoveryService().DiscoverAsync(includeSystem: true, CancellationToken.None)
            .GetAwaiter().GetResult().Where(x => x.Kind == ApplicationKind.MicrosoftStore).ToArray();
        var icons = packages.Where(x => x.DisplayIconPath.Length > 0).Select(x => x.DisplayIconPath).ToArray();
        True(icons.Length > 0);
        False(icons.Any(path => !File.Exists(path)));
    }));
}

var failures = 0;
foreach (var (name, run) in tests)
{
    try { run(); Console.WriteLine($"PASS  {name}"); }
    catch (Exception ex) { failures++; Console.Error.WriteLine($"FAIL  {name}: {ex.Message}"); }
}
Console.WriteLine($"{tests.Count - failures}/{tests.Count} logic tests passed.");
return failures;

static void Equal(string expected, string actual)
{
    if (!string.Equals(expected, actual, StringComparison.Ordinal))
        throw new Exception($"Expected '{expected}', got '{actual}'.");
}

static void EqualInt(int expected, int actual)
{
    if (expected != actual) throw new Exception($"Expected '{expected}', got '{actual}'.");
}

static void True(bool value)
{
    if (!value) throw new Exception("Expected true.");
}

static void False(bool value)
{
    if (value) throw new Exception("Expected false.");
}

static InstalledApplication TestApplication() => TestApplicationWith("test:acme", "", @"C:\Program Files\Acme");

static InstalledApplication TestApplicationWith(string id, string version, string location, string architecture = "64-bit") => new()
{
    Id = id,
    DisplayName = "Acme Test App",
    Publisher = "Acme Ltd",
    Version = version,
    InstallLocation = location,
    Architecture = architecture
};

static void EqualScope(CleanupScope expected, CleanupScope actual)
{
    if (expected != actual) throw new Exception($"Expected '{expected}', got '{actual}'.");
}

static void CreateTestRegistration(RegistryView view, string root, string keyName, string displayName)
{
    using var hive = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, view);
    using var key = hive.CreateSubKey($@"{root}\{keyName}");
    key.SetValue("DisplayName", displayName);
    key.SetValue("Publisher", "UninstallMate Tests");
    key.SetValue("DisplayVersion", "1.0");
}

static void DeleteTestRegistration(RegistryView view, string root, string keyName)
{
    try
    {
        using var hive = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, view);
        using var key = hive.OpenSubKey(root, writable: true);
        key?.DeleteSubKeyTree(keyName, throwOnMissingSubKey: false);
    }
    catch { }
}

static CleanupCandidate TestDirectoryCandidate(string target) => new()
{
    Target = target,
    Kind = CleanupKind.Directory,
    Risk = RiskLevel.Low,
    Reason = "Test candidate",
    IsSelected = true
};
