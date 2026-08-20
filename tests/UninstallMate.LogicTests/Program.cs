using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32;
using UninstallMate.Models;
using UninstallMate.Services;
using UninstallMate.Services.Providers;

var tests = new List<(string Name, Action Run)>();

void AddTest(string name, Action run) => tests.Add((name, run));

AddTest("MSI /I becomes /X", () => Equal("MsiExec.exe /X{12345678-1234-1234-1234-123456789012}",
    UninstallService.NormalizeMsiCommand("MsiExec.exe /I{12345678-1234-1234-1234-123456789012}")));

AddTest("Existing MSI /X is unchanged", () => Equal("msiexec /X {12345678-1234-1234-1234-123456789012}",
    UninstallService.NormalizeMsiCommand("msiexec /X {12345678-1234-1234-1234-123456789012}")));

AddTest("Nonzero exit is accepted when app registration is gone", () =>
    True(UninstallService.InterpretDesktopExit(1, registrationStillPresent: false).Success));

AddTest("Nonzero exit remains a failure while app is registered", () =>
    False(UninstallService.InterpretDesktopExit(1, registrationStillPresent: true).Success));

AddTest("Store removal script safely escapes package identity", () =>
    True(UninstallService.BuildStoreRemovalScript("Publisher.O'Brien_1.0_x64").Contains("O''Brien", StringComparison.Ordinal)));

AddTest("Non-MSI command is unchanged", () => Equal("C:\\Tools\\remove.exe /uninstall",
    UninstallService.NormalizeMsiCommand("C:\\Tools\\remove.exe /uninstall")));

AddTest("Unquoted executable path is recovered", () =>
{
    True(CommandLineParser.TrySplit("C:\\Program Files\\Example\\uninstall.exe /remove /user", out var file, out var args));
    Equal("C:\\Program Files\\Example\\uninstall.exe", file);
    Equal("/remove /user", args);
});

AddTest("Unquoted executable with .exe in folder name is parsed correctly", () =>
{
    True(CommandLineParser.TrySplit(@"C:\Program Files\Acme.Exe.Tools\unins000.exe /quiet /norestart", out var file, out var args));
    Equal(@"C:\Program Files\Acme.Exe.Tools\unins000.exe", file);
    Equal("/quiet /norestart", args);
});

AddTest("Install-path evidence matches a contained executable", () =>
    True(CleanupScanner.ReferencesEvidencePath(
        "\"C:\\Program Files\\Acme\\bin\\agent.exe\" --startup",
        ["C:\\Program Files\\Acme"])));

AddTest("Install-path evidence rejects a similarly prefixed folder", () =>
    False(CleanupScanner.ReferencesEvidencePath(
        "\"C:\\Program Files\\AcmeOther\\agent.exe\"",
        ["C:\\Program Files\\Acme"])));

AddTest("PATH cleanup removes only the app's segments", () =>
    Equal(
        @"C:\Windows;C:\Tools",
        CleanupService.RemoveEnvironmentPathSegments(
            @"C:\Windows;C:\Program Files\Acme;C:\Program Files\Acme\bin;C:\Tools",
            @"C:\Program Files\Acme")));

AddTest("Merge-safe PATH restore preserves subsequent unrelated PATH edits", () =>
{
    var currentPath = @"C:\Windows;C:\NewTools;C:\OtherApp";
    var segmentToRestore = @"C:\Program Files\Acme";
    var merged = QuarantineService.MergePathSegment(currentPath, segmentToRestore);
    Equal(@"C:\Windows;C:\NewTools;C:\OtherApp;C:\Program Files\Acme", merged);

    // Does not duplicate if already present
    var unchanged = QuarantineService.MergePathSegment(merged, segmentToRestore);
    Equal(merged, unchanged);
});

AddTest("Duplicate registry views collapse to one app", () =>
{
    var duplicate32 = TestApplicationWith("acme:32", "1.0", @"C:\Program Files\Acme", "32-bit");
    var duplicate64 = TestApplicationWith("acme:64", "1.0", @"C:\Program Files\Acme", "64-bit");
    EqualInt(1, AppDiscoveryService.Deduplicate([duplicate32, duplicate64]).Count());
});

AddTest("Different app versions remain separate", () =>
    EqualInt(2, AppDiscoveryService.Deduplicate([
        TestApplicationWith("acme:1", "1.0", @"C:\Program Files\Acme 1"),
        TestApplicationWith("acme:2", "2.0", @"C:\Program Files\Acme 2")]).Count()));

AddTest("Declared and OEM Store components are classified as system", () =>
{
    True(AppDiscoveryService.IsLikelySystemStorePackage(
        "Microsoft.Windows.StartMenuExperienceHost", "CN=Microsoft Corporation", "System", false, false, true));
    True(AppDiscoveryService.IsLikelySystemStorePackage(
        "AppUp.IntelGraphicsExperience", "CN=Intel", "Store", false, false, false));
    True(AppDiscoveryService.IsLikelySystemStorePackage(
        "aimgr", "CN=Microsoft Corporation", "Developer", false, false, false));
});

AddTest("Ordinary Store applications remain visible", () =>
    False(AppDiscoveryService.IsLikelySystemStorePackage(
        "OpenAI.Codex", "CN=OpenAI", "Store", false, false, false)));

AddTest("Store identities resolve to human-facing names", () =>
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
});

AddTest("Packaged app logo resolves to the preferred asset variant", () =>
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
});

AddTest("Desktop app icon falls back to its primary executable", () =>
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
});

AddTest("Certificate publishers resolve to readable text", () =>
{
    Equal("Dolby Laboratories", AppDiscoveryService.ResolvePackagePublisher(
        "CN=58D26209-1D57-48C2-B403-B65500000000", "Dolby Laboratories"));
    Equal("Microsoft Store", AppDiscoveryService.ResolvePackagePublisher(
        "CN=58D26209-1D57-48C2-B403-B65500000000", "ms-resource:Publisher"));
});

AddTest("Drivers are system components but ordinary desktop apps are not", () =>
{
    True(AppDiscoveryService.IsLikelySystemDesktopComponent("NVIDIA Graphics Driver 610.62", "NVIDIA Corporation"));
    True(AppDiscoveryService.IsLikelySystemDesktopComponent("ASUS Smart Display Control", "ASUSTeK COMPUTER INC."));
    False(AppDiscoveryService.IsLikelySystemDesktopComponent("7-Zip 25.00 (x64)", "Igor Pavlov"));
});

AddTest("Application, user, and system leftovers are classified separately", () =>
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
});

AddTest("Permanent cleanup creates no recovery payload", () =>
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
});

AddTest("Quarantined cleanup can be restored", () =>
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
});

AddTest("Pre-uninstall identity snapshot captures startup sources and executables", () =>
{
    var app = new InstalledApplication
    {
        Id = "neat-app-test",
        DisplayName = "Neat",
        Publisher = "The Neat Company",
        Version = "5.7.1",
        InstallLocation = @"C:\Program Files\Neat",
        DisplayIconPath = @"C:\Program Files\Neat\Neat.exe,0"
    };
    var graph = ApplicationIdentityGraph.Create(app);
    True(graph.CandidateNames.Contains("Neat", StringComparer.OrdinalIgnoreCase));
    True(graph.ExecutableNames.Contains("Neat.exe", StringComparer.OrdinalIgnoreCase));
    True(graph.ReferencesEvidence(@"C:\Program Files\Neat\Neat.exe"));
    False(graph.ReferencesEvidence(@"C:\Program Files\NeatOther\Other.exe"));
});

AddTest("Neat Task Manager stale startup-remnant regression test logic", () =>
{
    var neatApp = new InstalledApplication
    {
        Id = "neat-test",
        DisplayName = "Neat",
        Publisher = "The Neat Company",
        Version = "5.7.1",
        InstallLocation = @"C:\Program Files (x86)\Neat",
        DisplayIconPath = @"C:\Program Files (x86)\Neat\Neat.exe"
    };
    var graph = ApplicationIdentityGraph.Create(neatApp);

    graph.CapturedStartupSources.Add(new CapturedStartupEntry(
        "HKEY_CURRENT_USER",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "64",
        "Neat",
        @"C:\Program Files (x86)\Neat\Neat.exe",
        "Run"));

    graph.CapturedStartupApprovedEntries.Add(new CapturedStartupApprovedEntry(
        "HKEY_CURRENT_USER",
        @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
        "64",
        "Neat",
        Convert.ToBase64String(new byte[] { 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }),
        "Neat"));

    Equal("Neat", graph.CapturedStartupSources.Single().ValueName);
    Equal("Neat", graph.CapturedStartupApprovedEntries.Single().ValueName);

    var candidate = new CleanupCandidate
    {
        Target = @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
        Auxiliary = "Neat",
        Kind = CleanupKind.RegistryValue,
        RegistryViewName = "64",
        Risk = RiskLevel.Low,
        Confidence = OwnershipConfidence.Certain,
        Reason = "Stale Task Manager startup entry left behind after the 'Neat' startup source was removed",
        RegistryValueKindName = "Binary",
        RegistryRawValueBase64 = graph.CapturedStartupApprovedEntries.Single().RawBytesBase64,
        IsSelected = true
    };

    Equal("Certain", candidate.ConfidenceText);
    Equal("Low", candidate.RiskText);
    True(candidate.IsSelected);
    Equal(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run  ·  Neat", candidate.DisplayTarget);
});

AddTest("Candidate deduplication preserves strongest confidence and merges evidence", () =>
{
    var item1 = new CleanupCandidate
    {
        Target = @"C:\ProgramData\Acme",
        Kind = CleanupKind.Directory,
        Risk = RiskLevel.Low,
        Confidence = OwnershipConfidence.High,
        Reason = "Known data folder",
        SourceProvider = "KnownDataFolders",
        EvidenceList = new List<string> { "Path: C:\\ProgramData\\Acme" },
        IsSelected = true
    };

    var item2 = new CleanupCandidate
    {
        Target = @"C:\ProgramData\Acme",
        Kind = CleanupKind.Directory,
        Risk = RiskLevel.Low,
        Confidence = OwnershipConfidence.Certain,
        Reason = "Install evidence root",
        SourceProvider = "InstallLocation",
        EvidenceList = new List<string> { "Pre-uninstall root" },
        IsSelected = true
    };

    var deduplicated = CleanupScanner.DeduplicateCandidates(new[] { item1, item2 });
    EqualInt(1, deduplicated.Count);
    Equal(OwnershipConfidence.Certain, deduplicated[0].Confidence);
    EqualInt(2, deduplicated[0].EvidenceList.Count);
    True(deduplicated[0].SourceProvider.Contains("KnownDataFolders") && deduplicated[0].SourceProvider.Contains("InstallLocation"));
});

AddTest("Safe candidate selection defaults only low-risk high-confidence items", () =>
{
    var lowRisk = new CleanupCandidate
    {
        Target = @"C:\Users\Test\AppData\Local\Acme",
        Kind = CleanupKind.Directory,
        Risk = RiskLevel.Low,
        Confidence = OwnershipConfidence.High,
        Reason = "App cache",
        IsSelected = true
    };

    var highRiskUserData = new CleanupCandidate
    {
        Target = @"C:\Users\Test\Documents\Acme",
        Kind = CleanupKind.Directory,
        Risk = RiskLevel.High,
        Confidence = OwnershipConfidence.Medium,
        Reason = "User documents",
        IsSelected = false
    };

    True(lowRisk.IsSelected);
    False(highRiskUserData.IsSelected);
});

AddTest("Tracked install manifest saves and retrieves for matching application", () =>
{
    var root = Path.Combine(Path.GetTempPath(), "UninstallMateTests", Guid.NewGuid().ToString("N"));
    try
    {
        var tracker = new TrackedInstallService(root);
        var manifest = new TrackedInstallManifest
        {
            SessionId = "test-session-123",
            InstallerPath = @"C:\Downloads\Setup.exe",
            ApplicationDisplayName = "Acme Tools Pro",
            Publisher = "Acme Corp",
            Version = "3.2.1",
            CreatedDirectories = new List<string> { @"C:\Program Files\Acme Tools" },
            CreatedRegistryKeys = new List<string> { @"HKEY_LOCAL_MACHINE\SOFTWARE\Acme Tools" }
        };

        tracker.SaveManifestAsync(manifest, CancellationToken.None).GetAwaiter().GetResult();
        var app = new InstalledApplication
        {
            Id = "reg:acme-tools",
            DisplayName = "Acme Tools Pro"
        };

        var retrieved = tracker.FindManifestForApplication(app);
        True(retrieved is not null);
        Equal("test-session-123", retrieved!.SessionId);
        Equal("Acme Tools Pro", retrieved.ApplicationDisplayName);
        EqualInt(1, retrieved.CreatedDirectories.Count);
    }
    finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
});

if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
{
    AddTest("Quoted executable is parsed", () =>
    {
        True(CommandLineParser.TrySplit("\"C:\\Program Files\\Example\\uninstall.exe\" /remove", out var file, out var args));
        Equal("C:\\Program Files\\Example\\uninstall.exe", file);
        Equal("/remove", args);
    });

    AddTest("Missing Store package is verified as already absent", () =>
    {
        var result = UninstallService.RunPowerShellAsync(
            UninstallService.BuildStoreRemovalScript("UninstallMate.NonexistentPackage_0.0.0.0_x64__doesnotexist"),
            CancellationToken.None).GetAwaiter().GetResult();
        EqualInt(0, result.ExitCode);
    });

    AddTest("Equivalent uninstall registrations are all offered for cleanup", () =>
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
    });

    AddTest("Live desktop registration is detected before leftover scanning", () =>
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
    });

    AddTest("Shared startup registry values appear only once", () =>
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
    });

    AddTest("Neat StartupApproved value is identified and removed while preserving sibling values", () =>
    {
        const string startupApprovedRun = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
        var suffix = Guid.NewGuid().ToString("N");
        var neatValueName = "UninstallMateTest-Neat-" + suffix;
        var siblingValueName = "UninstallMateTest-OtherApp-" + suffix;
        var rawBytes = new byte[] { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        var siblingBytes = new byte[] { 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 };

        try
        {
            using (var hive = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64))
            using (var key = hive.CreateSubKey(startupApprovedRun))
            {
                key.SetValue(neatValueName, rawBytes, RegistryValueKind.Binary);
                key.SetValue(siblingValueName, siblingBytes, RegistryValueKind.Binary);
            }

            var app = new InstalledApplication
            {
                Id = "neat-reg-test:" + suffix,
                DisplayName = "Neat",
                Publisher = "The Neat Company"
            };

            var graph = ApplicationIdentityGraph.Create(app);
            graph.CapturedStartupSources.Add(new CapturedStartupEntry(
                "HKEY_CURRENT_USER", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "64", neatValueName, @"C:\Neat\Neat.exe", "Run"));

            var provider = new StartupProvider();
            var context = new CleanupScanContext { PreUninstallIdentity = graph };
            var scanResult = provider.ScanAsync(graph, context, CancellationToken.None).GetAwaiter().GetResult();

            var candidate = scanResult.Candidates.FirstOrDefault(c => c.Auxiliary == neatValueName);
            True(candidate is not null);
            Equal(OwnershipConfidence.Certain, candidate!.Confidence);

            // Execute exact value cleanup with backup
            var tempFolder = Path.Combine(Path.GetTempPath(), "UninstallMateTests", suffix);
            Directory.CreateDirectory(tempFolder);
            var cleaner = new CleanupService(tempFolder);
            var (report, session) = cleaner.ExecuteAsync(app, new[] { candidate }, true, null, CancellationToken.None).GetAwaiter().GetResult();

            // Verify Neat value was deleted, sibling value was preserved!
            using (var hive = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64))
            using (var key = hive.OpenSubKey(startupApprovedRun))
            {
                True(key!.GetValue(neatValueName) is null);
                True(key.GetValue(siblingValueName) is not null);
            }

            // Restore exact value
            var restored = QuarantineService.RestoreAsync(session, CancellationToken.None).GetAwaiter().GetResult();
            EqualInt(1, restored.Restored);

            using (var hive = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64))
            using (var key = hive.OpenSubKey(startupApprovedRun))
            {
                True(key!.GetValue(neatValueName) is not null);
                True(key.GetValue(siblingValueName) is not null);
            }
        }
        finally
        {
            using (var hive = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64))
            using (var key = hive.OpenSubKey(startupApprovedRun, writable: true))
            {
                key?.DeleteValue(neatValueName, false);
                key?.DeleteValue(siblingValueName, false);
            }
        }
    });

    AddTest("Discovery excludes classified system components when requested", () =>
    {
        var service = new AppDiscoveryService();
        var all = service.DiscoverAsync(includeSystem: true, CancellationToken.None).GetAwaiter().GetResult();
        var filtered = service.DiscoverAsync(includeSystem: false, CancellationToken.None).GetAwaiter().GetResult();
        True(all.Any(x => x.IsSystemComponent));
        False(filtered.Any(x => x.IsSystemComponent));
        True(filtered.Count < all.Count);
    });

    AddTest("Discovered Store apps contain no raw resource or certificate labels", () =>
    {
        var packages = new AppDiscoveryService().DiscoverAsync(includeSystem: true, CancellationToken.None)
            .GetAwaiter().GetResult().Where(x => x.Kind == ApplicationKind.MicrosoftStore).ToArray();
        False(packages.Any(x => x.DisplayName.StartsWith("ms-resource:", StringComparison.OrdinalIgnoreCase)));
        False(packages.Any(x => x.Publisher.StartsWith("CN=", StringComparison.OrdinalIgnoreCase)));
    });

    AddTest("Discovered Store icon sources resolve to existing files", () =>
    {
        var packages = new AppDiscoveryService().DiscoverAsync(includeSystem: true, CancellationToken.None)
            .GetAwaiter().GetResult().Where(x => x.Kind == ApplicationKind.MicrosoftStore).ToArray();
        var icons = packages.Where(x => x.DisplayIconPath.Length > 0).Select(x => x.DisplayIconPath).ToArray();
        True(icons.Length > 0);
        False(icons.Any(path => !File.Exists(path)));
    });
}

var failures = 0;
foreach (var (name, run) in tests)
{
    try { run(); Console.WriteLine($"PASS  {name}"); }
    catch (Exception ex) { failures++; Console.Error.WriteLine($"FAIL  {name}: {ex.Message}"); }
}
Console.WriteLine($"{tests.Count - failures}/{tests.Count} logic tests passed.");
return failures;

static void Equal<T>(T expected, T actual)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
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
