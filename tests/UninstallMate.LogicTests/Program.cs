using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32;
using UninstallMate.Models;
using UninstallMate.Services;
using UninstallMate.Services.Providers;

var tests = new List<(string Name, Action Run)>();

void AddTest(string name, Action run) => tests.Add((name, run));

// 1. MSI & Command Normalization
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

// 2. OwnershipConfidence Semantics & Semantic Helpers
AddTest("OwnershipConfidence ordering and semantic comparisons", () =>
{
    True(OwnershipConfidence.Certain.IsAtLeast(OwnershipConfidence.High));
    True(OwnershipConfidence.High.IsAtLeast(OwnershipConfidence.High));
    False(OwnershipConfidence.Medium.IsAtLeast(OwnershipConfidence.High));
    False(OwnershipConfidence.Low.IsAtLeast(OwnershipConfidence.High));
    True(OwnershipConfidence.Certain.IsAtLeast(OwnershipConfidence.Certain));
    False(OwnershipConfidence.High.IsAtLeast(OwnershipConfidence.Certain));

    Equal(OwnershipConfidence.Certain, OwnershipConfidenceExtensions.Strongest(OwnershipConfidence.Certain, OwnershipConfidence.High));
    Equal(OwnershipConfidence.High, OwnershipConfidenceExtensions.Strongest(OwnershipConfidence.Low, OwnershipConfidence.High));
    Equal(OwnershipConfidence.Low, OwnershipConfidenceExtensions.Weakest(OwnershipConfidence.Low, OwnershipConfidence.High));
});

// 3. RiskLevel Merge Semantics
AddTest("RiskLevel highest risk merge semantics", () =>
{
    Equal(RiskLevel.High, RiskLevelExtensions.Highest(RiskLevel.Low, RiskLevel.High));
    Equal(RiskLevel.High, RiskLevelExtensions.Highest(RiskLevel.High, RiskLevel.Low));
    Equal(RiskLevel.Medium, RiskLevelExtensions.Highest(RiskLevel.Medium, RiskLevel.Low));
    Equal(RiskLevel.Low, RiskLevelExtensions.Lowest(RiskLevel.Low, RiskLevel.High));
});

// 4. Centralized Default Selection Policy
AddTest("CleanupSelectionPolicy only auto-selects Low Risk + High/Certain Confidence", () =>
{
    var lowRiskCertain = new CleanupCandidate
    {
        Target = @"C:\Program Files\Acme",
        Kind = CleanupKind.Directory,
        Risk = RiskLevel.Low,
        Confidence = OwnershipConfidence.Certain,
        Reason = "Test",
        AutoSelectable = true
    };
    True(CleanupSelectionPolicy.ShouldAutoSelect(lowRiskCertain));

    var lowRiskHigh = new CleanupCandidate
    {
        Target = @"C:\Users\Test\AppData\Local\Acme",
        Kind = CleanupKind.Directory,
        Risk = RiskLevel.Low,
        Confidence = OwnershipConfidence.High,
        Reason = "Test",
        AutoSelectable = true
    };
    True(CleanupSelectionPolicy.ShouldAutoSelect(lowRiskHigh));

    var highRiskCertain = new CleanupCandidate
    {
        Target = @"C:\Windows\System32\acme.dll",
        Kind = CleanupKind.File,
        Risk = RiskLevel.High,
        Confidence = OwnershipConfidence.Certain,
        Reason = "Test",
        AutoSelectable = true
    };
    False(CleanupSelectionPolicy.ShouldAutoSelect(highRiskCertain));

    var lowRiskMedium = new CleanupCandidate
    {
        Target = @"HKEY_CURRENT_USER\Software\Acme",
        Kind = CleanupKind.RegistryKey,
        Risk = RiskLevel.Low,
        Confidence = OwnershipConfidence.Medium,
        Reason = "Test",
        AutoSelectable = true
    };
    False(CleanupSelectionPolicy.ShouldAutoSelect(lowRiskMedium));

    var notAutoSelectable = new CleanupCandidate
    {
        Target = @"C:\Program Files\Acme",
        Kind = CleanupKind.Directory,
        Risk = RiskLevel.Low,
        Confidence = OwnershipConfidence.Certain,
        Reason = "Test",
        AutoSelectable = false
    };
    False(CleanupSelectionPolicy.ShouldAutoSelect(notAutoSelectable));
});

// 5. Candidate Deduplication Invariants
AddTest("Candidate deduplication merges to highest risk and strongest confidence", () =>
{
    var lowRiskHighConfidence = new CleanupCandidate
    {
        Target = @"C:\ProgramData\Acme",
        Kind = CleanupKind.Directory,
        Risk = RiskLevel.Low,
        Confidence = OwnershipConfidence.High,
        Reason = "Known data folder",
        SourceProvider = "KnownDataFolders",
        EvidenceList = new List<string> { "Path: C:\\ProgramData\\Acme" },
        AutoSelectable = true
    };

    var highRiskCertainConfidence = new CleanupCandidate
    {
        Target = @"C:\ProgramData\Acme",
        Kind = CleanupKind.Directory,
        Risk = RiskLevel.High,
        Confidence = OwnershipConfidence.Certain,
        Reason = "Shared data folder",
        SourceProvider = "InstallLocation",
        EvidenceList = new List<string> { "Shared root" },
        AutoSelectable = false
    };

    var deduplicated = CleanupScanner.DeduplicateCandidates(new[] { lowRiskHighConfidence, highRiskCertainConfidence });
    EqualInt(1, deduplicated.Count);
    Equal(OwnershipConfidence.Certain, deduplicated[0].Confidence);
    Equal(RiskLevel.High, deduplicated[0].Risk);
    False(deduplicated[0].AutoSelectable);
    False(deduplicated[0].IsSelected);
    EqualInt(2, deduplicated[0].EvidenceList.Count);
});

// 6. Evidence & Path Matching
AddTest("Install-path evidence matches a contained executable", () =>
    True(CleanupScanner.ReferencesEvidencePath(
        "\"C:\\Program Files\\Acme\\bin\\agent.exe\" --startup",
        ["C:\\Program Files\\Acme"])));

AddTest("Install-path evidence rejects a similarly prefixed folder", () =>
    False(CleanupScanner.ReferencesEvidencePath(
        "\"C:\\Program Files\\AcmeOther\\agent.exe\"",
        ["C:\\Program Files\\Acme"])));

// 7. Protected Windows Subtree Deletion Rejection
AddTest("Protected Windows directories and user profile roots are strictly rejected from cleanup", () =>
{
    var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
    var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    True(CleanupService.IsWithinProtectedWindowsRoot(winDir));
    True(CleanupService.IsWithinProtectedWindowsRoot(system));
    True(CleanupService.IsWithinProtectedWindowsRoot(userProfile));
    False(CleanupScanner.IsSafeSpecificPath(winDir));
    False(CleanupScanner.IsSafeSpecificPath(system));
    False(CleanupScanner.IsSafeSpecificPath(userProfile));
});

// 8. PATH Cleanup & Index-Aware Merge-Safe Restore
AddTest("PATH cleanup removes only the app's segments", () =>
    Equal(
        @"C:\Windows;C:\Tools",
        CleanupService.RemoveEnvironmentPathSegments(
            @"C:\Windows;C:\Program Files\Acme;C:\Program Files\Acme\bin;C:\Tools",
            @"C:\Program Files\Acme")));

AddTest("Merge-safe PATH restore preserves approximate original position and newer edits", () =>
{
    var currentPath = @"C:\Windows;C:\NewTools;C:\OtherApp";
    var segmentToRestore = @"C:\Program Files\Acme";
    var merged = QuarantineService.MergePathSegment(currentPath, segmentToRestore, originalIndex: 1);
    Equal(@"C:\Windows;C:\Program Files\Acme;C:\NewTools;C:\OtherApp", merged);

    // Does not duplicate if already present
    var unchanged = QuarantineService.MergePathSegment(merged, segmentToRestore, originalIndex: 1);
    Equal(merged, unchanged);
});

// 9. Application Discovery & Store Components
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
});

AddTest("Drivers are system components but ordinary desktop apps are not", () =>
{
    True(AppDiscoveryService.IsLikelySystemDesktopComponent("NVIDIA Graphics Driver 610.62", "NVIDIA Corporation"));
    True(AppDiscoveryService.IsLikelySystemDesktopComponent("ASUS Smart Display Control", "ASUSTeK COMPUTER INC."));
    False(AppDiscoveryService.IsLikelySystemDesktopComponent("7-Zip 25.00 (x64)", "Igor Pavlov"));
});

// 10. StartupApproved False-Positive Prevention & Pre-Uninstall Correlation
AddTest("StartupApproved correlation prevents same-name unrelated false positives", () =>
{
    var app = new InstalledApplication
    {
        Id = "vendor-a-agent",
        DisplayName = "Agent",
        Publisher = "Vendor A",
        InstallLocation = @"C:\Program Files\VendorA\Agent"
    };

    var graph = ApplicationIdentityGraph.Create(app);

    // Unrelated startup source belonging to Vendor B
    var unrelatedCorrelationKey = new StartupCorrelationKey(
        RegistryHive.CurrentUser, RegistryView.Registry64, StartupSourceKind.Run, "Agent");

    var unrelatedSource = new CapturedStartupSource(
        unrelatedCorrelationKey,
        @"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"C:\Program Files\VendorB\Agent.exe",
        null,
        OwnershipConfidence.Medium, // Name-only match without path evidence is Medium
        ["Name match only"]);

    graph.CapturedStartupSources.Add(unrelatedSource);

    // Correlating an approval against unrelated source must NOT yield Certain or AutoSelectable
    var matchingSource = graph.CapturedStartupSources.FirstOrDefault(s =>
        s.CorrelationKey == unrelatedCorrelationKey
        && s.Confidence.IsAtLeast(OwnershipConfidence.High));

    True(matchingSource is null); // Correctly rejects promotion because source was not High/Certain
});

AddTest("StartupApproved correlation accepts exact verified pre-uninstall startup source", () =>
{
    var app = new InstalledApplication
    {
        Id = "neat-app",
        DisplayName = "Neat",
        Publisher = "The Neat Company",
        InstallLocation = @"C:\Program Files (x86)\Neat"
    };

    var graph = ApplicationIdentityGraph.Create(app);

    var neatCorrelationKey = new StartupCorrelationKey(
        RegistryHive.CurrentUser, RegistryView.Registry64, StartupSourceKind.Run, "Neat");

    var verifiedNeatSource = new CapturedStartupSource(
        neatCorrelationKey,
        @"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"C:\Program Files (x86)\Neat\Neat.exe",
        null,
        OwnershipConfidence.Certain, // Path matches evidence
        ["Command points into app installation: C:\\Program Files (x86)\\Neat\\Neat.exe"]);

    graph.CapturedStartupSources.Add(verifiedNeatSource);

    var matchingSource = graph.CapturedStartupSources.FirstOrDefault(s =>
        s.CorrelationKey == neatCorrelationKey
        && s.Confidence.IsAtLeast(OwnershipConfidence.High));

    True(matchingSource is not null);
    Equal(OwnershipConfidence.Certain, matchingSource!.Confidence);
});

// 11. Scan Completeness & Status Aggregation
AddTest("Scan completeness: Provider failure or access denied prevents Clean verification outcome", () =>
{
    var completeResult = ProviderScanResult.Succeeded("InstallLocation", [], TimeSpan.Zero);
    var accessDeniedResult = ProviderScanResult.AccessDeniedResult("Registry", @"HKEY_LOCAL_MACHINE\SOFTWARE\Protected", "Access denied reading protected key");

    var aggregated = CleanupScanner.AggregateStatus(new List<ProviderScanResult> { completeResult, accessDeniedResult });
    Equal(ScanStatus.AccessDenied, aggregated);
});

// 12. Fail-Closed Cleanup
AddTest("Fail-closed cleanup: CleanupSafetyException thrown when target is within protected Windows root", () =>
{
    var root = Path.Combine(Path.GetTempPath(), "UninstallMateTests", Guid.NewGuid().ToString("N"));
    try
    {
        var protectedTarget = @"C:\Windows\System32\acme.dll";
        var candidate = new CleanupCandidate
        {
            Target = protectedTarget,
            Kind = CleanupKind.File,
            Risk = RiskLevel.High,
            Confidence = OwnershipConfidence.Certain,
            Reason = "Protected directory",
            AutoSelectable = false
        };

        var service = new CleanupService(root);
        var (report, _) = service.ExecuteAsync(TestApplication(), [candidate], true, null, CancellationToken.None).GetAwaiter().GetResult();
        False(report.Items.Single().Success);
        True(report.Items.Single().Detail.Contains("protected Windows directory"));
    }
    finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
});

// 13. Exact Registry Type Serialization
AddTest("RegistryValueBackupData faithfully serializes MultiString, DWord, QWord, and Binary types", () =>
{
    var multiData = new RegistryValueBackupData
    {
        Hive = "HKEY_CURRENT_USER",
        View = "64",
        SubKey = @"SOFTWARE\Acme",
        ValueName = "List",
        ValueKind = "MultiString",
        MultiStringValue = ["One", "Two", "Three"]
    };

    var json = JsonSerializer.Serialize(multiData);
    var deserialized = JsonSerializer.Deserialize<RegistryValueBackupData>(json);
    True(deserialized is not null);
    EqualInt(3, deserialized!.MultiStringValue?.Length ?? 0);
    Equal("Two", deserialized.MultiStringValue![1]);
});

// 14. Shared Ownership Protection
AddTest("Shared ownership protection sets candidate to High Risk and unselected", () =>
{
    var app1 = TestApplicationWith("acme-1", "1.0", @"C:\Program Files\Acme Shared");
    var app2 = TestApplicationWith("acme-2", "2.0", @"C:\Program Files\Acme Shared");

    var graph = ApplicationIdentityGraph.Create(app1);

    var candidate = new CleanupCandidate
    {
        Target = @"C:\Program Files\Acme Shared\common.dll",
        Kind = CleanupKind.File,
        Risk = RiskLevel.Low,
        Confidence = OwnershipConfidence.High,
        Reason = "App file",
        AutoSelectable = true,
        IsSelected = true
    };

    var candidates = new List<CleanupCandidate> { candidate };
    CleanupScanner.ApplySharedOwnershipProtection(candidates, [app1, app2], graph);

    False(candidates[0].AutoSelectable);
    False(candidates[0].IsSelected);
    Equal(RiskLevel.High, candidates[0].Risk);
});

// 15. Tracked Install Manifest
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

// 16. Permanent & Quarantined Directory Operations
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

// 17. Real Windows Platform Tests
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
            var neatKey = new StartupCorrelationKey(
                RegistryHive.CurrentUser, RegistryView.Registry64, StartupSourceKind.Run, neatValueName);

            graph.CapturedStartupSources.Add(new CapturedStartupSource(
                neatKey,
                @"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"C:\Neat\Neat.exe",
                null,
                OwnershipConfidence.Certain,
                ["Verified pre-uninstall Neat source"]));

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

    AddTest("32-bit and 64-bit different registry values are independently backed up and restored", () =>
    {
        const string subKey = @"Software\UninstallMateTests\BothViewsTest";
        var suffix = Guid.NewGuid().ToString("N");
        var valName = "DualViewVal-" + suffix;

        try
        {
            using (var hive64 = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64))
            using (var key64 = hive64.CreateSubKey(subKey))
            {
                key64.SetValue(valName, "VALUE_64", RegistryValueKind.String);
            }

            using (var hive32 = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry32))
            using (var key32 = hive32.CreateSubKey(subKey))
            {
                key32.SetValue(valName, "VALUE_32", RegistryValueKind.String);
            }

            var bundle = CleanupService.CreateRegistryValueBundle($@"HKEY_CURRENT_USER\{subKey}", valName);
            EqualInt(2, bundle.Values.Count);
            True(bundle.Values.Any(v => v.View == "64" && v.StringValue == "VALUE_64"));
            True(bundle.Values.Any(v => v.View == "32" && v.StringValue == "VALUE_32"));
        }
        finally
        {
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                using var hive = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, view);
                using var key = hive.OpenSubKey(subKey, writable: true);
                key?.DeleteValue(valName, false);
            }
        }
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

static CleanupCandidate TestDirectoryCandidate(string target) => new()
{
    Target = target,
    Kind = CleanupKind.Directory,
    Risk = RiskLevel.Low,
    Reason = "Test candidate",
    IsSelected = true
};
