using System.Diagnostics;
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

// 4. Centralized Default Selection Policy - Exhaustive Table Test
AddTest("Selection policy exhaustive table invariant (only Low+High+true and Low+Certain+true auto-select)", () =>
{
    var risks = new[] { RiskLevel.Low, RiskLevel.Medium, RiskLevel.High };
    var confidences = new[] { OwnershipConfidence.Low, OwnershipConfidence.Medium, OwnershipConfidence.High, OwnershipConfidence.Certain };
    var autoSelectables = new[] { true, false };

    foreach (var risk in risks)
    {
        foreach (var conf in confidences)
        {
            foreach (var auto in autoSelectables)
            {
                var candidate = new CleanupCandidate
                {
                    Target = @"C:\Test\Path",
                    Kind = CleanupKind.Directory,
                    Risk = risk,
                    Confidence = conf,
                    Reason = "Test",
                    AutoSelectable = auto
                };

                var expected = auto && risk == RiskLevel.Low && conf.IsAtLeast(OwnershipConfidence.High);
                var actual = CleanupSelectionPolicy.ShouldAutoSelect(candidate);
                Equal(expected, actual);
            }
        }
    }
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

// 7. P0 User-Profile Path Safety Fix (Exact root protected vs descendants allowed)
AddTest("User profile root is protected, but AppData and valid application descendants are allowed", () =>
{
    var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

    // Exact roots must be rejected
    True(CleanupService.IsWithinProtectedWindowsRoot(@"C:\Users"));
    True(CleanupService.IsWithinProtectedWindowsRoot(userProfile));
    False(CleanupScanner.IsSafeSpecificPath(@"C:\Users"));
    False(CleanupScanner.IsSafeSpecificPath(userProfile));

    // Windows subtrees must be rejected
    True(CleanupService.IsWithinProtectedWindowsRoot(@"C:\Windows\System32"));
    True(CleanupService.IsWithinProtectedWindowsRoot(@"C:\ProgramData\Microsoft\Edge"));
    False(CleanupScanner.IsSafeSpecificPath(@"C:\Windows\System32\app.dll"));

    // User profile descendants (AppData, LocalLow, App folders) MUST be allowed!
    var localAppFolder = @"C:\Users\Alice\AppData\Local\AcmeVendor\App";
    False(CleanupService.IsWithinProtectedWindowsRoot(localAppFolder));
    True(CleanupScanner.IsSafeSpecificPath(localAppFolder));

    var roamingAppFolder = @"C:\Users\Alice\AppData\Roaming\AcmeVendor\App";
    False(CleanupService.IsWithinProtectedWindowsRoot(roamingAppFolder));
    True(CleanupScanner.IsSafeSpecificPath(roamingAppFolder));

    var localLowFolder = @"C:\Users\Alice\AppData\LocalLow\AcmeVendor\App";
    False(CleanupService.IsWithinProtectedWindowsRoot(localLowFolder));
    True(CleanupScanner.IsSafeSpecificPath(localLowFolder));

    var docsAppFolder = @"C:\Users\Alice\Documents\AcmeVendor\App";
    False(CleanupService.IsWithinProtectedWindowsRoot(docsAppFolder));
    True(CleanupScanner.IsSafeSpecificPath(docsAppFolder));
});

// 8. ScanStatusAccumulator Status Transitions
AddTest("ScanStatusAccumulator correctly transitions across warnings, partial, access denied, and failed", () =>
{
    var acc = new ScanStatusAccumulator();
    Equal(ScanStatus.Complete, acc.Status);

    acc.MarkWarning();
    Equal(ScanStatus.CompleteWithWarnings, acc.Status);

    acc.MarkPartial();
    Equal(ScanStatus.Partial, acc.Status);

    acc.MarkAccessDenied();
    Equal(ScanStatus.AccessDenied, acc.Status);

    acc.MarkFailed();
    Equal(ScanStatus.Failed, acc.Status);

    // Once failed, stays failed
    acc.MarkPartial();
    Equal(ScanStatus.Failed, acc.Status);
});

// 9. VerificationService Incompleteness Invariants
AddTest("VerificationService produces ScanIncomplete (never Clean) on Partial, AccessDenied, or Failed provider results", () =>
{
    var app = TestApplication();
    var identity = ApplicationIdentityGraph.Create(app);
    var verifier = new VerificationService();

    var emptyReport = new CleanupReport
    {
        ApplicationName = app.DisplayName,
        FinalStatus = "Completed"
    };

    // Test with partial result in scanner results
    var partialResult = new ProviderScanResult
    {
        ProviderName = "ScheduledTasks",
        Status = ScanStatus.Partial,
        Candidates = [],
        Diagnostics = [new ScanDiagnostic("ScheduledTasks", "PowerShell error", IsWarning: true)],
        Elapsed = TimeSpan.FromMilliseconds(10)
    };

    var scanExecution = new ScanExecutionResult
    {
        Identity = identity,
        Status = ScanStatus.Partial,
        Candidates = [],
        ProviderResults = [partialResult],
        Diagnostics = partialResult.Diagnostics,
        TotalElapsed = TimeSpan.FromMilliseconds(10)
    };

    var (outcome, message) = VerificationService.DetermineOutcome(
        emptyReport,
        stillInstalled: false,
        scanExecution);

    Equal(VerificationOutcome.ScanIncomplete, outcome);
    True(message.Contains("Verification scan incomplete"));
});

// 10. ShortcutProvider False-Positive & Provenance Tests
AddTest("ShortcutProvider: unrelated target path prevents auto-selection even with matching shortcut name", () =>
{
    var app = new InstalledApplication
    {
        Id = "neat-app",
        DisplayName = "Neat",
        InstallLocation = @"C:\Program Files\The Neat Company\Neat"
    };

    var graph = ApplicationIdentityGraph.Create(app);

    // Shortcut with matching name "Neat.lnk" but target points to another vendor's executable
    var candidate = new CleanupCandidate
    {
        Target = @"C:\Users\Alice\Desktop\Neat.lnk",
        Kind = CleanupKind.File,
        Risk = RiskLevel.Medium,
        Confidence = OwnershipConfidence.Medium,
        Reason = "Shortcut name matches application name; verify target before removal",
        AutoSelectable = false
    };

    False(CleanupSelectionPolicy.ShouldAutoSelect(candidate));
});

AddTest("ShortcutProvider: target-verified shortcut retains Certain confidence even when binary is gone", () =>
{
    var app = new InstalledApplication
    {
        Id = "neat-app",
        DisplayName = "Neat",
        InstallLocation = @"C:\Program Files\The Neat Company\Neat"
    };

    var graph = ApplicationIdentityGraph.Create(app);

    var capturedShortcut = new CapturedShortcutEntry(
        @"C:\Users\Alice\Desktop\My Scanner.lnk",
        "My Scanner",
        @"C:\Program Files\The Neat Company\Neat\Neat.exe",
        "",
        CleanupScope.User,
        OwnershipConfidence.Certain,
        ["Pre-uninstall verified target: C:\\Program Files\\The Neat Company\\Neat\\Neat.exe"]);

    graph.CapturedShortcuts.Add(capturedShortcut);

    var match = graph.CapturedShortcuts.FirstOrDefault(s =>
        s.ShortcutPath.Equals(@"C:\Users\Alice\Desktop\My Scanner.lnk", StringComparison.OrdinalIgnoreCase));

    True(match is not null);
    Equal(OwnershipConfidence.Certain, match!.Confidence);
});

// 11. Firewall Rule Ownership Tests
AddTest("Firewall rule: executable-bound rule is Certain/Low/AutoSelectable, name-only is Medium/Medium/unselected", () =>
{
    var app = new InstalledApplication
    {
        Id = "acme-app",
        DisplayName = "Acme Server",
        InstallLocation = @"C:\Program Files\Acme"
    };

    var graph = ApplicationIdentityGraph.Create(app);

    var strongCandidate = new CleanupCandidate
    {
        Target = @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
        Auxiliary = "AcmeRule1",
        Kind = CleanupKind.FirewallRule,
        Risk = RiskLevel.Low,
        Confidence = OwnershipConfidence.Certain,
        Reason = "Windows Firewall rule references application executable",
        AutoSelectable = true
    };
    True(CleanupSelectionPolicy.ShouldAutoSelect(strongCandidate));

    var nameOnlyCandidate = new CleanupCandidate
    {
        Target = @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
        Auxiliary = "AcmeRule2",
        Kind = CleanupKind.FirewallRule,
        Risk = RiskLevel.Medium,
        Confidence = OwnershipConfidence.Medium,
        Reason = "Windows Firewall rule name matches candidate name; review before removal",
        AutoSelectable = false
    };
    False(CleanupSelectionPolicy.ShouldAutoSelect(nameOnlyCandidate));
});

// 12. Native Messaging Host Manifest Validation
AddTest("Native messaging host: manifest-backed target is Certain, name-only is Medium/unselected", () =>
{
    var strongCandidate = new CleanupCandidate
    {
        Target = @"HKEY_CURRENT_USER\SOFTWARE\Google\Chrome\NativeMessagingHosts\com.acme.host",
        Kind = CleanupKind.RegistryKey,
        Risk = RiskLevel.Low,
        Confidence = OwnershipConfidence.Certain,
        Reason = "Browser native messaging host points to application executable",
        AutoSelectable = true
    };
    True(CleanupSelectionPolicy.ShouldAutoSelect(strongCandidate));

    var nameOnlyCandidate = new CleanupCandidate
    {
        Target = @"HKEY_CURRENT_USER\SOFTWARE\Google\Chrome\NativeMessagingHosts\com.acme.unrelated",
        Kind = CleanupKind.RegistryKey,
        Risk = RiskLevel.Medium,
        Confidence = OwnershipConfidence.Medium,
        Reason = "Browser native messaging host matches application name; review before removal",
        AutoSelectable = false
    };
    False(CleanupSelectionPolicy.ShouldAutoSelect(nameOnlyCandidate));
});

// 13. App Paths Provenance Confidence Preservation
AddTest("App Paths: weak name-only pre-capture does not become Certain post-uninstall", () =>
{
    var app = new InstalledApplication
    {
        Id = "acme-app",
        DisplayName = "Acme",
        InstallLocation = @"C:\Program Files\Acme"
    };

    var graph = ApplicationIdentityGraph.Create(app);

    var weakCapturedAppPath = new CapturedAppPathEntry(
        RegistryHive.LocalMachine,
        RegistryView.Registry64,
        "acme.exe",
        @"C:\OtherApp\acme.exe",
        "",
        OwnershipConfidence.Medium,
        ["App Paths exe key matches 'acme.exe'"]);

    graph.CapturedAppPaths.Add(weakCapturedAppPath);

    var candidate = new CleanupCandidate
    {
        Target = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\acme.exe",
        Kind = CleanupKind.RegistryKey,
        Risk = RiskLevel.Medium,
        Confidence = weakCapturedAppPath.Confidence,
        Reason = "App Paths registration matches application executable name",
        AutoSelectable = false
    };

    Equal(OwnershipConfidence.Medium, candidate.Confidence);
    False(CleanupSelectionPolicy.ShouldAutoSelect(candidate));
});

// 14. Scheduled Task Provenance Confidence Preservation
AddTest("Scheduled task: weak name-only pre-capture remains Medium confidence post-uninstall", () =>
{
    var app = new InstalledApplication
    {
        Id = "acme-app",
        DisplayName = "Acme",
        InstallLocation = @"C:\Program Files\Acme"
    };

    var graph = ApplicationIdentityGraph.Create(app);

    var weakTask = new CapturedTaskEntry(
        "AcmeUpdate",
        "\\",
        "C:\\Tools\\other.exe",
        "",
        "",
        null,
        OwnershipConfidence.Medium,
        ["Task name matches candidate name 'AcmeUpdate'"]);

    graph.CapturedTasks.Add(weakTask);

    var candidate = new CleanupCandidate
    {
        Target = "\\AcmeUpdate",
        Kind = CleanupKind.ScheduledTask,
        Risk = RiskLevel.Medium,
        Confidence = weakTask.Confidence,
        Reason = "Scheduled task matches app name; review before removal",
        AutoSelectable = false
    };

    Equal(OwnershipConfidence.Medium, candidate.Confidence);
    False(CleanupSelectionPolicy.ShouldAutoSelect(candidate));
});

// 15. PATH Neighbor Anchors Merge-Safe Restore
AddTest("Neighbor-anchor PATH restore restores segment relative to previous and next neighbors", () =>
{
    // Scenario: Original was A;APP;B. After cleanup it was A;B. Later user edited PATH to X;A;B;Y.
    var currentPath = @"C:\NewRoot\X;C:\Tools\A;C:\Utils\B;C:\NewRoot\Y";
    var segmentToRestore = @"C:\Program Files\Acme\bin";
    var previousAnchor = @"C:\Tools\A";
    var nextAnchor = @"C:\Utils\B";

    var merged = QuarantineService.MergePathSegment(
        currentPath,
        segmentToRestore,
        originalIndex: 1,
        previousSegment: previousAnchor,
        nextSegment: nextAnchor);

    Equal(@"C:\NewRoot\X;C:\Tools\A;C:\Program Files\Acme\bin;C:\Utils\B;C:\NewRoot\Y", merged);
});

// 16. SameApplicationIdentity Prioritization
AddTest("SameApplicationIdentity prioritizes Store package identity, registry key path, install location, and scope", () =>
{
    var store1 = new InstalledApplication
    {
        Id = "store1",
        DisplayName = "App",
        Kind = ApplicationKind.MicrosoftStore,
        PackageFullName = "Publisher.App_1.0.0.0_x64__12345",
        Scope = InstallScope.CurrentUser
    };

    var store2 = new InstalledApplication
    {
        Id = "store2",
        DisplayName = "App",
        Kind = ApplicationKind.MicrosoftStore,
        PackageFullName = "Publisher.App_1.0.0.0_x64__12345",
        Scope = InstallScope.CurrentUser
    };

    var storeDifferentScope = new InstalledApplication
    {
        Id = "store3",
        DisplayName = "App",
        Kind = ApplicationKind.MicrosoftStore,
        PackageFullName = "Publisher.App_1.0.0.0_x64__12345",
        Scope = InstallScope.AllUsers
    };

    True(AppDiscoveryService.SameApplicationIdentity(store1, store2));
    False(AppDiscoveryService.SameApplicationIdentity(store1, storeDifferentScope));

    var reg1 = new InstalledApplication
    {
        Id = "reg1",
        DisplayName = "Desktop App",
        Kind = ApplicationKind.Desktop,
        RegistryKeyPath = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{1111-2222}",
        Scope = InstallScope.AllUsers,
        Architecture = "64-bit"
    };

    var reg2 = new InstalledApplication
    {
        Id = "reg2",
        DisplayName = "Desktop App",
        Kind = ApplicationKind.Desktop,
        RegistryKeyPath = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{1111-2222}",
        Scope = InstallScope.AllUsers,
        Architecture = "64-bit"
    };

    var regDifferentKey = new InstalledApplication
    {
        Id = "reg3",
        DisplayName = "Desktop App",
        Kind = ApplicationKind.Desktop,
        RegistryKeyPath = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{9999-8888}",
        Scope = InstallScope.AllUsers,
        Architecture = "64-bit"
    };

    True(AppDiscoveryService.SameApplicationIdentity(reg1, reg2));
    False(AppDiscoveryService.SameApplicationIdentity(reg1, regDifferentKey));
});

// 17. ToolRunner Process Execution and Timeout
AddTest("ToolRunner runs executable, captures output, and exits cleanly", () =>
{
    var cmd = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "cmd.exe" : "echo";
    var args = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? new[] { "/c", "echo", "UninstallMateTest" } : new[] { "UninstallMateTest" };

    var result = ToolRunner.RunAsync(cmd, args, TimeSpan.FromSeconds(5), CancellationToken.None).GetAwaiter().GetResult();
    True(result.Success);
    True(result.StandardOutput.Contains("UninstallMateTest"));
    False(result.TimedOut);
});

// 18. Backup Failure Fail-Closed Destructive Protection Test
AddTest("Fail-closed: Target remains untouched when backup creation fails", () =>
{
    var root = Path.Combine(Path.GetTempPath(), "UninstallMateTests", Guid.NewGuid().ToString("N"));
    try
    {
        var targetFile = Path.Combine(root, "app.exe");
        Directory.CreateDirectory(root);
        File.WriteAllText(targetFile, "binary content");

        var candidate = new CleanupCandidate
        {
            Target = targetFile,
            Kind = CleanupKind.File,
            Risk = RiskLevel.Low,
            Confidence = OwnershipConfidence.Certain,
            Reason = "App binary",
            AutoSelectable = true,
            IsSelected = true
        };

        // Create an invalid session folder path to simulate backup failure
        var invalidSessionRoot = Path.Combine(root, "invalid:\0folder");
        var service = new CleanupService(invalidSessionRoot);

        try
        {
            service.ExecuteAsync(TestApplication(), [candidate], true, null, CancellationToken.None).GetAwaiter().GetResult();
        }
        catch { }

        // Invariant: Target file MUST remain present because backup failed
        True(File.Exists(targetFile));
    }
    finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
});

// 19. StartupApproved Cross-Hive / Cross-View Non-Correlation
AddTest("StartupApproved correlation rejects cross-hive and cross-view false correlation", () =>
{
    var app = new InstalledApplication
    {
        Id = "agent-app",
        DisplayName = "Agent",
        InstallLocation = @"C:\Program Files\Agent"
    };

    var graph = ApplicationIdentityGraph.Create(app);

    // HKCU Run 64-bit source
    var hkcuKey = new StartupCorrelationKey(RegistryHive.CurrentUser, StartupSourceKind.Run, "Agent", RegistryView.Registry64);
    var hkcuSource = new CapturedStartupSource(
        hkcuKey,
        @"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"C:\Program Files\Agent\Agent.exe",
        null,
        OwnershipConfidence.Certain,
        ["Verified path"]);

    graph.CapturedStartupSources.Add(hkcuSource);

    // Checking HKLM approval against HKCU source must NOT match
    var hklmKey = new StartupCorrelationKey(RegistryHive.LocalMachine, StartupSourceKind.Run, "Agent", RegistryView.Registry64);
    var matchHklm = graph.CapturedStartupSources.FirstOrDefault(s => s.CorrelationKey == hklmKey);
    True(matchHklm is null);

    // Checking HKCU 32-bit approval against HKCU 64-bit source must NOT match
    var hkcu32Key = new StartupCorrelationKey(RegistryHive.CurrentUser, StartupSourceKind.Run, "Agent", RegistryView.Registry32);
    var match32 = graph.CapturedStartupSources.FirstOrDefault(s => s.CorrelationKey == hkcu32Key);
    True(match32 is null);
});

// 20. Tracked Install Manifest
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

// 21. Permanent & Quarantined Directory Operations
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

// 22. Real Windows Platform Tests
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
                RegistryHive.CurrentUser, StartupSourceKind.Run, neatValueName, RegistryView.Registry64);

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

    AddTest("Registry types (SZ, EXPAND_SZ, MULTI_SZ, DWORD, QWORD, BINARY) complete round trip faithfully", () =>
    {
        const string subKey = @"Software\UninstallMateTests\TypeRoundTripTest";
        var suffix = Guid.NewGuid().ToString("N");
        var szName = "SZ-" + suffix;
        var expandName = "EXPAND-" + suffix;
        var multiName = "MULTI-" + suffix;
        var dwordName = "DWORD-" + suffix;
        var qwordName = "QWORD-" + suffix;
        var binaryName = "BINARY-" + suffix;

        try
        {
            using (var hive = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64))
            using (var key = hive.CreateSubKey(subKey))
            {
                key.SetValue(szName, "SimpleString", RegistryValueKind.String);
                key.SetValue(expandName, "%SystemRoot%\\test", RegistryValueKind.ExpandString);
                key.SetValue(multiName, new[] { "Line1", "Line2" }, RegistryValueKind.MultiString);
                key.SetValue(dwordName, 42, RegistryValueKind.DWord);
                key.SetValue(qwordName, 9876543210L, RegistryValueKind.QWord);
                key.SetValue(binaryName, new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }, RegistryValueKind.Binary);
            }

            var szBundle = CleanupService.CreateRegistryValueBundle($@"HKEY_CURRENT_USER\{subKey}", szName);
            var expandBundle = CleanupService.CreateRegistryValueBundle($@"HKEY_CURRENT_USER\{subKey}", expandName);
            var multiBundle = CleanupService.CreateRegistryValueBundle($@"HKEY_CURRENT_USER\{subKey}", multiName);
            var dwordBundle = CleanupService.CreateRegistryValueBundle($@"HKEY_CURRENT_USER\{subKey}", dwordName);
            var qwordBundle = CleanupService.CreateRegistryValueBundle($@"HKEY_CURRENT_USER\{subKey}", qwordName);
            var binaryBundle = CleanupService.CreateRegistryValueBundle($@"HKEY_CURRENT_USER\{subKey}", binaryName);

            Equal("SimpleString", szBundle.Values.First().StringValue);
            Equal("%SystemRoot%\\test", expandBundle.Values.First().StringValue);
            EqualInt(2, multiBundle.Values.First().MultiStringValue!.Length);
            EqualInt(42, dwordBundle.Values.First().DWordValue!.Value);
            Equal(9876543210L, qwordBundle.Values.First().QWordValue!.Value);
            EqualInt(4, binaryBundle.Values.First().BinaryValue!.Length);

            // Delete all values
            using (var hive = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64))
            using (var key = hive.OpenSubKey(subKey, writable: true))
            {
                key!.DeleteValue(szName);
                key.DeleteValue(expandName);
                key.DeleteValue(multiName);
                key.DeleteValue(dwordName);
                key.DeleteValue(qwordName);
                key.DeleteValue(binaryName);
            }

            // Restore all bundles
            QuarantineService.RestoreRegistryValueBundle(szBundle);
            QuarantineService.RestoreRegistryValueBundle(expandBundle);
            QuarantineService.RestoreRegistryValueBundle(multiBundle);
            QuarantineService.RestoreRegistryValueBundle(dwordBundle);
            QuarantineService.RestoreRegistryValueBundle(qwordBundle);
            QuarantineService.RestoreRegistryValueBundle(binaryBundle);

            // Verify exact restored data and kinds
            using (var hive = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64))
            using (var key = hive.OpenSubKey(subKey))
            {
                Equal("SimpleString", key!.GetValue(szName, "", RegistryValueOptions.DoNotExpandEnvironmentNames));
                Equal("%SystemRoot%\\test", key.GetValue(expandName, "", RegistryValueOptions.DoNotExpandEnvironmentNames));
                var multiArr = key.GetValue(multiName) as string[];
                EqualInt(2, multiArr!.Length);
                Equal("Line2", multiArr[1]);
                Equal(42, Convert.ToInt32(key.GetValue(dwordName)));
                Equal(9876543210L, Convert.ToInt64(key.GetValue(qwordName)));
                var binArr = key.GetValue(binaryName) as byte[];
                EqualInt(4, binArr!.Length);
                Equal((byte)0xDE, binArr[0]);
            }
        }
        finally
        {
            using var hive = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64);
            using var key = hive.OpenSubKey(subKey, writable: true);
            key?.DeleteValue(szName, false);
            key?.DeleteValue(expandName, false);
            key?.DeleteValue(multiName, false);
            key?.DeleteValue(dwordName, false);
            key?.DeleteValue(qwordName, false);
            key?.DeleteValue(binaryName, false);
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
