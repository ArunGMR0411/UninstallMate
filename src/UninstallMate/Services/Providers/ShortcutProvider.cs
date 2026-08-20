using System.Diagnostics;
using UninstallMate.Models;

namespace UninstallMate.Services.Providers;

public sealed class ShortcutProvider : ICleanupArtifactProvider
{
    private static readonly IShortcutResolver ShortcutResolver = new WindowsShortcutResolver();

    public string Name => "Shortcuts";

    public async Task<ProviderScanResult> ScanAsync(
        ApplicationIdentityGraph identity,
        CleanupScanContext context,
        CancellationToken token)
    {
        var sw = Stopwatch.StartNew();
        var candidates = new List<CleanupCandidate>();
        var diagnostics = new List<ScanDiagnostic>();
        var statusAcc = new ScanStatusAccumulator();

        await Task.Run(() =>
        {
            try
            {
                ScanShortcuts(identity, context, candidates, diagnostics, statusAcc, token);
            }
            catch (Exception ex)
            {
                diagnostics.Add(new ScanDiagnostic(Name, $"Error during shortcut scan: {ex.Message}", IsError: true, ExceptionDetail: ex.ToString()));
                statusAcc.MarkFailed();
            }
        }, token);

        return new ProviderScanResult
        {
            ProviderName = Name,
            Status = statusAcc.Status,
            Candidates = candidates,
            Diagnostics = diagnostics,
            Elapsed = sw.Elapsed
        };
    }

    private void ScanShortcuts(
        ApplicationIdentityGraph identity,
        CleanupScanContext context,
        List<CleanupCandidate> candidates,
        List<ScanDiagnostic> diagnostics,
        ScanStatusAccumulator statusAcc,
        CancellationToken token)
    {
        var names = identity.CandidateNames.ToArray();
        var roots = new[]
        {
            (Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), CleanupScope.User),
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory), CleanupScope.System),
            (Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), "Programs"), CleanupScope.User),
            (Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu), "Programs"), CleanupScope.System)
        }.Where(r => !string.IsNullOrWhiteSpace(r.Item1) && Directory.Exists(r.Item1)).DistinctBy(r => r.Item1, StringComparer.OrdinalIgnoreCase);

        foreach (var (root, scope) in roots)
        {
            token.ThrowIfCancellationRequested();

            // 1. Check for app-specific shortcut folder (e.g. Start Menu\Programs\Acme\)
            foreach (var name in names)
            {
                var folderPath = Path.Combine(root, name);
                if (Directory.Exists(folderPath) && CleanupScanner.IsSafeSpecificPath(folderPath))
                {
                    var fullFolder = Path.GetFullPath(folderPath).TrimEnd(Path.DirectorySeparatorChar);
                    var size = CleanupScanner.GetDirectorySize(fullFolder);
                    var candidate = new CleanupCandidate
                    {
                        Target = fullFolder,
                        Kind = CleanupKind.Directory,
                        Risk = RiskLevel.Low,
                        Confidence = OwnershipConfidence.High,
                        Reason = "App-specific Start menu or desktop shortcut folder",
                        SizeBytes = size,
                        Scope = scope,
                        SourceProvider = Name,
                        EvidenceList = [$"Shortcut directory: {fullFolder}"],
                        AutoSelectable = true
                    };
                    candidate.IsSelected = CleanupSelectionPolicy.ShouldAutoSelect(candidate);
                    candidates.Add(candidate);
                }
            }

            // 2. Check individual shortcut files
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
            catch (UnauthorizedAccessException ex)
            {
                diagnostics.Add(new ScanDiagnostic(Name, $"Access denied enumerating shortcuts in '{root}': {ex.Message}", IsWarning: true, TargetPath: root));
                statusAcc.MarkAccessDenied();
                continue;
            }
            catch (Exception ex)
            {
                diagnostics.Add(new ScanDiagnostic(Name, $"Failed enumerating shortcuts in '{root}': {ex.Message}", IsWarning: true, TargetPath: root));
                statusAcc.MarkWarning();
                continue;
            }

            foreach (var file in files)
            {
                token.ThrowIfCancellationRequested();
                var shortcutName = Path.GetFileNameWithoutExtension(file);

                var resolution = file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)
                    ? ShortcutResolver.Resolve(file)
                    : ShortcutResolution.Empty;

                var targetPath = resolution.HasTarget ? resolution.TargetPath : "";
                var pathMatch = identity.ReferencesEvidence(targetPath);
                var matchesName = names.Any(name => ShortcutNameMatches(shortcutName, name));

                // Check pre-uninstall verified shortcut provenance
                var matchingCapturedShortcut = identity.CapturedShortcuts.FirstOrDefault(s =>
                    s.ShortcutPath.Equals(file, StringComparison.OrdinalIgnoreCase)
                    || (s.ShortcutName.Equals(shortcutName, StringComparison.OrdinalIgnoreCase) && s.Scope == scope));

                var capturedPathVerified = matchingCapturedShortcut is not null && matchingCapturedShortcut.Confidence == OwnershipConfidence.Certain;

                // Ownership Rules:
                // 1. Path Match or Pre-uninstall Path-verified -> Certain / Low Risk / AutoSelectable
                // 2. Name match with unrelated target binary -> Ignored / High Risk / NOT AutoSelectable
                // 3. Name match without target binary -> Medium / Medium Risk / NOT AutoSelectable

                if (pathMatch || capturedPathVerified)
                {
                    var size = 0L;
                    try { size = new FileInfo(file).Length; } catch { }

                    var evidence = new List<string> { $"Shortcut file: {file}" };
                    if (pathMatch) evidence.Add($"Resolved target points to app binary: {targetPath}");
                    if (capturedPathVerified && matchingCapturedShortcut is not null)
                        evidence.Add($"Pre-uninstall verified target: {matchingCapturedShortcut.ResolvedTarget}");

                    var candidate = new CleanupCandidate
                    {
                        Target = file,
                        Kind = CleanupKind.File,
                        Risk = RiskLevel.Low,
                        Confidence = OwnershipConfidence.Certain,
                        Reason = pathMatch
                            ? $"Shortcut targets application executable '{targetPath}'"
                            : "Pre-uninstall verified application shortcut",
                        SizeBytes = size,
                        Scope = scope,
                        SourceProvider = Name,
                        EvidenceList = evidence,
                        AutoSelectable = true
                    };
                    candidate.IsSelected = CleanupSelectionPolicy.ShouldAutoSelect(candidate);
                    candidates.Add(candidate);
                }
                else if (matchesName)
                {
                    // Unrelated target check
                    if (resolution.HasTarget && !string.IsNullOrWhiteSpace(targetPath) && File.Exists(targetPath))
                    {
                        // Target exists and belongs to another application -> do NOT claim ownership
                        continue;
                    }

                    // Broken or unresolved name match -> Medium Confidence / Medium Risk / Unselected
                    var size = 0L;
                    try { size = new FileInfo(file).Length; } catch { }

                    var candidate = new CleanupCandidate
                    {
                        Target = file,
                        Kind = CleanupKind.File,
                        Risk = RiskLevel.Medium,
                        Confidence = OwnershipConfidence.Medium,
                        Reason = $"Shortcut name '{shortcutName}' matches application name; verify target before removal",
                        SizeBytes = size,
                        Scope = scope,
                        SourceProvider = Name,
                        EvidenceList = [$"Shortcut file: {file}", "Name match only without verified target path"],
                        AutoSelectable = false
                    };
                    candidate.IsSelected = CleanupSelectionPolicy.ShouldAutoSelect(candidate);
                    candidates.Add(candidate);
                }
            }
        }
    }

    private static bool ShortcutNameMatches(string shortcutName, string appName) =>
        shortcutName.Equals(appName, StringComparison.CurrentCultureIgnoreCase)
        || shortcutName.Equals($"Uninstall {appName}", StringComparison.CurrentCultureIgnoreCase)
        || shortcutName.Equals($"{appName} Uninstall", StringComparison.CurrentCultureIgnoreCase);
}
