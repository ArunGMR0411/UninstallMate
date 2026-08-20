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

        await Task.Run(() =>
        {
            try
            {
                ScanShortcuts(identity, context, candidates, diagnostics, token);
            }
            catch (Exception ex)
            {
                diagnostics.Add(new ScanDiagnostic(Name, $"Error during shortcut scan: {ex.Message}", IsError: true, ExceptionDetail: ex.ToString()));
            }
        }, token);

        return new ProviderScanResult
        {
            ProviderName = Name,
            Status = diagnostics.Any(d => d.IsError) ? ScanStatus.CompleteWithWarnings : ScanStatus.Complete,
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
        CancellationToken token)
    {
        var names = identity.CandidateNames.ToArray();
        var roots = new[]
        {
            (Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), CleanupScope.User),
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory), CleanupScope.System),
            (Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), "Programs"), CleanupScope.User),
            (Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu), "Programs"), CleanupScope.System)
        }.Where(r => Directory.Exists(r.Item1)).DistinctBy(r => r.Item1, StringComparer.OrdinalIgnoreCase);

        foreach (var (root, scope) in roots)
        {
            // 1. Check for app-specific shortcut folder (e.g. Start Menu\Programs\Acme\)
            foreach (var name in names)
            {
                var folderPath = Path.Combine(root, name);
                if (Directory.Exists(folderPath) && CleanupScanner.IsSafeSpecificPath(folderPath))
                {
                    var fullFolder = Path.GetFullPath(folderPath).TrimEnd(Path.DirectorySeparatorChar);
                    var size = CleanupScanner.GetDirectorySize(fullFolder);
                    candidates.Add(new CleanupCandidate
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
                        AutoSelectable = true,
                        IsSelected = true
                    });
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
            catch (Exception ex)
            {
                diagnostics.Add(new ScanDiagnostic(Name, $"Failed enumerating shortcuts in '{root}': {ex.Message}", IsWarning: true, TargetPath: root));
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
                var matchesPreUninstall = identity.CapturedStartupSources.Any(s => s.CorrelationKey.ValueName.Equals(shortcutName, StringComparison.OrdinalIgnoreCase));

                if (pathMatch || matchesName || matchesPreUninstall)
                {
                    var size = 0L;
                    try { size = new FileInfo(file).Length; } catch { }

                    var confidence = pathMatch ? OwnershipConfidence.Certain
                        : (matchesPreUninstall ? OwnershipConfidence.Certain : OwnershipConfidence.High);

                    var evidence = new List<string> { $"Shortcut file: {file}" };
                    if (pathMatch) evidence.Add($"Resolved target points to app binary: {targetPath}");

                    candidates.Add(new CleanupCandidate
                    {
                        Target = file,
                        Kind = CleanupKind.File,
                        Risk = RiskLevel.Low,
                        Confidence = confidence,
                        Reason = pathMatch
                            ? $"Shortcut targets application executable '{targetPath}'"
                            : "App-named desktop or Start menu shortcut",
                        SizeBytes = size,
                        Scope = scope,
                        SourceProvider = Name,
                        EvidenceList = evidence,
                        AutoSelectable = true,
                        IsSelected = true
                    });
                }
            }
        }
    }

    private static bool ShortcutNameMatches(string shortcutName, string appName) =>
        shortcutName.Equals(appName, StringComparison.CurrentCultureIgnoreCase)
        || shortcutName.Equals($"Uninstall {appName}", StringComparison.CurrentCultureIgnoreCase)
        || shortcutName.Equals($"{appName} Uninstall", StringComparison.CurrentCultureIgnoreCase);
}
