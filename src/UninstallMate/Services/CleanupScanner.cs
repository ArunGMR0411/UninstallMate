using System.Diagnostics;
using UninstallMate.Models;
using UninstallMate.Services.Providers;

namespace UninstallMate.Services;

public sealed class ScanExecutionResult
{
    public required ApplicationIdentityGraph Identity { get; init; }
    public required ScanStatus Status { get; init; }
    public IReadOnlyList<CleanupCandidate> Candidates { get; init; } = [];
    public IReadOnlyList<ProviderScanResult> ProviderResults { get; init; } = [];
    public IReadOnlyList<ScanDiagnostic> Diagnostics { get; init; } = [];
    public TimeSpan TotalElapsed { get; init; }

    public bool HasWarnings => Diagnostics.Any(d => d.IsWarning);
    public bool HasErrors => Diagnostics.Any(d => d.IsError);
}

public sealed partial class CleanupScanner
{
    private readonly List<ICleanupArtifactProvider> _providers = [];

    public IReadOnlyList<ICleanupArtifactProvider> Providers => _providers;

    public CleanupScanner()
    {
        _providers.AddRange([
            new InstallLocationProvider(),
            new KnownDataFolderProvider(),
            new ShortcutProvider(),
            new StartupProvider(),
            new RegistryProvider(),
            new EnvironmentProvider(),
            new AppPathsProvider(),
            new ComRegistrationProvider(),
            new ServiceProvider(),
            new ScheduledTaskProvider(),
            new FirewallRuleProvider(),
            new CrashDumpProvider(),
            new FileAssociationProvider(),
            new NativeMessagingProvider(),
            new EventLogProvider()
        ]);
    }

    public CleanupScanner(IEnumerable<ICleanupArtifactProvider> customProviders)
    {
        _providers.AddRange(customProviders);
    }

    public async Task<IReadOnlyList<CleanupCandidate>> ScanAsync(
        InstalledApplication app,
        CancellationToken token)
    {
        var identity = await ApplicationIdentityGraph.CaptureAsync(app, token);
        var result = await ScanWithDetailsAsync(identity, new CleanupScanContext(), null, token);
        return result.Candidates;
    }

    public async Task<ScanExecutionResult> ScanWithDetailsAsync(
        ApplicationIdentityGraph identity,
        CleanupScanContext context,
        IProgress<string>? progress,
        CancellationToken token)
    {
        var sw = Stopwatch.StartNew();
        var providerResults = new List<ProviderScanResult>();
        var allCandidates = new List<CleanupCandidate>();
        var allDiagnostics = new List<ScanDiagnostic>();

        for (var i = 0; i < _providers.Count; i++)
        {
            token.ThrowIfCancellationRequested();
            var provider = _providers[i];
            progress?.Report($"Scanning {provider.Name} ({i + 1}/{_providers.Count})…");

            try
            {
                var result = await provider.ScanAsync(identity, context, token);
                providerResults.Add(result);
                allCandidates.AddRange(result.Candidates);
                allDiagnostics.AddRange(result.Diagnostics);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                var failedResult = ProviderScanResult.FailedResult(provider.Name, $"Provider execution failed: {ex.Message}", ex.ToString());
                providerResults.Add(failedResult);
                allDiagnostics.AddRange(failedResult.Diagnostics);
            }
        }

        // Apply shared ownership protection against other installed applications
        ApplySharedOwnershipProtection(allCandidates, context.InstalledApplications, identity);

        var deduplicated = DeduplicateCandidates(allCandidates);
        var finalStatus = AggregateStatus(providerResults);

        return new ScanExecutionResult
        {
            Identity = identity,
            Status = finalStatus,
            Candidates = deduplicated,
            ProviderResults = providerResults,
            Diagnostics = allDiagnostics,
            TotalElapsed = sw.Elapsed
        };
    }

    public static void ApplySharedOwnershipProtection(
        List<CleanupCandidate> candidates,
        IReadOnlyList<InstalledApplication> installedApps,
        ApplicationIdentityGraph targetApp)
    {
        if (installedApps.Count == 0) return;

        var otherApps = installedApps
            .Where(a => !AppDiscoveryService.SameApplicationIdentity(a, targetApp.Application))
            .ToList();

        if (otherApps.Count == 0) return;

        for (var i = 0; i < candidates.Count; i++)
        {
            var candidate = candidates[i];
            foreach (var other in otherApps)
            {
                var otherInstall = NormalizePath(other.InstallLocation);
                if (string.IsNullOrWhiteSpace(otherInstall)) continue;

                // Check if filesystem candidate is within or matches another app's install location
                if (candidate.Kind is CleanupKind.File or CleanupKind.Directory)
                {
                    var candPath = NormalizePath(candidate.Target);
                    if (candPath.Equals(otherInstall, StringComparison.OrdinalIgnoreCase)
                        || candPath.StartsWith(otherInstall + "\\", StringComparison.OrdinalIgnoreCase)
                        || candPath.StartsWith(otherInstall + "/", StringComparison.OrdinalIgnoreCase))
                    {
                        candidates[i] = new CleanupCandidate
                        {
                            Target = candidate.Target,
                            Kind = candidate.Kind,
                            Risk = RiskLevel.High,
                            Confidence = candidate.Confidence,
                            Reason = $"[Shared Component] Shared with {other.DisplayName} ({candidate.Reason})",
                            SizeBytes = candidate.SizeBytes,
                            RegistryViewName = candidate.RegistryViewName,
                            Auxiliary = candidate.Auxiliary,
                            EvidencePath = candidate.EvidencePath,
                            EvidenceList = candidate.EvidenceList.Concat([$"Shared with installed app: {other.DisplayName}"]).ToList(),
                            SourceProvider = candidate.SourceProvider,
                            Scope = candidate.Scope,
                            AutoSelectable = false,
                            IsSelected = false
                        };
                        break;
                    }
                }
            }
        }
    }

    private static string NormalizePath(string path) =>
        path.Trim().Trim('"', '\'').TrimEnd('\\', '/');

    public static IReadOnlyList<CleanupCandidate> DeduplicateCandidates(IEnumerable<CleanupCandidate> source)
    {
        var merged = new Dictionary<string, CleanupCandidate>(StringComparer.OrdinalIgnoreCase);

        foreach (var candidate in source)
        {
            var key = MakeCandidateKey(candidate);
            if (!merged.TryGetValue(key, out var existing))
            {
                var single = new CleanupCandidate
                {
                    Target = candidate.Target,
                    Kind = candidate.Kind,
                    Risk = candidate.Risk,
                    Confidence = candidate.Confidence,
                    Reason = candidate.Reason,
                    SizeBytes = candidate.SizeBytes,
                    RegistryViewName = candidate.RegistryViewName,
                    Auxiliary = candidate.Auxiliary,
                    EvidencePath = candidate.EvidencePath,
                    EvidenceList = [..candidate.EvidenceList],
                    SourceProvider = candidate.SourceProvider,
                    Scope = candidate.Scope,
                    OriginalExists = candidate.OriginalExists,
                    DetectedBeforeUninstall = candidate.DetectedBeforeUninstall,
                    DetectedAfterUninstall = candidate.DetectedAfterUninstall,
                    RequiresReboot = candidate.RequiresReboot,
                    AutoSelectable = candidate.AutoSelectable,
                    RegistryValueKindName = candidate.RegistryValueKindName,
                    RegistryRawValueBase64 = candidate.RegistryRawValueBase64,
                    IsSelected = CleanupSelectionPolicy.ShouldAutoSelect(candidate)
                };
                merged[key] = single;
            }
            else
            {
                // Safety Invariant: Highest Risk wins, Strongest Confidence wins, AutoSelectable requires BOTH true
                var mergedConfidence = OwnershipConfidenceExtensions.Strongest(existing.Confidence, candidate.Confidence);
                var mergedRisk = RiskLevelExtensions.Highest(existing.Risk, candidate.Risk);
                var mergedAutoSelectable = existing.AutoSelectable && candidate.AutoSelectable;
                var mergedEvidence = existing.EvidenceList.Concat(candidate.EvidenceList).Distinct().ToList();

                var mergedView = existing.RegistryViewName;
                if (existing.RegistryViewName != candidate.RegistryViewName && candidate.RegistryViewName is "32" or "64")
                {
                    mergedView = "Both";
                }

                var mergedCandidate = new CleanupCandidate
                {
                    Target = existing.Target,
                    Kind = existing.Kind,
                    Risk = mergedRisk,
                    Confidence = mergedConfidence,
                    Reason = existing.Reason,
                    SizeBytes = Math.Max(existing.SizeBytes, candidate.SizeBytes),
                    RegistryViewName = mergedView,
                    Auxiliary = existing.Auxiliary,
                    EvidencePath = string.IsNullOrEmpty(existing.EvidencePath) ? candidate.EvidencePath : existing.EvidencePath,
                    EvidenceList = mergedEvidence,
                    SourceProvider = $"{existing.SourceProvider}, {candidate.SourceProvider}",
                    Scope = existing.Scope,
                    OriginalExists = existing.OriginalExists && candidate.OriginalExists,
                    DetectedBeforeUninstall = existing.DetectedBeforeUninstall || candidate.DetectedBeforeUninstall,
                    DetectedAfterUninstall = existing.DetectedAfterUninstall || candidate.DetectedAfterUninstall,
                    RequiresReboot = existing.RequiresReboot || candidate.RequiresReboot,
                    AutoSelectable = mergedAutoSelectable,
                    RegistryValueKindName = existing.RegistryValueKindName.Length > 0 ? existing.RegistryValueKindName : candidate.RegistryValueKindName,
                    RegistryRawValueBase64 = existing.RegistryRawValueBase64.Length > 0 ? existing.RegistryRawValueBase64 : candidate.RegistryRawValueBase64
                };

                mergedCandidate.IsSelected = CleanupSelectionPolicy.ShouldAutoSelect(mergedCandidate);
                merged[key] = mergedCandidate;
            }
        }

        RemoveNestedFilesystemCandidates(merged);

        return merged.Values
            .OrderBy(x => x.Risk)
            .ThenByDescending(x => x.Confidence)
            .ThenBy(x => x.Kind)
            .ThenBy(x => x.Target, StringComparer.CurrentCultureIgnoreCase)
            .ToList();
    }

    private static string MakeCandidateKey(CleanupCandidate c)
    {
        return c.Kind switch
        {
            CleanupKind.RegistryValue => $"val:{c.Target}|{c.Auxiliary}|{c.RegistryViewName}",
            CleanupKind.EnvironmentEntry => $"env:{c.Target}|{c.Auxiliary}",
            CleanupKind.WindowsService => $"svc:{c.Auxiliary}",
            CleanupKind.ScheduledTask => $"task:{c.Target}",
            CleanupKind.FirewallRule => $"fw:{c.Auxiliary}",
            CleanupKind.File or CleanupKind.Directory => $"fs:{Path.GetFullPath(c.Target).TrimEnd(Path.DirectorySeparatorChar)}",
            CleanupKind.RegistryKey => $"key:{c.Target}|{c.RegistryViewName}",
            _ => $"{c.Kind}:{c.Target}|{c.Auxiliary}"
        };
    }

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

    public static ScanStatus AggregateStatus(List<ProviderScanResult> results)
    {
        if (results.Count == 0) return ScanStatus.Complete;
        if (results.Any(r => r.Status == ScanStatus.Failed)) return ScanStatus.Failed;
        if (results.Any(r => r.Status == ScanStatus.AccessDenied)) return ScanStatus.AccessDenied;
        if (results.Any(r => r.Status == ScanStatus.Partial)) return ScanStatus.Partial;
        if (results.Any(r => r.Status == ScanStatus.CompleteWithWarnings)) return ScanStatus.CompleteWithWarnings;
        return ScanStatus.Complete;
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

            if (CleanupService.IsWithinProtectedWindowsRoot(path)) return false;

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

    internal static (Microsoft.Win32.RegistryHive Hive, string SubKey) SplitRegistryPath(string path)
    {
        var slash = path.IndexOf('\\');
        if (slash < 0) throw new ArgumentException("Registry path has no subkey.", nameof(path));
        var hiveName = path[..slash];
        var hive = hiveName.ToUpperInvariant() switch
        {
            "HKEY_LOCAL_MACHINE" or "HKLM" => Microsoft.Win32.RegistryHive.LocalMachine,
            "HKEY_CURRENT_USER" or "HKCU" => Microsoft.Win32.RegistryHive.CurrentUser,
            _ => throw new ArgumentException("Only HKLM and HKCU cleanup is supported.", nameof(path))
        };
        return (hive, path[(slash + 1)..]);
    }

    internal static Microsoft.Win32.RegistryKey OpenHive(Microsoft.Win32.RegistryHive hive, string viewName) =>
        Microsoft.Win32.RegistryKey.OpenBaseKey(hive, viewName switch
        {
            "32" => Microsoft.Win32.RegistryView.Registry32,
            "64" => Microsoft.Win32.RegistryView.Registry64,
            _ => Microsoft.Win32.RegistryView.Default
        });

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

    internal static long GetDirectorySize(string path)
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
}
