using System.Diagnostics;
using System.Text.RegularExpressions;
using UninstallMate.Models;

namespace UninstallMate.Services.Providers;

public sealed partial class KnownDataFolderProvider : ICleanupArtifactProvider
{
    public string Name => "KnownDataFolders";

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
                ScanDataRoots(identity, context, candidates, diagnostics, statusAcc, token);
            }
            catch (Exception ex)
            {
                diagnostics.Add(new ScanDiagnostic(Name, $"Error during known data folder scan: {ex.Message}", IsError: true, ExceptionDetail: ex.ToString()));
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

    private void ScanDataRoots(
        ApplicationIdentityGraph identity,
        CleanupScanContext context,
        List<CleanupCandidate> candidates,
        List<ScanDiagnostic> diagnostics,
        ScanStatusAccumulator statusAcc,
        CancellationToken token)
    {
        var names = identity.CandidateNames.ToArray();
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        var lowRiskRoots = new[]
        {
            localAppData,
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            Path.Combine(userProfile, "AppData", "LocalLow"),
            Path.Combine(localAppData, "Temp")
        }.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase);

        foreach (var root in lowRiskRoots)
        {
            foreach (var name in names)
            {
                token.ThrowIfCancellationRequested();
                CheckAndAddDirectory(root, name, RiskLevel.Low, OwnershipConfidence.High, "Exact app-named data, cache, log, or temporary folder", candidates, diagnostics, statusAcc, CleanupScope.User);
            }
            AddPublisherNestedFolders(identity, root, names, candidates, diagnostics, statusAcc, token, RiskLevel.Low, OwnershipConfidence.High, CleanupScope.User);
        }

        var programRoots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonProgramFilesX86)
        }.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase);

        foreach (var root in programRoots)
        {
            foreach (var name in names)
            {
                token.ThrowIfCancellationRequested();
                CheckAndAddDirectory(root, name, RiskLevel.Medium, OwnershipConfidence.High, "Exact app-named program folder remaining after removal", candidates, diagnostics, statusAcc, CleanupScope.Application);
            }
            AddPublisherNestedFolders(identity, root, names, candidates, diagnostics, statusAcc, token, RiskLevel.Medium, OwnershipConfidence.High, CleanupScope.Application);
        }

        if (identity.Kind == ApplicationKind.MicrosoftStore && identity.PackageFamilyName.Length >= 3)
        {
            var packageRoot = Path.Combine(localAppData, "Packages");
            CheckAndAddDirectory(packageRoot, identity.PackageFamilyName, RiskLevel.Low, OwnershipConfidence.Certain, "Store application's private data folder", candidates, diagnostics, statusAcc, CleanupScope.User);
        }

        // Personal roots (Documents, Saved Games, dot folders) - high risk, never auto-selected by default
        var personalRoots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.Combine(userProfile, "Saved Games")
        }.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase);

        foreach (var root in personalRoots)
        {
            foreach (var name in names)
            {
                token.ThrowIfCancellationRequested();
                CheckAndAddDirectory(root, name, RiskLevel.High, OwnershipConfidence.Medium, "User-created data folder that may contain personal files or projects", candidates, diagnostics, statusAcc, CleanupScope.User, autoSelectable: false);
            }
        }

        foreach (var name in names)
        {
            var dotName = "." + SlugRegex().Replace(name.ToLowerInvariant(), "");
            if (dotName.Length >= 4)
            {
                CheckAndAddDirectory(userProfile, dotName, RiskLevel.High, OwnershipConfidence.Medium, "Hidden per-user profile configuration folder", candidates, diagnostics, statusAcc, CleanupScope.User, autoSelectable: false);
            }
        }
    }

    private void AddPublisherNestedFolders(
        ApplicationIdentityGraph identity,
        string root,
        string[] names,
        List<CleanupCandidate> candidates,
        List<ScanDiagnostic> diagnostics,
        ScanStatusAccumulator statusAcc,
        CancellationToken token,
        RiskLevel risk,
        OwnershipConfidence confidence,
        CleanupScope scope)
    {
        var publisher = SafeSegment(identity.Publisher);
        if (publisher.Length < 3 || publisher.Equals("Microsoft Corporation", StringComparison.OrdinalIgnoreCase)) return;
        var publisherPath = Path.Combine(root, publisher);
        if (!Directory.Exists(publisherPath)) return;

        foreach (var name in names)
        {
            token.ThrowIfCancellationRequested();
            CheckAndAddDirectory(publisherPath, name, risk, confidence,
                risk == RiskLevel.Low
                    ? "App folder inside its publisher's data folder"
                    : "App folder inside a publisher program folder (publisher root preserved)",
                candidates, diagnostics, statusAcc, scope);
        }
    }

    private void CheckAndAddDirectory(
        string root,
        string name,
        RiskLevel risk,
        OwnershipConfidence confidence,
        string reason,
        List<CleanupCandidate> candidates,
        List<ScanDiagnostic> diagnostics,
        ScanStatusAccumulator statusAcc,
        CleanupScope scope,
        bool autoSelectable = true)
    {
        if (name.Length < 3 || !Directory.Exists(root)) return;
        var targetPath = Path.Combine(root, name);
        try
        {
            if (!Directory.Exists(targetPath) || !CleanupScanner.IsSafeSpecificPath(targetPath)) return;
            var fullPath = Path.GetFullPath(targetPath).TrimEnd(Path.DirectorySeparatorChar);
            var size = CleanupScanner.GetDirectorySize(fullPath);

            var candidate = new CleanupCandidate
            {
                Target = fullPath,
                Kind = CleanupKind.Directory,
                Risk = risk,
                Confidence = confidence,
                Reason = reason,
                SizeBytes = size,
                Scope = scope,
                SourceProvider = Name,
                AutoSelectable = autoSelectable && risk == RiskLevel.Low,
                EvidenceList = [$"Target path: {fullPath}", $"Matched candidate name: {name}"]
            };
            candidate.IsSelected = CleanupSelectionPolicy.ShouldAutoSelect(candidate);
            candidates.Add(candidate);
        }
        catch (UnauthorizedAccessException ex)
        {
            diagnostics.Add(new ScanDiagnostic(Name, $"Access denied for '{targetPath}'", IsWarning: true, TargetPath: targetPath, ExceptionDetail: ex.Message));
            statusAcc.MarkAccessDenied();
        }
        catch (Exception ex)
        {
            diagnostics.Add(new ScanDiagnostic(Name, $"Failed checking directory '{targetPath}': {ex.Message}", IsWarning: true, TargetPath: targetPath, ExceptionDetail: ex.Message));
            statusAcc.MarkWarning();
        }
    }

    private static string SafeSegment(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Equals("Unknown publisher", StringComparison.OrdinalIgnoreCase)) return "";
        var invalid = Path.GetInvalidFileNameChars();
        return string.Concat(value.Trim().Where(c => !invalid.Contains(c))).TrimEnd('.');
    }

    [GeneratedRegex(@"[^a-z0-9._-]+")]
    private static partial Regex SlugRegex();
}
