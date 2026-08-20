using System.Diagnostics;
using UninstallMate.Models;

namespace UninstallMate.Services.Providers;

public sealed class InstallLocationProvider : ICleanupArtifactProvider
{
    public string Name => "InstallLocation";

    public Task<ProviderScanResult> ScanAsync(
        ApplicationIdentityGraph identity,
        CleanupScanContext context,
        CancellationToken token)
    {
        var sw = Stopwatch.StartNew();
        var candidates = new List<CleanupCandidate>();
        var diagnostics = new List<ScanDiagnostic>();
        var statusAcc = new ScanStatusAccumulator();

        if (identity.Kind == ApplicationKind.MicrosoftStore)
        {
            // Windows manages Store package payloads.
            return Task.FromResult(ProviderScanResult.Succeeded(Name, candidates, sw.Elapsed));
        }

        var location = identity.InstallLocation;
        if (!string.IsNullOrWhiteSpace(location))
        {
            try
            {
                if (Directory.Exists(location) && CleanupScanner.IsSafeSpecificPath(location))
                {
                    var fullPath = Path.GetFullPath(location).TrimEnd(Path.DirectorySeparatorChar);
                    var size = CleanupScanner.GetDirectorySize(fullPath);
                    var candidate = new CleanupCandidate
                    {
                        Target = fullPath,
                        Kind = CleanupKind.Directory,
                        Risk = RiskLevel.Low,
                        Confidence = OwnershipConfidence.Certain,
                        Reason = "Application installation directory remaining after removal",
                        SizeBytes = size,
                        Scope = CleanupScope.Application,
                        SourceProvider = Name,
                        EvidenceList = [$"Registered install location: {location}"],
                        AutoSelectable = true
                    };
                    candidate.IsSelected = CleanupSelectionPolicy.ShouldAutoSelect(candidate);
                    candidates.Add(candidate);
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                diagnostics.Add(new ScanDiagnostic(Name, $"Access denied checking install location '{location}': {ex.Message}", IsWarning: true, TargetPath: location));
                statusAcc.MarkAccessDenied();
            }
            catch (Exception ex)
            {
                diagnostics.Add(new ScanDiagnostic(Name, $"Failed checking install location '{location}': {ex.Message}", IsWarning: true, TargetPath: location));
                statusAcc.MarkWarning();
            }
        }

        return Task.FromResult(new ProviderScanResult
        {
            ProviderName = Name,
            Status = statusAcc.Status,
            Candidates = candidates,
            Diagnostics = diagnostics,
            Elapsed = sw.Elapsed
        });
    }
}
