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
                    candidates.Add(new CleanupCandidate
                    {
                        Target = fullPath,
                        Kind = CleanupKind.Directory,
                        Risk = RiskLevel.Medium,
                        Confidence = OwnershipConfidence.Certain,
                        Reason = "Application installation directory remaining after removal",
                        SizeBytes = size,
                        Scope = CleanupScope.Application,
                        SourceProvider = Name,
                        EvidenceList = [$"Registered install location: {location}"],
                        IsSelected = true // High confidence app-owned directory
                    });
                }
            }
            catch (Exception ex)
            {
                diagnostics.Add(new ScanDiagnostic(Name, $"Failed checking install location '{location}': {ex.Message}", IsWarning: true, TargetPath: location));
            }
        }

        return Task.FromResult(new ProviderScanResult
        {
            ProviderName = Name,
            Status = ScanStatus.Complete,
            Candidates = candidates,
            Diagnostics = diagnostics,
            Elapsed = sw.Elapsed
        });
    }
}
