using UninstallMate.Models;

namespace UninstallMate.Services.Providers;

public sealed class CleanupScanContext
{
    public IReadOnlyList<InstalledApplication> InstalledApplications { get; init; } = [];
    public ApplicationIdentityGraph? PreUninstallIdentity { get; init; }
    public ApplicationIdentityCaptureResult? PreUninstallCaptureResult { get; init; }
    public Action<ScanDiagnostic>? DiagnosticSink { get; init; }

    public bool IsSharedWithOtherInstalledApp(string pathOrName, string currentAppId)
    {
        if (string.IsNullOrWhiteSpace(pathOrName)) return false;
        foreach (var other in InstalledApplications)
        {
            if (other.Id.Equals(currentAppId, StringComparison.OrdinalIgnoreCase)) continue;
            if (other.InstallLocation.Length > 0 && pathOrName.StartsWith(other.InstallLocation, StringComparison.OrdinalIgnoreCase))
                return true;
            if (other.DisplayName.Equals(pathOrName, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }
}
