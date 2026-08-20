using UninstallMate.Models;

namespace UninstallMate.Services.Providers;

public interface ICleanupArtifactProvider
{
    string Name { get; }

    Task<ProviderScanResult> ScanAsync(
        ApplicationIdentityGraph identity,
        CleanupScanContext context,
        CancellationToken token);
}
