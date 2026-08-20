using UninstallMate.Models;
using UninstallMate.Services.Providers;

namespace UninstallMate.Services;

public enum VerificationOutcome
{
    Clean,
    CleanAfterRestart,
    ResidualItemsRequireReview,
    CleanupIncomplete,
    ScanIncomplete,
    VerificationIncomplete
}

public sealed class VerificationReport
{
    public required VerificationOutcome Outcome { get; init; }
    public required string OutcomeMessage { get; init; }
    public IReadOnlyList<CleanupCandidate> RemainingRemnants { get; init; } = [];
    public IReadOnlyList<ScanDiagnostic> Diagnostics { get; init; } = [];
    public bool RestartRequired { get; init; }
    public bool InventoryStillPresent { get; init; }
}

public sealed class VerificationService
{
    private readonly CleanupScanner _scanner;
    private readonly AppDiscoveryService _discovery;

    public VerificationService(CleanupScanner? scanner = null, AppDiscoveryService? discovery = null)
    {
        _scanner = scanner ?? new CleanupScanner();
        _discovery = discovery ?? new AppDiscoveryService();
    }

    public async Task<VerificationReport> VerifyAsync(
        ApplicationIdentityGraph identity,
        CleanupReport cleanupReport,
        IProgress<string>? progress,
        CancellationToken token)
    {
        progress?.Report("Running post-clean verification scan…");

        // 1. Check if any selected cleanup item failed
        var failedItems = cleanupReport.Items.Where(x => !x.Success).ToList();
        var restartPending = cleanupReport.Items.Any(x => x.Detail.Contains("reboot", StringComparison.OrdinalIgnoreCase));

        // 2. Re-discover applications to verify registration removal
        var inventory = await _discovery.DiscoverAsync(includeSystem: true, token);
        var stillInstalled = inventory.Any(a => AppDiscoveryService.SameApplicationIdentity(a, identity.Application));

        // 3. Re-run scan across all providers
        var context = new CleanupScanContext
        {
            InstalledApplications = inventory,
            PreUninstallIdentity = identity
        };

        var scanResult = await _scanner.ScanWithDetailsAsync(identity, context, progress, token);
        var remaining = scanResult.Candidates;
        var hasProviderFailure = scanResult.Status is ScanStatus.Failed or ScanStatus.AccessDenied;

        // 4. Calculate outcome
        VerificationOutcome outcome;
        string message;

        if (hasProviderFailure)
        {
            outcome = VerificationOutcome.ScanIncomplete;
            message = "Verification scan incomplete: one or more providers encountered access or system errors.";
        }
        else if (failedItems.Count > 0)
        {
            outcome = VerificationOutcome.CleanupIncomplete;
            message = $"Cleanup completed with {failedItems.Count} item(s) that could not be removed.";
        }
        else if (stillInstalled)
        {
            outcome = VerificationOutcome.VerificationIncomplete;
            message = "Windows still reports an application registration in inventory.";
        }
        else if (remaining.Count == 0)
        {
            if (restartPending)
            {
                outcome = VerificationOutcome.CleanAfterRestart;
                message = "Clean after restart: all live application remnants removed; locked items are scheduled for restart deletion.";
            }
            else
            {
                outcome = VerificationOutcome.Clean;
                message = "Clean: verified that all application registrations, startup entries, services, and remnants have been removed.";
            }
        }
        else
        {
            var hasHighConfidenceRemaining = remaining.Any(r => r.Confidence >= OwnershipConfidence.High && r.Risk == RiskLevel.Low);
            if (hasHighConfidenceRemaining)
            {
                outcome = VerificationOutcome.CleanupIncomplete;
                message = $"Verification found {remaining.Count} remaining leftover item(s).";
            }
            else
            {
                outcome = VerificationOutcome.ResidualItemsRequireReview;
                message = $"Verification complete: {remaining.Count} medium/high-risk or optional items remain for review.";
            }
        }

        return new VerificationReport
        {
            Outcome = outcome,
            OutcomeMessage = message,
            RemainingRemnants = remaining,
            Diagnostics = scanResult.Diagnostics,
            RestartRequired = restartPending,
            InventoryStillPresent = stillInstalled
        };
    }
}
