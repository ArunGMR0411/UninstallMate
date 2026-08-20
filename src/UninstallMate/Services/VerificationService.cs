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
        var restartPending = cleanupReport.RestartRequired
            || cleanupReport.Items.Any(x => x.VerificationStatus == "PendingReboot" || x.Detail.Contains("reboot", StringComparison.OrdinalIgnoreCase));

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

        var (outcome, message) = DetermineOutcome(cleanupReport, stillInstalled, scanResult);

        cleanupReport.FinalStatus = outcome.ToString();
        cleanupReport.RestartRequired = restartPending;
        cleanupReport.Verification = new VerificationReportData
        {
            Outcome = outcome.ToString(),
            OutcomeMessage = message,
            RemainingCount = remaining.Count,
            RestartRequired = restartPending,
            InventoryStillPresent = stillInstalled
        };

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

    public static (VerificationOutcome Outcome, string Message) DetermineOutcome(
        CleanupReport cleanupReport,
        bool stillInstalled,
        ScanExecutionResult scanResult)
    {
        var failedItems = cleanupReport.Items.Where(x => !x.Success).ToList();
        var restartPending = cleanupReport.RestartRequired
            || cleanupReport.Items.Any(x => x.VerificationStatus == "PendingReboot" || x.Detail.Contains("reboot", StringComparison.OrdinalIgnoreCase));
        var remaining = scanResult.Candidates;
        var hasProviderFailure = scanResult.Status is ScanStatus.Failed or ScanStatus.AccessDenied or ScanStatus.Partial;

        if (hasProviderFailure)
        {
            return (VerificationOutcome.ScanIncomplete, $"Verification scan incomplete: one or more providers reported status '{scanResult.Status}'.");
        }
        if (failedItems.Count > 0)
        {
            return (VerificationOutcome.CleanupIncomplete, $"Cleanup completed with {failedItems.Count} item(s) that could not be removed.");
        }
        if (stillInstalled)
        {
            return (VerificationOutcome.VerificationIncomplete, "Windows still reports an application registration in inventory.");
        }
        if (remaining.Count == 0)
        {
            if (restartPending)
            {
                return (VerificationOutcome.CleanAfterRestart, "Clean after restart: all live application remnants removed; locked items are scheduled for restart deletion.");
            }
            return (VerificationOutcome.Clean, "Clean: verified that all application registrations, startup entries, services, and remnants have been removed.");
        }

        var hasAutoSelectableRemaining = remaining.Any(r => r.Confidence.IsAtLeast(OwnershipConfidence.High) && r.Risk == RiskLevel.Low);
        if (hasAutoSelectableRemaining)
        {
            return (VerificationOutcome.CleanupIncomplete, $"Verification found {remaining.Count} remaining leftover item(s).");
        }
        return (VerificationOutcome.ResidualItemsRequireReview, $"Verification complete: {remaining.Count} medium/high-risk or optional items remain for review.");
    }
}
