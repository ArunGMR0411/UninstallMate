namespace UninstallMate.Models;

public enum ScanStatus
{
    Complete,
    CompleteWithWarnings,
    Partial,
    AccessDenied,
    Failed,
    NotApplicable
}

public sealed record ScanDiagnostic(
    string ProviderName,
    string Message,
    bool IsWarning = false,
    bool IsError = false,
    string? TargetPath = null,
    string? ExceptionDetail = null);

public sealed class ProviderScanResult
{
    public required string ProviderName { get; init; }
    public required ScanStatus Status { get; init; }
    public IReadOnlyList<CleanupCandidate> Candidates { get; init; } = [];
    public IReadOnlyList<ScanDiagnostic> Diagnostics { get; init; } = [];
    public TimeSpan Elapsed { get; init; } = TimeSpan.Zero;

    public static ProviderScanResult Succeeded(string providerName, IReadOnlyList<CleanupCandidate> candidates, TimeSpan elapsed = default) =>
        new()
        {
            ProviderName = providerName,
            Status = ScanStatus.Complete,
            Candidates = candidates,
            Elapsed = elapsed
        };

    public static ProviderScanResult FailedResult(string providerName, string errorMessage, string? exceptionDetail = null, TimeSpan elapsed = default) =>
        new()
        {
            ProviderName = providerName,
            Status = ScanStatus.Failed,
            Diagnostics = [new ScanDiagnostic(providerName, errorMessage, IsError: true, ExceptionDetail: exceptionDetail)],
            Elapsed = elapsed
        };

    public static ProviderScanResult AccessDeniedResult(string providerName, string targetPath, string message, TimeSpan elapsed = default) =>
        new()
        {
            ProviderName = providerName,
            Status = ScanStatus.AccessDenied,
            Diagnostics = [new ScanDiagnostic(providerName, message, IsWarning: true, TargetPath: targetPath)],
            Elapsed = elapsed
        };
}
