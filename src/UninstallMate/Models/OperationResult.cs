namespace UninstallMate.Models;

public sealed record OperationResult(bool Success, string Message, int ExitCode = 0);

public sealed class CleanupReport
{
    public DateTimeOffset StartedAt { get; init; } = DateTimeOffset.Now;
    public DateTimeOffset FinishedAt { get; set; }
    public required string ApplicationName { get; init; }
    public List<CleanupReportItem> Items { get; init; } = [];
}

public sealed record CleanupReportItem(
    string Target,
    CleanupKind Kind,
    bool Success,
    string Detail,
    string RecoverySource = "",
    string RegistryViewName = "Default",
    string Auxiliary = "",
    string EvidencePath = "");
