namespace UninstallMate.Models;

public sealed record OperationResult(bool Success, string Message, int ExitCode = 0);

public sealed class CleanupReport
{
    public string SchemaVersion { get; init; } = "2.0";
    public string SessionId { get; init; } = "";
    public DateTimeOffset StartedAt { get; init; } = DateTimeOffset.Now;
    public DateTimeOffset FinishedAt { get; set; }
    public required string ApplicationName { get; init; }
    public string FinalStatus { get; set; } = "Complete";
    public bool RestartRequired { get; set; }
    public List<CleanupReportItem> Items { get; init; } = [];
    public List<ScanDiagnostic> Diagnostics { get; init; } = [];
}

public sealed record CleanupReportItem(
    string Target,
    CleanupKind Kind,
    bool Success,
    string Detail,
    string RecoverySource = "",
    string RegistryViewName = "Default",
    string Auxiliary = "",
    string EvidencePath = "",
    RiskLevel Risk = RiskLevel.Low,
    OwnershipConfidence Confidence = OwnershipConfidence.High,
    string SourceProvider = "",
    string RegistryValueKindName = "",
    string RegistryRawValueBase64 = "",
    string StructuredPayloadJson = "",
    string VerificationStatus = "Unknown");

public sealed class RegistryValueBackupData
{
    public required string Hive { get; init; }
    public required string SubKey { get; init; }
    public required string View { get; init; }
    public required string ValueName { get; init; }
    public required string ValueKind { get; init; }
    public required string RawValueBase64 { get; init; }
    public string StringValue { get; init; } = "";
}

public sealed class ServiceBackupData
{
    public required string ServiceName { get; init; }
    public string DisplayName { get; init; } = "";
    public string ImagePath { get; init; } = "";
    public string ServiceDll { get; init; } = "";
    public int ServiceType { get; init; }
    public int StartType { get; init; }
    public string Description { get; init; } = "";
}

public sealed class PathSegmentBackupData
{
    public required string Hive { get; init; }
    public required string SubKey { get; init; }
    public required string View { get; init; }
    public required string ValueName { get; init; }
    public required string RemovedSegment { get; init; }
}
