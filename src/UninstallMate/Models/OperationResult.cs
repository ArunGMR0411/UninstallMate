namespace UninstallMate.Models;

public sealed record OperationResult(bool Success, string Message, int ExitCode = 0);

public sealed class CleanupSafetyException : Exception
{
    public CleanupSafetyException(string message) : base(message) { }
    public CleanupSafetyException(string message, Exception inner) : base(message, inner) { }
}

public sealed class CleanupReport
{
    public string SchemaVersion { get; init; } = "3.0";
    public string SessionId { get; init; } = "";
    public DateTimeOffset StartedAt { get; init; } = DateTimeOffset.Now;
    public DateTimeOffset FinishedAt { get; set; }
    public required string ApplicationName { get; init; }
    public string FinalStatus { get; set; } = "InProgress";
    public bool RestartRequired { get; set; }
    public List<CleanupReportItem> Items { get; init; } = [];
    public List<ScanDiagnostic> Diagnostics { get; init; } = [];
    public VerificationReportData? Verification { get; set; }
}

public sealed class VerificationReportData
{
    public required string Outcome { get; init; }
    public required string OutcomeMessage { get; init; }
    public int RemainingCount { get; init; }
    public bool RestartRequired { get; init; }
    public bool InventoryStillPresent { get; init; }
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
    public string SchemaVersion { get; init; } = "2.0";
    public required string Hive { get; init; }
    public required string View { get; init; }
    public required string SubKey { get; init; }
    public required string ValueName { get; init; }
    public required string ValueKind { get; init; }

    public string? StringValue { get; init; }
    public string[]? MultiStringValue { get; init; }
    public int? DWordValue { get; init; }
    public long? QWordValue { get; init; }
    public byte[]? BinaryValue { get; init; }
    public string RawValueBase64 { get; init; } = "";
}

public sealed class RegistryValueBackupBundle
{
    public string SchemaVersion { get; init; } = "2.0";
    public List<RegistryValueBackupData> Values { get; init; } = [];
}

public sealed class ServiceBackupData
{
    public required string ServiceName { get; init; }
    public string DisplayName { get; init; } = "";
    public string ImagePath { get; init; } = "";
    public string ServiceDll { get; init; } = "";
    public int ServiceType { get; init; }
    public int StartType { get; init; }
    public int ErrorControl { get; init; } = 1;
    public string ServiceAccount { get; init; } = "";
    public string[] Dependencies { get; init; } = [];
    public bool DelayedAutoStart { get; init; }
    public string Description { get; init; } = "";
    public Dictionary<string, string> Parameters { get; init; } = [];
}

public sealed class PathSegmentBackupData
{
    public required string Hive { get; init; }
    public required string SubKey { get; init; }
    public required string View { get; init; }
    public required string ValueName { get; init; }
    public required string RemovedSegment { get; init; }
    public int OriginalIndex { get; init; }
    public string PreviousSegment { get; init; } = "";
    public string NextSegment { get; init; } = "";
}

public sealed class FirewallRuleBackupData
{
    public required string RuleName { get; init; }
    public string AppPath { get; init; } = "";
    public string ServiceName { get; init; } = "";
    public string RawRuleData { get; init; } = "";
}
