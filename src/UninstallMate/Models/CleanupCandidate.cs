using UninstallMate.Infrastructure;

namespace UninstallMate.Models;

public enum CleanupKind
{
    File,
    Directory,
    RegistryKey,
    RegistryValue,
    EnvironmentEntry,
    WindowsService,
    ScheduledTask,
    FirewallRule,
    NativeMessagingHost,
    EventLogSource
}

public enum RiskLevel
{
    Low = 0,
    Medium = 1,
    High = 2
}

public static class RiskLevelExtensions
{
    public static RiskLevel Highest(RiskLevel a, RiskLevel b)
        => a >= b ? a : b;

    public static RiskLevel Lowest(RiskLevel a, RiskLevel b)
        => a <= b ? a : b;
}

public enum CleanupScope { Application, User, System }

public static class CleanupSelectionPolicy
{
    public static bool ShouldAutoSelect(CleanupCandidate candidate)
        => candidate.AutoSelectable
           && candidate.Risk == RiskLevel.Low
           && candidate.Confidence.IsAtLeast(OwnershipConfidence.High);
}

public sealed class CleanupCandidate : ObservableObject
{
    private bool _isSelected;
    public required string Target { get; init; }
    public required CleanupKind Kind { get; init; }
    public required RiskLevel Risk { get; init; }
    public OwnershipConfidence Confidence { get; init; } = OwnershipConfidence.High;
    public required string Reason { get; init; }
    public long SizeBytes { get; init; }
    public string RegistryViewName { get; init; } = "Default";
    public string Auxiliary { get; init; } = "";
    public string EvidencePath { get; init; } = "";
    public List<string> EvidenceList { get; init; } = [];
    public string SourceProvider { get; init; } = "";
    public bool OriginalExists { get; init; } = true;
    public bool DetectedBeforeUninstall { get; init; }
    public bool DetectedAfterUninstall { get; init; } = true;
    public bool RequiresReboot { get; init; }
    public bool AutoSelectable { get; set; } = true;
    public string RegistryValueKindName { get; init; } = "";
    public string RegistryRawValueBase64 { get; init; } = "";
    public CleanupScope Scope { get; init; }

    public bool IsSelected
    {
        get => _isSelected;
        set => SetProperty(ref _isSelected, value);
    }

    public string DisplayTarget => Auxiliary.Length == 0 ? Target : $"{Target}  ·  {Auxiliary}";
    public string SizeText => SizeBytes <= 0 ? "—" : FormatBytes(SizeBytes);
    public string ConfidenceText => Confidence switch
    {
        OwnershipConfidence.Certain => "Certain",
        OwnershipConfidence.High => "High",
        OwnershipConfidence.Medium => "Medium",
        OwnershipConfidence.Low => "Low",
        _ => "Unknown"
    };
    public string RiskText => Risk switch
    {
        RiskLevel.Low => "Low",
        RiskLevel.Medium => "Medium",
        RiskLevel.High => "High",
        _ => "Unknown"
    };

    private static string FormatBytes(long bytes) => bytes switch
    {
        >= 1024 * 1024 * 1024 => $"{bytes / (1024.0 * 1024 * 1024):0.1} GB",
        >= 1024 * 1024 => $"{bytes / (1024.0 * 1024):0.1} MB",
        >= 1024 => $"{bytes / 1024.0:0.0} KB",
        _ => $"{bytes} B"
    };
}
