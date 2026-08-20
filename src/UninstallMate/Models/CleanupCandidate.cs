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

public enum RiskLevel { Low, Medium, High }
public enum CleanupScope { Application, User, System }

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
    public bool AutoSelectable { get; init; } = true;
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

    public string EvidenceSummary => EvidenceList.Count > 0
        ? string.Join(" | ", EvidenceList)
        : (string.IsNullOrEmpty(EvidencePath) ? Reason : $"{Reason} (backed by: {EvidencePath})");

    private static string FormatBytes(long bytes)
    {
        string[] suffix = ["B", "KB", "MB", "GB", "TB"];
        double value = bytes;
        var unit = 0;
        while (value >= 1024 && unit < suffix.Length - 1) { value /= 1024; unit++; }
        return $"{value:0.#} {suffix[unit]}";
    }
}
