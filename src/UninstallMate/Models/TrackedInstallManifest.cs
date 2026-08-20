namespace UninstallMate.Models;

public sealed class TrackedInstallManifest
{
    public string SchemaVersion { get; init; } = "1.0";
    public required string SessionId { get; init; }
    public required string InstallerPath { get; init; }
    public string ApplicationDisplayName { get; set; } = "";
    public string Publisher { get; set; } = "";
    public string Version { get; set; } = "";
    public DateTimeOffset StartedAt { get; init; } = DateTimeOffset.Now;
    public DateTimeOffset CompletedAt { get; set; }
    public List<string> CreatedFiles { get; init; } = [];
    public List<string> CreatedDirectories { get; init; } = [];
    public List<string> CreatedRegistryKeys { get; init; } = [];
    public List<string> CreatedRegistryValues { get; init; } = [];
    public List<string> CreatedServices { get; init; } = [];
    public List<string> CreatedScheduledTasks { get; init; } = [];
    public List<string> CreatedFirewallRules { get; init; } = [];
}
