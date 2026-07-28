namespace UninstallMate.Models;

public enum ApplicationKind { Desktop, Msi, MicrosoftStore }
public enum InstallScope { CurrentUser, AllUsers }

public sealed class InstalledApplication
{
    public required string Id { get; init; }
    public required string DisplayName { get; init; }
    public string Publisher { get; init; } = "Unknown publisher";
    public string Version { get; init; } = "";
    public string InstallLocation { get; init; } = "";
    public string DisplayIconPath { get; init; } = "";
    public string UninstallString { get; init; } = "";
    public string QuietUninstallString { get; init; } = "";
    public string RegistryKeyPath { get; init; } = "";
    public string RegistryHive { get; init; } = "";
    public string PackageFullName { get; init; } = "";
    public string PackageFamilyName { get; init; } = "";
    public string Architecture { get; init; } = "";
    public string InstallDate { get; init; } = "";
    public long EstimatedSizeBytes { get; init; }
    public ApplicationKind Kind { get; init; }
    public InstallScope Scope { get; init; }
    public bool IsSystemComponent { get; init; }
    public bool IsProtected { get; init; }
    public bool HasUninstaller => Kind == ApplicationKind.MicrosoftStore || !string.IsNullOrWhiteSpace(UninstallString);
    public string SizeText => EstimatedSizeBytes <= 0 ? "—" : FormatBytes(EstimatedSizeBytes);
    public string DisplayInitial => string.IsNullOrWhiteSpace(DisplayName)
        ? "?"
        : DisplayName.Trim()[0].ToString().ToUpperInvariant();
    public string SourceText => Kind switch
    {
        ApplicationKind.MicrosoftStore => "Store / MSIX",
        ApplicationKind.Msi => "Windows Installer",
        _ => "Desktop"
    };

    private static string FormatBytes(long bytes)
    {
        string[] suffix = ["B", "KB", "MB", "GB", "TB"];
        var value = (double)bytes;
        var unit = 0;
        while (value >= 1024 && unit < suffix.Length - 1) { value /= 1024; unit++; }
        return $"{value:0.#} {suffix[unit]}";
    }
}
