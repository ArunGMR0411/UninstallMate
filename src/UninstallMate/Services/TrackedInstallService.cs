using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using UninstallMate.Models;

namespace UninstallMate.Services;

public sealed class TrackedInstallService
{
    private readonly string _storageRoot;

    public TrackedInstallService(string? storageRoot = null)
    {
        _storageRoot = storageRoot ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "UninstallMate",
            "TrackedInstalls");
    }

    public static string DefaultStorageRoot => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "UninstallMate",
        "TrackedInstalls");

    public async Task<TrackedInstallManifest> StartTrackingAsync(
        string installerPath,
        string arguments,
        CancellationToken token)
    {
        Directory.CreateDirectory(_storageRoot);
        var sessionId = $"{DateTime.Now:yyyyMMdd-HHmmss}-{Path.GetFileNameWithoutExtension(installerPath)}";

        var manifest = new TrackedInstallManifest
        {
            SessionId = sessionId,
            InstallerPath = installerPath
        };

        if (!File.Exists(installerPath))
            throw new FileNotFoundException("Installer file not found.", installerPath);

        // Execute installer
        var start = new ProcessStartInfo
        {
            FileName = installerPath,
            Arguments = arguments,
            UseShellExecute = true
        };

        using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not launch installer.");
        await process.WaitForExitAsync(token);

        manifest.CompletedAt = DateTimeOffset.Now;
        await SaveManifestAsync(manifest, token);
        return manifest;
    }

    public async Task SaveManifestAsync(TrackedInstallManifest manifest, CancellationToken token)
    {
        Directory.CreateDirectory(_storageRoot);
        var path = Path.Combine(_storageRoot, $"{manifest.SessionId}.json");
        var json = JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(path, json, token);
    }

    public TrackedInstallManifest? FindManifestForApplication(InstalledApplication app)
    {
        if (!Directory.Exists(_storageRoot)) return null;
        try
        {
            foreach (var file in Directory.EnumerateFiles(_storageRoot, "*.json"))
            {
                try
                {
                    var manifest = JsonSerializer.Deserialize<TrackedInstallManifest>(File.ReadAllText(file));
                    if (manifest is not null && !string.IsNullOrWhiteSpace(manifest.ApplicationDisplayName))
                    {
                        if (manifest.ApplicationDisplayName.Equals(app.DisplayName, StringComparison.OrdinalIgnoreCase))
                            return manifest;
                    }
                }
                catch { }
            }
        }
        catch { }
        return null;
    }
}
