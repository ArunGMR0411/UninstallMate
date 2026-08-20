using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using UninstallMate.Models;

namespace UninstallMate.Services.Providers;

public sealed class RegistryProvider : ICleanupArtifactProvider
{
    public string Name => "Registry";

    public async Task<ProviderScanResult> ScanAsync(
        ApplicationIdentityGraph identity,
        CleanupScanContext context,
        CancellationToken token)
    {
        var sw = Stopwatch.StartNew();
        var candidates = new List<CleanupCandidate>();
        var diagnostics = new List<ScanDiagnostic>();

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return ProviderScanResult.Succeeded(Name, candidates, sw.Elapsed);
        }

        await Task.Run(() =>
        {
            try
            {
                ScanUninstallEntries(identity, context, candidates, diagnostics, token);
                ScanSoftwareKeys(identity, context, candidates, diagnostics, token);
            }
            catch (Exception ex)
            {
                diagnostics.Add(new ScanDiagnostic(Name, $"Error during registry scan: {ex.Message}", IsError: true, ExceptionDetail: ex.ToString()));
            }
        }, token);

        return new ProviderScanResult
        {
            ProviderName = Name,
            Status = diagnostics.Any(d => d.IsError) ? ScanStatus.CompleteWithWarnings : ScanStatus.Complete,
            Candidates = candidates,
            Diagnostics = diagnostics,
            Elapsed = sw.Elapsed
        };
    }

    private void ScanUninstallEntries(
        ApplicationIdentityGraph identity,
        CleanupScanContext context,
        List<CleanupCandidate> candidates,
        List<ScanDiagnostic> diagnostics,
        CancellationToken token)
    {
        if (identity.Kind == ApplicationKind.MicrosoftStore) return;

        var appRegistryView = identity.Application.Architecture == "32-bit" ? "32"
            : identity.Application.Architecture == "64-bit" ? "64" : "Default";

        if (!string.IsNullOrWhiteSpace(identity.RegistryKeyPath) && RegistryPathExists(identity.RegistryKeyPath, appRegistryView))
        {
            candidates.Add(new CleanupCandidate
            {
                Target = identity.RegistryKeyPath,
                Kind = CleanupKind.RegistryKey,
                Risk = RiskLevel.Low,
                Confidence = OwnershipConfidence.Certain,
                Reason = "The application's registered uninstall entry",
                RegistryViewName = appRegistryView,
                Scope = identity.RegistryKeyPath.StartsWith("HKEY_CURRENT_USER", StringComparison.OrdinalIgnoreCase) ? CleanupScope.User : CleanupScope.System,
                SourceProvider = Name,
                EvidenceList = [$"Registered key: {identity.RegistryKeyPath}"],
                IsSelected = true
            });
        }

        // Equivalent registrations across other views/hives
        const string uninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        foreach (var hiveName in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
        {
            var hiveText = hiveName == RegistryHive.CurrentUser ? "HKEY_CURRENT_USER" : "HKEY_LOCAL_MACHINE";
            foreach (var view in new[] { "64", "32" })
            {
                try
                {
                    using var hive = OpenHive(hiveName, view);
                    using var root = hive.OpenSubKey(uninstallPath);
                    if (root is null) continue;
                    foreach (var keyName in root.GetSubKeyNames())
                    {
                        token.ThrowIfCancellationRequested();
                        using var key = root.OpenSubKey(keyName);
                        if (key is null || !EquivalentRegistration(identity.Application, key)) continue;
                        var path = $@"{hiveText}\{uninstallPath}\{keyName}";
                        if (candidates.Any(c => c.Target.Equals(path, StringComparison.OrdinalIgnoreCase) && c.RegistryViewName == view))
                            continue;

                        candidates.Add(new CleanupCandidate
                        {
                            Target = path,
                            Kind = CleanupKind.RegistryKey,
                            Risk = RiskLevel.Low,
                            Confidence = OwnershipConfidence.Certain,
                            Reason = path.Equals(identity.RegistryKeyPath, StringComparison.OrdinalIgnoreCase)
                                ? "The application's registered uninstall entry"
                                : "Duplicate registration for the same application in another registry scope/view",
                            RegistryViewName = view,
                            Scope = hiveName == RegistryHive.CurrentUser ? CleanupScope.User : CleanupScope.System,
                            SourceProvider = Name,
                            EvidenceList = [$"Uninstall registration matching '{identity.DisplayName}'"],
                            IsSelected = true
                        });
                    }
                }
                catch (Exception ex)
                {
                    diagnostics.Add(new ScanDiagnostic(Name, $"Failed scanning uninstall keys in {hiveText} ({view}-bit): {ex.Message}", IsWarning: true));
                }
            }
        }
    }

    private void ScanSoftwareKeys(
        ApplicationIdentityGraph identity,
        CleanupScanContext context,
        List<CleanupCandidate> candidates,
        List<ScanDiagnostic> diagnostics,
        CancellationToken token)
    {
        var names = identity.CandidateNames.ToArray();
        foreach (var hive in new[] { "HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE" })
        {
            var scope = hive == "HKEY_CURRENT_USER" ? CleanupScope.User : CleanupScope.System;
            foreach (var name in names)
            {
                token.ThrowIfCancellationRequested();
                AddRegistryIfPresent($@"{hive}\SOFTWARE\{name}", "Exact app-named software key", candidates, diagnostics, scope, name);
            }

            var publisher = SafeSegment(identity.Publisher);
            if (publisher.Length >= 3 && !publisher.Equals("Microsoft Corporation", StringComparison.OrdinalIgnoreCase))
            {
                foreach (var name in names)
                {
                    token.ThrowIfCancellationRequested();
                    AddRegistryIfPresent($@"{hive}\SOFTWARE\{publisher}\{name}", "App key below its publisher key", candidates, diagnostics, scope, $"{publisher}\\{name}");
                }
            }
        }
    }

    private void AddRegistryIfPresent(
        string path,
        string reason,
        List<CleanupCandidate> candidates,
        List<ScanDiagnostic> diagnostics,
        CleanupScope scope,
        string matchName)
    {
        foreach (var view in new[] { "64", "32" })
        {
            try
            {
                if (!RegistryPathExists(path, view)) continue;
                candidates.Add(new CleanupCandidate
                {
                    Target = path,
                    Kind = CleanupKind.RegistryKey,
                    Risk = RiskLevel.Medium,
                    Confidence = OwnershipConfidence.High,
                    Reason = $"{reason} ({view}-bit view; may contain shared settings)",
                    RegistryViewName = view,
                    Scope = scope,
                    SourceProvider = Name,
                    EvidenceList = [$"Registry key matched '{matchName}' in {view}-bit view"],
                    IsSelected = false // Software keys under publisher might be medium risk
                });
            }
            catch (Exception ex)
            {
                diagnostics.Add(new ScanDiagnostic(Name, $"Failed checking registry path '{path}' ({view}-bit): {ex.Message}", IsWarning: true, TargetPath: path));
            }
        }
    }

    private static bool EquivalentRegistration(InstalledApplication app, RegistryKey key)
    {
        static string Read(RegistryKey source, string name) => (Convert.ToString(source.GetValue(name)) ?? "").Trim();
        if (!Read(key, "DisplayName").Equals(app.DisplayName.Trim(), StringComparison.CurrentCultureIgnoreCase)) return false;
        var publisher = Read(key, "Publisher");
        if (publisher.Length > 0 && app.Publisher.Length > 0
            && !publisher.Equals(app.Publisher.Trim(), StringComparison.CurrentCultureIgnoreCase)) return false;
        var version = Read(key, "DisplayVersion");
        if (version.Length > 0 && app.Version.Length > 0
            && !version.Equals(app.Version.Trim(), StringComparison.CurrentCultureIgnoreCase)) return false;
        var location = Environment.ExpandEnvironmentVariables(Read(key, "InstallLocation")).Trim().Trim('"');
        if (location.Length > 0 && app.InstallLocation.Length > 0)
        {
            try
            {
                if (!Path.GetFullPath(location).TrimEnd('\\').Equals(
                    Path.GetFullPath(app.InstallLocation).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) return false;
            }
            catch { return false; }
        }
        return true;
    }

    private static bool RegistryPathExists(string fullPath, string viewName = "Default")
    {
        try
        {
            var (hiveName, subKey) = CleanupScanner.SplitRegistryPath(fullPath);
            using var hive = OpenHive(hiveName, viewName);
            using var key = hive.OpenSubKey(subKey);
            return key is not null;
        }
        catch { return false; }
    }

    private static RegistryKey OpenHive(RegistryHive hive, string viewName) => RegistryKey.OpenBaseKey(hive, viewName switch
    {
        "32" => RegistryView.Registry32,
        "64" => RegistryView.Registry64,
        _ => RegistryView.Default
    });

    private static string SafeSegment(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Equals("Unknown publisher", StringComparison.OrdinalIgnoreCase)) return "";
        var invalid = Path.GetInvalidFileNameChars();
        return string.Concat(value.Trim().Where(c => !invalid.Contains(c))).TrimEnd('.');
    }
}
