using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using UninstallMate.Models;

namespace UninstallMate.Services.Providers;

public sealed class AppPathsProvider : ICleanupArtifactProvider
{
    public string Name => "AppPaths";

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
                ScanAppPaths(identity, context, candidates, diagnostics, token);
            }
            catch (Exception ex)
            {
                diagnostics.Add(new ScanDiagnostic(Name, $"Error during App Paths scan: {ex.Message}", IsError: true, ExceptionDetail: ex.ToString()));
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

    private void ScanAppPaths(
        ApplicationIdentityGraph identity,
        CleanupScanContext context,
        List<CleanupCandidate> candidates,
        List<ScanDiagnostic> diagnostics,
        CancellationToken token)
    {
        const string rootPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths";

        foreach (var hiveName in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
        {
            var hiveText = hiveName == RegistryHive.CurrentUser ? "HKEY_CURRENT_USER" : "HKEY_LOCAL_MACHINE";
            var scope = hiveName == RegistryHive.CurrentUser ? CleanupScope.User : CleanupScope.System;

            foreach (var viewName in new[] { "64", "32" })
            {
                token.ThrowIfCancellationRequested();
                try
                {
                    var view = viewName == "32" ? RegistryView.Registry32 : RegistryView.Registry64;
                    using var baseKey = RegistryKey.OpenBaseKey(hiveName, view);
                    using var root = baseKey.OpenSubKey(rootPath);
                    if (root is null) continue;

                    foreach (var name in root.GetSubKeyNames())
                    {
                        token.ThrowIfCancellationRequested();
                        using var key = root.OpenSubKey(name);
                        if (key is null) continue;

                        var defaultVal = Convert.ToString(key.GetValue(null)) ?? "";
                        var pathVal = Convert.ToString(key.GetValue("Path")) ?? "";
                        var combined = defaultVal + ";" + pathVal;

                        var matchesEvidence = identity.ReferencesEvidence(combined);
                        var matchesExe = identity.ExecutableNames.Any(e => e.Equals(name, StringComparison.OrdinalIgnoreCase));
                        var matchesPre = identity.CapturedAppPaths.Any(p => p.ExeName.Equals(name, StringComparison.OrdinalIgnoreCase));

                        if (!matchesEvidence && !matchesExe && !matchesPre) continue;

                        var confidence = (matchesPre || matchesEvidence) ? OwnershipConfidence.Certain : OwnershipConfidence.High;
                        var target = $@"{hiveText}\{rootPath}\{name}";

                        candidates.Add(new CleanupCandidate
                        {
                            Target = target,
                            Kind = CleanupKind.RegistryKey,
                            RegistryViewName = viewName,
                            Risk = RiskLevel.Low,
                            Confidence = confidence,
                            Scope = scope,
                            Reason = $"Windows App Paths registration points into the app's installation ({viewName}-bit view)",
                            SourceProvider = Name,
                            EvidenceList = [$"App Paths key '{name}' -> {defaultVal}"],
                            IsSelected = true
                        });
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    diagnostics.Add(new ScanDiagnostic(Name, $"Access denied for App Paths in {hiveText}", IsWarning: true, TargetPath: $@"{hiveText}\{rootPath}", ExceptionDetail: ex.Message));
                }
                catch (Exception ex)
                {
                    diagnostics.Add(new ScanDiagnostic(Name, $"Failed scanning App Paths in {hiveText} ({viewName}-bit): {ex.Message}", IsWarning: true, TargetPath: $@"{hiveText}\{rootPath}", ExceptionDetail: ex.Message));
                }
            }
        }
    }
}
