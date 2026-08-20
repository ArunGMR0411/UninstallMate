using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using UninstallMate.Models;

namespace UninstallMate.Services.Providers;

public sealed class NativeMessagingProvider : ICleanupArtifactProvider
{
    public string Name => "NativeMessagingHosts";

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
                ScanBrowserHosts(identity, context, candidates, diagnostics, token);
            }
            catch (Exception ex)
            {
                diagnostics.Add(new ScanDiagnostic(Name, $"Error during native messaging host scan: {ex.Message}", IsError: true, ExceptionDetail: ex.ToString()));
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

    private void ScanBrowserHosts(
        ApplicationIdentityGraph identity,
        CleanupScanContext context,
        List<CleanupCandidate> candidates,
        List<ScanDiagnostic> diagnostics,
        CancellationToken token)
    {
        var hostPaths = new[]
        {
            @"SOFTWARE\Google\Chrome\NativeMessagingHosts",
            @"SOFTWARE\Microsoft\Edge\NativeMessagingHosts",
            @"SOFTWARE\Mozilla\NativeMessagingHosts"
        };

        foreach (var hiveName in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
        {
            var hiveText = hiveName == RegistryHive.CurrentUser ? "HKEY_CURRENT_USER" : "HKEY_LOCAL_MACHINE";
            var scope = hiveName == RegistryHive.CurrentUser ? CleanupScope.User : CleanupScope.System;

            foreach (var subKeyPath in hostPaths)
            {
                foreach (var viewName in new[] { "64", "32" })
                {
                    token.ThrowIfCancellationRequested();
                    try
                    {
                        var view = viewName == "32" ? RegistryView.Registry32 : RegistryView.Registry64;
                        using var baseKey = RegistryKey.OpenBaseKey(hiveName, view);
                        using var root = baseKey.OpenSubKey(subKeyPath);
                        if (root is null) continue;

                        foreach (var hostName in root.GetSubKeyNames())
                        {
                            using var hostKey = root.OpenSubKey(hostName);
                            if (hostKey is null) continue;

                            var manifestPath = Convert.ToString(hostKey.GetValue(null)) ?? "";
                            var matchesEvidence = identity.ReferencesEvidence(manifestPath);
                            var matchesName = identity.CandidateNames.Any(c => c.Equals(hostName, StringComparison.OrdinalIgnoreCase));

                            if (matchesEvidence || matchesName)
                            {
                                var target = $@"{hiveText}\{subKeyPath}\{hostName}";
                                candidates.Add(new CleanupCandidate
                                {
                                    Target = target,
                                    Kind = CleanupKind.RegistryKey,
                                    RegistryViewName = viewName,
                                    Risk = RiskLevel.Low,
                                    Confidence = matchesEvidence ? OwnershipConfidence.Certain : OwnershipConfidence.High,
                                    Scope = scope,
                                    Reason = $"Browser native messaging host registration ({viewName}-bit view)",
                                    SourceProvider = Name,
                                    EvidenceList = [$"Host name: {hostName}", $"Manifest: {manifestPath}"],
                                    IsSelected = true
                                });
                            }
                        }
                    }
                    catch { }
                }
            }
        }
    }
}
