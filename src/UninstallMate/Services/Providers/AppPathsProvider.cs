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
        var statusAcc = new ScanStatusAccumulator();

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return ProviderScanResult.Succeeded(Name, candidates, sw.Elapsed);
        }

        await Task.Run(() =>
        {
            try
            {
                ScanAppPaths(identity, context, candidates, diagnostics, statusAcc, token);
            }
            catch (Exception ex)
            {
                diagnostics.Add(new ScanDiagnostic(Name, $"Error during App Paths scan: {ex.Message}", IsError: true, ExceptionDetail: ex.ToString()));
                statusAcc.MarkFailed();
            }
        }, token);

        return new ProviderScanResult
        {
            ProviderName = Name,
            Status = statusAcc.Status,
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
        ScanStatusAccumulator statusAcc,
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
                        var matchesExe = identity.ExecutableNames.Any(e => e.Equals(name, StringComparison.OrdinalIgnoreCase))
                            || identity.CandidateNames.Any(c => c.Equals(name, StringComparison.OrdinalIgnoreCase));

                        var matchingPre = identity.CapturedAppPaths.FirstOrDefault(p =>
                            p.Hive == hiveName && p.View == view && p.ExeName.Equals(name, StringComparison.OrdinalIgnoreCase));

                        if (!matchesEvidence && !matchesExe && matchingPre is null) continue;

                        OwnershipConfidence confidence;
                        RiskLevel risk;
                        bool autoSelect;

                        if (matchesEvidence)
                        {
                            confidence = OwnershipConfidence.Certain;
                            risk = RiskLevel.Low;
                            autoSelect = true;
                        }
                        else if (matchingPre is not null && matchingPre.Confidence.IsAtLeast(OwnershipConfidence.High))
                        {
                            confidence = matchingPre.Confidence;
                            risk = RiskLevel.Low;
                            autoSelect = true;
                        }
                        else
                        {
                            // Name-only match without path evidence remains Medium confidence, Medium risk, not auto-selectable
                            confidence = OwnershipConfidence.Medium;
                            risk = RiskLevel.Medium;
                            autoSelect = false;
                        }

                        var target = $@"{hiveText}\{rootPath}\{name}";
                        var reason = matchesEvidence
                            ? $"Windows App Paths registration points into the app's installation: {defaultVal} ({viewName}-bit view)"
                            : (matchingPre is not null && matchingPre.Confidence == OwnershipConfidence.Certain
                                ? $"Pre-uninstall verified App Paths registration for '{name}'"
                                : $"App Paths registration '{name}' matches application executable name; review before removal");

                        var evidence = new List<string> { $"App Paths key '{name}' -> {defaultVal}" };
                        if (matchingPre is not null) evidence.AddRange(matchingPre.Evidence);

                        var candidate = new CleanupCandidate
                        {
                            Target = target,
                            Kind = CleanupKind.RegistryKey,
                            RegistryViewName = viewName,
                            Risk = risk,
                            Confidence = confidence,
                            Scope = scope,
                            Reason = reason,
                            SourceProvider = Name,
                            EvidenceList = evidence,
                            AutoSelectable = autoSelect
                        };
                        candidate.IsSelected = CleanupSelectionPolicy.ShouldAutoSelect(candidate);
                        candidates.Add(candidate);
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    diagnostics.Add(new ScanDiagnostic(Name, $"Access denied for App Paths in {hiveText}", IsWarning: true, TargetPath: $@"{hiveText}\{rootPath}", ExceptionDetail: ex.Message));
                    statusAcc.MarkAccessDenied();
                }
                catch (Exception ex)
                {
                    diagnostics.Add(new ScanDiagnostic(Name, $"Failed scanning App Paths in {hiveText} ({viewName}-bit): {ex.Message}", IsWarning: true, TargetPath: $@"{hiveText}\{rootPath}", ExceptionDetail: ex.Message));
                    statusAcc.MarkWarning();
                }
            }
        }
    }
}
