using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using UninstallMate.Models;

namespace UninstallMate.Services.Providers;

public sealed class EnvironmentProvider : ICleanupArtifactProvider
{
    public string Name => "Environment";

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
                ScanEnvironment(RegistryHive.CurrentUser, "HKEY_CURRENT_USER", @"Environment", CleanupScope.User, identity, context, candidates, diagnostics, token);
                ScanEnvironment(RegistryHive.LocalMachine, "HKEY_LOCAL_MACHINE", @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", CleanupScope.System, identity, context, candidates, diagnostics, token);
            }
            catch (Exception ex)
            {
                diagnostics.Add(new ScanDiagnostic(Name, $"Error during environment scan: {ex.Message}", IsError: true, ExceptionDetail: ex.ToString()));
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

    private void ScanEnvironment(
        RegistryHive hiveName,
        string hiveText,
        string subKey,
        CleanupScope scope,
        ApplicationIdentityGraph identity,
        CleanupScanContext context,
        List<CleanupCandidate> candidates,
        List<ScanDiagnostic> diagnostics,
        CancellationToken token)
    {
        var evidenceRoots = identity.EvidenceRoots.ToArray();
        if (evidenceRoots.Length == 0 && identity.CandidateNames.Count == 0) return;

        foreach (var viewName in new[] { "64", "32" })
        {
            token.ThrowIfCancellationRequested();
            try
            {
                var view = viewName == "32" ? RegistryView.Registry32 : RegistryView.Registry64;
                using var hive = RegistryKey.OpenBaseKey(hiveName, view);
                using var key = hive.OpenSubKey(subKey);
                if (key is null) continue;

                foreach (var valueName in key.GetValueNames())
                {
                    var value = Convert.ToString(key.GetValue(valueName, "", RegistryValueOptions.DoNotExpandEnvironmentNames)) ?? "";
                    var target = $@"{hiveText}\{subKey}";

                    if (valueName.Equals("Path", StringComparison.OrdinalIgnoreCase))
                    {
                        var matchingEvidence = evidenceRoots.FirstOrDefault(root => ReferencesEvidencePath(value, [root]));
                        if (matchingEvidence is not null)
                        {
                            candidates.Add(new CleanupCandidate
                            {
                                Target = target,
                                Auxiliary = valueName,
                                EvidencePath = matchingEvidence,
                                Kind = CleanupKind.EnvironmentEntry,
                                RegistryViewName = viewName,
                                Risk = RiskLevel.High,
                                Confidence = OwnershipConfidence.Certain,
                                Scope = scope,
                                Reason = "An app installation directory remains in PATH; cleanup removes only matching PATH segments",
                                SourceProvider = Name,
                                EvidenceList = [$"PATH segment points into: {matchingEvidence}"],
                                IsSelected = false // Environment PATH edit requires review
                            });
                        }
                    }
                    else
                    {
                        var matchesPath = evidenceRoots.Any(root => ReferencesEvidencePath(value, [root]));
                        var matchesName = identity.CandidateNames.Any(c => c.Equals(valueName, StringComparison.OrdinalIgnoreCase));
                        if (matchesPath || matchesName)
                        {
                            var kind = key.GetValueKind(valueName);
                            var rawObj = key.GetValue(valueName, "", RegistryValueOptions.DoNotExpandEnvironmentNames);
                            candidates.Add(new CleanupCandidate
                            {
                                Target = target,
                                Auxiliary = valueName,
                                Kind = CleanupKind.RegistryValue,
                                RegistryViewName = viewName,
                                Risk = RiskLevel.High,
                                Confidence = matchesPath ? OwnershipConfidence.Certain : OwnershipConfidence.Medium,
                                Scope = scope,
                                Reason = "Environment variable points into the app's installation",
                                SourceProvider = Name,
                                RegistryValueKindName = kind.ToString(),
                                RegistryRawValueBase64 = rawObj?.ToString() ?? "",
                                EvidenceList = [$"Environment variable '{valueName}' = '{value}'"],
                                IsSelected = false
                            });
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                diagnostics.Add(new ScanDiagnostic(Name, $"Access denied for environment key {hiveText}\\{subKey}", IsWarning: true, TargetPath: $@"{hiveText}\{subKey}", ExceptionDetail: ex.Message));
            }
            catch (Exception ex)
            {
                diagnostics.Add(new ScanDiagnostic(Name, $"Failed scanning environment in {hiveText}\\{subKey}: {ex.Message}", IsWarning: true, TargetPath: $@"{hiveText}\{subKey}", ExceptionDetail: ex.Message));
            }
        }
    }

    private static bool ReferencesEvidencePath(string value, IEnumerable<string> evidenceRoots) =>
        CleanupScanner.ReferencesEvidencePath(value, evidenceRoots);
}
