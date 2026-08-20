using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using UninstallMate.Models;

namespace UninstallMate.Services.Providers;

public sealed class FileAssociationProvider : ICleanupArtifactProvider
{
    public string Name => "FileAssociations";

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
                ScanRegisteredApplications(identity, context, candidates, diagnostics, statusAcc, token);
                ScanClassesApplications(identity, context, candidates, diagnostics, statusAcc, token);
                ScanProgIdsAndProtocols(identity, context, candidates, diagnostics, statusAcc, token);
            }
            catch (Exception ex)
            {
                diagnostics.Add(new ScanDiagnostic(Name, $"Error during file association scan: {ex.Message}", IsError: true, ExceptionDetail: ex.ToString()));
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

    private void ScanRegisteredApplications(
        ApplicationIdentityGraph identity,
        CleanupScanContext context,
        List<CleanupCandidate> candidates,
        List<ScanDiagnostic> diagnostics,
        ScanStatusAccumulator statusAcc,
        CancellationToken token)
    {
        const string registeredAppsPath = @"SOFTWARE\RegisteredApplications";
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
                    using var regApps = baseKey.OpenSubKey(registeredAppsPath);
                    if (regApps is null) continue;

                    foreach (var appName in regApps.GetValueNames())
                    {
                        var capabilitiesPath = Convert.ToString(regApps.GetValue(appName)) ?? "";
                        var matchesName = identity.CandidateNames.Any(c => c.Equals(appName, StringComparison.OrdinalIgnoreCase));
                        var matchesCap = identity.CandidateNames.Any(c => capabilitiesPath.Contains(c, StringComparison.OrdinalIgnoreCase))
                            || identity.ReferencesEvidence(capabilitiesPath);

                        if (matchesName || matchesCap)
                        {
                            var target = $@"{hiveText}\{registeredAppsPath}";
                            var candidate = new CleanupCandidate
                            {
                                Target = target,
                                Auxiliary = appName,
                                Kind = CleanupKind.RegistryValue,
                                RegistryViewName = viewName,
                                Risk = RiskLevel.Medium,
                                Confidence = matchesCap ? OwnershipConfidence.High : OwnershipConfidence.Medium,
                                Scope = scope,
                                Reason = $"RegisteredApplications registration references app capabilities '{capabilitiesPath}'",
                                SourceProvider = Name,
                                RegistryValueKindName = "String",
                                RegistryRawValueBase64 = capabilitiesPath,
                                EvidenceList = [$"RegisteredApplication: {appName}", $"Capabilities path: {capabilitiesPath}"],
                                AutoSelectable = false // File associations require review
                            };
                            candidate.IsSelected = CleanupSelectionPolicy.ShouldAutoSelect(candidate);
                            candidates.Add(candidate);
                        }
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    diagnostics.Add(new ScanDiagnostic(Name, $"Access denied scanning RegisteredApplications in {hiveText}", IsWarning: true, TargetPath: $@"{hiveText}\{registeredAppsPath}", ExceptionDetail: ex.Message));
                    statusAcc.MarkAccessDenied();
                }
                catch (Exception ex)
                {
                    diagnostics.Add(new ScanDiagnostic(Name, $"Failed scanning RegisteredApplications in {hiveText}: {ex.Message}", IsWarning: true, TargetPath: $@"{hiveText}\{registeredAppsPath}", ExceptionDetail: ex.Message));
                    statusAcc.MarkWarning();
                }
            }
        }
    }

    private void ScanClassesApplications(
        ApplicationIdentityGraph identity,
        CleanupScanContext context,
        List<CleanupCandidate> candidates,
        List<ScanDiagnostic> diagnostics,
        ScanStatusAccumulator statusAcc,
        CancellationToken token)
    {
        const string rootPath = @"SOFTWARE\Classes\Applications";
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

                    foreach (var appKey in root.GetSubKeyNames())
                    {
                        token.ThrowIfCancellationRequested();
                        using var command = root.OpenSubKey($@"{appKey}\shell\open\command");
                        var value = Convert.ToString(command?.GetValue(null)) ?? "";
                        var matchesEvidence = identity.ReferencesEvidence(value);
                        var matchesExe = identity.ExecutableNames.Any(e => e.Equals(appKey, StringComparison.OrdinalIgnoreCase));

                        if (!matchesEvidence && !matchesExe) continue;

                        var target = $@"{hiveText}\{rootPath}\{appKey}";
                        var candidate = new CleanupCandidate
                        {
                            Target = target,
                            Kind = CleanupKind.RegistryKey,
                            RegistryViewName = viewName,
                            Risk = RiskLevel.Medium,
                            Confidence = matchesEvidence ? OwnershipConfidence.Certain : OwnershipConfidence.Medium,
                            Scope = scope,
                            Reason = "File-association application registration points into the app's installation",
                            SourceProvider = Name,
                            EvidenceList = [$"Classes\\Applications key: {appKey}", $"Command: {value}"],
                            AutoSelectable = false
                        };
                        candidate.IsSelected = CleanupSelectionPolicy.ShouldAutoSelect(candidate);
                        candidates.Add(candidate);
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    diagnostics.Add(new ScanDiagnostic(Name, $"Access denied for Classes\\Applications in {hiveText}", IsWarning: true, TargetPath: $@"{hiveText}\{rootPath}", ExceptionDetail: ex.Message));
                    statusAcc.MarkAccessDenied();
                }
                catch (Exception ex)
                {
                    diagnostics.Add(new ScanDiagnostic(Name, $"Failed scanning Classes\\Applications in {hiveText}: {ex.Message}", IsWarning: true, TargetPath: $@"{hiveText}\{rootPath}", ExceptionDetail: ex.Message));
                    statusAcc.MarkWarning();
                }
            }
        }
    }

    private void ScanProgIdsAndProtocols(
        ApplicationIdentityGraph identity,
        CleanupScanContext context,
        List<CleanupCandidate> candidates,
        List<ScanDiagnostic> diagnostics,
        ScanStatusAccumulator statusAcc,
        CancellationToken token)
    {
        const string rootPath = @"SOFTWARE\Classes";
        var excluded = new HashSet<string>(["CLSID", "Applications", "Installer", "Interface", "TypeLib", "WOW6432Node", "AppID", "MIME", "MediaFileSystems"], StringComparer.OrdinalIgnoreCase);

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

                    foreach (var className in root.GetSubKeyNames())
                    {
                        token.ThrowIfCancellationRequested();
                        if (className.StartsWith('.') || excluded.Contains(className)) continue;

                        using var command = root.OpenSubKey($@"{className}\shell\open\command");
                        using var icon = root.OpenSubKey($@"{className}\DefaultIcon");
                        var commandVal = Convert.ToString(command?.GetValue(null)) ?? "";
                        var iconVal = Convert.ToString(icon?.GetValue(null)) ?? "";
                        var combined = commandVal + ";" + iconVal;

                        if (!identity.ReferencesEvidence(combined)) continue;

                        var target = $@"{hiveText}\{rootPath}\{className}";
                        var candidate = new CleanupCandidate
                        {
                            Target = target,
                            Kind = CleanupKind.RegistryKey,
                            RegistryViewName = viewName,
                            Risk = RiskLevel.Medium,
                            Confidence = OwnershipConfidence.High,
                            Scope = scope,
                            Reason = "Protocol or file-type class registration points into the app's installation",
                            SourceProvider = Name,
                            EvidenceList = [$"Class: {className}", $"Command/Icon: {combined}"],
                            AutoSelectable = false
                        };
                        candidate.IsSelected = CleanupSelectionPolicy.ShouldAutoSelect(candidate);
                        candidates.Add(candidate);
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    diagnostics.Add(new ScanDiagnostic(Name, $"Access denied for Classes in {hiveText}", IsWarning: true, TargetPath: $@"{hiveText}\{rootPath}", ExceptionDetail: ex.Message));
                    statusAcc.MarkAccessDenied();
                }
                catch (Exception ex)
                {
                    diagnostics.Add(new ScanDiagnostic(Name, $"Failed scanning Classes in {hiveText}: {ex.Message}", IsWarning: true, TargetPath: $@"{hiveText}\{rootPath}", ExceptionDetail: ex.Message));
                    statusAcc.MarkWarning();
                }
            }
        }
    }
}
