using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using UninstallMate.Models;

namespace UninstallMate.Services.Providers;

public sealed class StartupProvider : ICleanupArtifactProvider
{
    public string Name => "Startup";

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
                ScanRegistryRunValues(identity, context, candidates, diagnostics, token);
                ScanStartupFolders(identity, context, candidates, diagnostics, token);
                ScanStartupApprovedValues(identity, context, candidates, diagnostics, token);
            }
            catch (Exception ex)
            {
                diagnostics.Add(new ScanDiagnostic(Name, $"Error during startup scan: {ex.Message}", IsError: true, ExceptionDetail: ex.ToString()));
            }
        }, token);

        var status = diagnostics.Any(d => d.IsError) ? ScanStatus.CompleteWithWarnings : ScanStatus.Complete;
        return new ProviderScanResult
        {
            ProviderName = Name,
            Status = status,
            Candidates = candidates,
            Diagnostics = diagnostics,
            Elapsed = sw.Elapsed
        };
    }

    private void ScanRegistryRunValues(
        ApplicationIdentityGraph identity,
        CleanupScanContext context,
        List<CleanupCandidate> candidates,
        List<ScanDiagnostic> diagnostics,
        CancellationToken token)
    {
        var valueLocations = new[]
        {
            (RegistryHive.CurrentUser, "HKEY_CURRENT_USER", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", RiskLevel.Low, "Startup entry points into the app's installation", CleanupScope.User),
            (RegistryHive.CurrentUser, "HKEY_CURRENT_USER", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", RiskLevel.Low, "One-time startup entry points into the app's installation", CleanupScope.User),
            (RegistryHive.LocalMachine, "HKEY_LOCAL_MACHINE", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", RiskLevel.Low, "Machine startup entry points into the app's installation", CleanupScope.System),
            (RegistryHive.LocalMachine, "HKEY_LOCAL_MACHINE", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", RiskLevel.Low, "Machine one-time startup entry points into the app's installation", CleanupScope.System)
        };

        foreach (var (hive, hiveText, path, risk, reason, scope) in valueLocations)
        {
            foreach (var viewName in new[] { "64", "32" })
            {
                token.ThrowIfCancellationRequested();
                try
                {
                    var view = viewName == "32" ? RegistryView.Registry32 : RegistryView.Registry64;
                    using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                    using var key = baseKey.OpenSubKey(path);
                    if (key is null) continue;
                    foreach (var valueName in key.GetValueNames())
                    {
                        var value = Convert.ToString(key.GetValue(valueName, "", RegistryValueOptions.DoNotExpandEnvironmentNames)) ?? "";
                        var matchesEvidence = identity.ReferencesEvidence(value);
                        var matchesCandidateName = identity.CandidateNames.Any(c => c.Equals(valueName, StringComparison.OrdinalIgnoreCase));
                        var matchesPreUninstall = identity.CapturedStartupSources.Any(s =>
                            s.Hive.Equals(hiveText, StringComparison.OrdinalIgnoreCase)
                            && s.SubKey.Equals(path, StringComparison.OrdinalIgnoreCase)
                            && s.ValueName.Equals(valueName, StringComparison.OrdinalIgnoreCase));

                        if (!matchesEvidence && !matchesCandidateName && !matchesPreUninstall) continue;

                        var confidence = matchesPreUninstall || matchesEvidence ? OwnershipConfidence.Certain : OwnershipConfidence.High;
                        var rawValueObj = key.GetValue(valueName);
                        var kind = key.GetValueKind(valueName);
                        var target = $@"{hiveText}\{path}";

                        candidates.Add(new CleanupCandidate
                        {
                            Target = target,
                            Auxiliary = valueName,
                            Kind = CleanupKind.RegistryValue,
                            RegistryViewName = viewName,
                            Risk = risk,
                            Confidence = confidence,
                            Scope = scope,
                            Reason = $"{reason} ({viewName}-bit view)",
                            SourceProvider = Name,
                            RegistryValueKindName = kind.ToString(),
                            RegistryRawValueBase64 = rawValueObj is byte[] bytes ? Convert.ToBase64String(bytes) : (rawValueObj?.ToString() ?? ""),
                            EvidenceList = [$"Value: {value}", $"Matched startup source '{valueName}'"],
                            IsSelected = risk == RiskLevel.Low && confidence >= OwnershipConfidence.High
                        });
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    diagnostics.Add(new ScanDiagnostic(Name, $"Access denied scanning {hiveText}\\{path}", IsWarning: true, TargetPath: $@"{hiveText}\{path}", ExceptionDetail: ex.Message));
                }
                catch (Exception ex)
                {
                    diagnostics.Add(new ScanDiagnostic(Name, $"Failed scanning {hiveText}\\{path}: {ex.Message}", IsWarning: true, TargetPath: $@"{hiveText}\{path}", ExceptionDetail: ex.Message));
                }
            }
        }
    }

    private void ScanStartupFolders(
        ApplicationIdentityGraph identity,
        CleanupScanContext context,
        List<CleanupCandidate> candidates,
        List<ScanDiagnostic> diagnostics,
        CancellationToken token)
    {
        var roots = new[]
        {
            (Environment.GetFolderPath(Environment.SpecialFolder.Startup), CleanupScope.User),
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), CleanupScope.System)
        }.Where(r => Directory.Exists(r.Item1)).DistinctBy(r => r.Item1, StringComparer.OrdinalIgnoreCase);

        foreach (var (folder, scope) in roots)
        {
            token.ThrowIfCancellationRequested();
            try
            {
                foreach (var file in Directory.EnumerateFiles(folder, "*", SearchOption.TopDirectoryOnly))
                {
                    var ext = Path.GetExtension(file);
                    if (!ext.Equals(".lnk", StringComparison.OrdinalIgnoreCase) && !ext.Equals(".url", StringComparison.OrdinalIgnoreCase))
                        continue;

                    var name = Path.GetFileNameWithoutExtension(file);
                    var matchesName = identity.CandidateNames.Any(c => c.Equals(name, StringComparison.OrdinalIgnoreCase))
                        || identity.CandidateNames.Any(c => name.Equals($"Uninstall {c}", StringComparison.OrdinalIgnoreCase) || name.Equals($"{c} Uninstall", StringComparison.OrdinalIgnoreCase));

                    var matchesPreUninstall = identity.CapturedStartupSources.Any(s => s.ValueName.Equals(Path.GetFileName(file), StringComparison.OrdinalIgnoreCase) || s.ValueName.Equals(name, StringComparison.OrdinalIgnoreCase));

                    if (matchesName || matchesPreUninstall)
                    {
                        var size = 0L;
                        try { size = new FileInfo(file).Length; } catch { }
                        candidates.Add(new CleanupCandidate
                        {
                            Target = file,
                            Kind = CleanupKind.File,
                            Risk = RiskLevel.Low,
                            Confidence = matchesPreUninstall ? OwnershipConfidence.Certain : OwnershipConfidence.High,
                            Reason = "Startup folder shortcut for the removed application",
                            Scope = scope,
                            SizeBytes = size,
                            SourceProvider = Name,
                            EvidenceList = [$"Startup shortcut file: {file}"],
                            IsSelected = true
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                diagnostics.Add(new ScanDiagnostic(Name, $"Failed reading startup folder '{folder}': {ex.Message}", IsWarning: true, TargetPath: folder));
            }
        }
    }

    private void ScanStartupApprovedValues(
        ApplicationIdentityGraph identity,
        CleanupScanContext context,
        List<CleanupCandidate> candidates,
        List<ScanDiagnostic> diagnostics,
        CancellationToken token)
    {
        var approvedLocations = new[]
        {
            (RegistryHive.CurrentUser, "HKEY_CURRENT_USER", @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run", CleanupScope.User),
            (RegistryHive.CurrentUser, "HKEY_CURRENT_USER", @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32", CleanupScope.User),
            (RegistryHive.CurrentUser, "HKEY_CURRENT_USER", @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder", CleanupScope.User),
            (RegistryHive.LocalMachine, "HKEY_LOCAL_MACHINE", @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run", CleanupScope.System),
            (RegistryHive.LocalMachine, "HKEY_LOCAL_MACHINE", @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32", CleanupScope.System),
            (RegistryHive.LocalMachine, "HKEY_LOCAL_MACHINE", @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder", CleanupScope.System)
        };

        foreach (var (hive, hiveText, subKey, scope) in approvedLocations)
        {
            foreach (var viewName in new[] { "64", "32" })
            {
                token.ThrowIfCancellationRequested();
                try
                {
                    var view = viewName == "32" ? RegistryView.Registry32 : RegistryView.Registry64;
                    using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                    using var key = baseKey.OpenSubKey(subKey);
                    if (key is null) continue;

                    foreach (var valueName in key.GetValueNames())
                    {
                        var stemName = Path.GetFileNameWithoutExtension(valueName);

                        // Check correlation against pre-uninstall snapshot
                        var preApproved = identity.CapturedStartupApprovedEntries.FirstOrDefault(e =>
                            e.Hive.Equals(hiveText, StringComparison.OrdinalIgnoreCase)
                            && e.SubKey.Equals(subKey, StringComparison.OrdinalIgnoreCase)
                            && e.ValueName.Equals(valueName, StringComparison.OrdinalIgnoreCase));

                        var preStartupSource = identity.CapturedStartupSources.FirstOrDefault(s =>
                            s.ValueName.Equals(valueName, StringComparison.OrdinalIgnoreCase)
                            || s.ValueName.Equals(stemName, StringComparison.OrdinalIgnoreCase));

                        var exactCandidateMatch = identity.CandidateNames.FirstOrDefault(c =>
                            c.Equals(valueName, StringComparison.OrdinalIgnoreCase)
                            || c.Equals(stemName, StringComparison.OrdinalIgnoreCase));

                        var exeMatch = identity.ExecutableNames.FirstOrDefault(e =>
                            e.Equals(valueName, StringComparison.OrdinalIgnoreCase)
                            || Path.GetFileNameWithoutExtension(e).Equals(valueName, StringComparison.OrdinalIgnoreCase)
                            || Path.GetFileNameWithoutExtension(e).Equals(stemName, StringComparison.OrdinalIgnoreCase));

                        if (preApproved is null && preStartupSource is null && exactCandidateMatch is null && exeMatch is null)
                            continue;

                        var confidence = (preApproved is not null || preStartupSource is not null)
                            ? OwnershipConfidence.Certain
                            : (exactCandidateMatch is not null || exeMatch is not null ? OwnershipConfidence.High : OwnershipConfidence.Medium);

                        var rawObj = key.GetValue(valueName);
                        var rawBytes = rawObj as byte[] ?? [];
                        var rawBase64 = Convert.ToBase64String(rawBytes);
                        var kind = key.GetValueKind(valueName);

                        var target = $@"{hiveText}\{subKey}";
                        var reason = preStartupSource is not null
                            ? $"Stale Task Manager startup entry left behind after the '{preStartupSource.ValueName}' startup source was removed"
                            : "Stale Task Manager startup approval entry matching the application identity";

                        var evidence = new List<string>();
                        if (preStartupSource is not null)
                            evidence.Add($"Correlated with pre-uninstall startup source '{preStartupSource.ValueName}' in {preStartupSource.SubKey}");
                        if (preApproved is not null)
                            evidence.Add($"Captured in pre-uninstall snapshot as {preApproved.CorrelatedSource}");
                        if (exactCandidateMatch is not null)
                            evidence.Add($"Value name matches application name '{exactCandidateMatch}'");
                        if (exeMatch is not null)
                            evidence.Add($"Value name matches application executable '{exeMatch}'");

                        candidates.Add(new CleanupCandidate
                        {
                            Target = target,
                            Auxiliary = valueName,
                            Kind = CleanupKind.RegistryValue,
                            RegistryViewName = viewName,
                            Risk = RiskLevel.Low,
                            Confidence = confidence,
                            Scope = scope,
                            Reason = reason,
                            SourceProvider = Name,
                            RegistryValueKindName = kind.ToString(),
                            RegistryRawValueBase64 = rawBase64,
                            EvidenceList = evidence,
                            IsSelected = confidence >= OwnershipConfidence.High
                        });
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    diagnostics.Add(new ScanDiagnostic(Name, $"Access denied scanning StartupApproved {hiveText}\\{subKey}", IsWarning: true, TargetPath: $@"{hiveText}\{subKey}", ExceptionDetail: ex.Message));
                }
                catch (Exception ex)
                {
                    diagnostics.Add(new ScanDiagnostic(Name, $"Failed scanning StartupApproved {hiveText}\\{subKey}: {ex.Message}", IsWarning: true, TargetPath: $@"{hiveText}\{subKey}", ExceptionDetail: ex.Message));
                }
            }
        }
    }
}
