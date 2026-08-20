using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using UninstallMate.Models;

namespace UninstallMate.Services.Providers;

public sealed class StartupProvider : ICleanupArtifactProvider
{
    public string Name => "StartupEntries";

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
                ScanRunSubKeys(identity, context, candidates, diagnostics, token);
                ScanStartupFolder(identity, context, candidates, diagnostics, token);
                ScanStartupApprovedSubKeys(identity, context, candidates, diagnostics, token);
            }
            catch (Exception ex)
            {
                diagnostics.Add(new ScanDiagnostic(Name, $"Error during startup scan: {ex.Message}", IsError: true, ExceptionDetail: ex.ToString()));
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

    private void ScanRunSubKeys(
        ApplicationIdentityGraph identity,
        CleanupScanContext context,
        List<CleanupCandidate> candidates,
        List<ScanDiagnostic> diagnostics,
        CancellationToken token)
    {
        var runLocations = new[]
        {
            (RegistryHive.CurrentUser, "HKEY_CURRENT_USER", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", CleanupScope.User, StartupSourceKind.Run),
            (RegistryHive.CurrentUser, "HKEY_CURRENT_USER", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", CleanupScope.User, StartupSourceKind.RunOnce),
            (RegistryHive.LocalMachine, "HKEY_LOCAL_MACHINE", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", CleanupScope.System, StartupSourceKind.Run),
            (RegistryHive.LocalMachine, "HKEY_LOCAL_MACHINE", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", CleanupScope.System, StartupSourceKind.RunOnce)
        };

        foreach (var (hiveName, hiveText, subKey, scope, kind) in runLocations)
        {
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                var viewName = view == RegistryView.Registry32 ? "32" : "64";
                token.ThrowIfCancellationRequested();
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(hiveName, view);
                    using var key = baseKey.OpenSubKey(subKey);
                    if (key is null) continue;

                    foreach (var valueName in key.GetValueNames())
                    {
                        var command = Convert.ToString(key.GetValue(valueName, "", RegistryValueOptions.DoNotExpandEnvironmentNames)) ?? "";
                        var pathMatch = identity.ReferencesEvidence(command);
                        var nameMatch = identity.CandidateNames.Any(c => c.Equals(valueName, StringComparison.OrdinalIgnoreCase));

                        if (!pathMatch && !nameMatch) continue;

                        var confidence = pathMatch ? OwnershipConfidence.Certain : OwnershipConfidence.Medium;
                        var risk = pathMatch ? RiskLevel.Low : RiskLevel.Medium;
                        var autoSelect = CleanupSelectionPolicy.ShouldAutoSelect(new CleanupCandidate
                        {
                            Target = $@"{hiveText}\{subKey}",
                            Kind = CleanupKind.RegistryValue,
                            Risk = risk,
                            Confidence = confidence,
                            Reason = "",
                            AutoSelectable = pathMatch
                        });

                        var target = $@"{hiveText}\{subKey}";
                        var reason = pathMatch
                            ? $"Startup entry launches application binary from '{command}'"
                            : $"Startup entry name '{valueName}' matches application name; command requires review";

                        candidates.Add(new CleanupCandidate
                        {
                            Target = target,
                            Auxiliary = valueName,
                            Kind = CleanupKind.RegistryValue,
                            RegistryViewName = viewName,
                            Risk = risk,
                            Confidence = confidence,
                            Scope = scope,
                            Reason = reason,
                            SourceProvider = Name,
                            RegistryValueKindName = "String",
                            RegistryRawValueBase64 = command,
                            AutoSelectable = pathMatch,
                            EvidenceList = [$"Command: {command}", $"View: {viewName}-bit"],
                            IsSelected = autoSelect
                        });
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    diagnostics.Add(new ScanDiagnostic(Name, $"Access denied reading {hiveText}\\{subKey}", IsWarning: true, TargetPath: $@"{hiveText}\{subKey}", ExceptionDetail: ex.Message));
                }
                catch (Exception ex)
                {
                    diagnostics.Add(new ScanDiagnostic(Name, $"Failed scanning {hiveText}\\{subKey}: {ex.Message}", IsWarning: true, TargetPath: $@"{hiveText}\{subKey}", ExceptionDetail: ex.Message));
                }
            }
        }
    }

    private void ScanStartupFolder(
        ApplicationIdentityGraph identity,
        CleanupScanContext context,
        List<CleanupCandidate> candidates,
        List<ScanDiagnostic> diagnostics,
        CancellationToken token)
    {
        var shortcutResolver = new WindowsShortcutResolver();
        var startupFolders = new[]
        {
            (Environment.GetFolderPath(Environment.SpecialFolder.Startup), CleanupScope.User),
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), CleanupScope.System)
        };

        foreach (var (folder, scope) in startupFolders)
        {
            if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(folder, "*.*", SearchOption.TopDirectoryOnly))
                {
                    token.ThrowIfCancellationRequested();
                    var name = Path.GetFileNameWithoutExtension(file);
                    var resolution = file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)
                        ? shortcutResolver.Resolve(file)
                        : ShortcutResolution.Empty;

                    var targetPath = resolution.HasTarget ? resolution.TargetPath : file;
                    var pathMatch = identity.ReferencesEvidence(targetPath);
                    var nameMatch = identity.CandidateNames.Any(c => c.Equals(name, StringComparison.OrdinalIgnoreCase));

                    if (!pathMatch && !nameMatch) continue;

                    var confidence = pathMatch ? OwnershipConfidence.Certain : OwnershipConfidence.Medium;
                    var risk = pathMatch ? RiskLevel.Low : RiskLevel.Medium;

                    candidates.Add(new CleanupCandidate
                    {
                        Target = file,
                        Kind = CleanupKind.File,
                        Risk = risk,
                        Confidence = confidence,
                        Scope = scope,
                        Reason = pathMatch
                            ? $"Startup folder shortcut targets application binary '{targetPath}'"
                            : $"Startup folder item '{name}' matches application name",
                        SourceProvider = Name,
                        AutoSelectable = pathMatch,
                        EvidenceList = [$"Target: {targetPath}"],
                        IsSelected = pathMatch
                    });
                }
            }
            catch (Exception ex)
            {
                diagnostics.Add(new ScanDiagnostic(Name, $"Failed scanning startup folder {folder}: {ex.Message}", IsWarning: true, TargetPath: folder));
            }
        }
    }

    private void ScanStartupApprovedSubKeys(
        ApplicationIdentityGraph identity,
        CleanupScanContext context,
        List<CleanupCandidate> candidates,
        List<ScanDiagnostic> diagnostics,
        CancellationToken token)
    {
        var approvedLocations = new[]
        {
            (RegistryHive.CurrentUser, "HKEY_CURRENT_USER", @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run", CleanupScope.User, StartupSourceKind.Run),
            (RegistryHive.CurrentUser, "HKEY_CURRENT_USER", @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32", CleanupScope.User, StartupSourceKind.Run),
            (RegistryHive.CurrentUser, "HKEY_CURRENT_USER", @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder", CleanupScope.User, StartupSourceKind.StartupFolder),
            (RegistryHive.LocalMachine, "HKEY_LOCAL_MACHINE", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run", CleanupScope.System, StartupSourceKind.Run),
            (RegistryHive.LocalMachine, "HKEY_LOCAL_MACHINE", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32", CleanupScope.System, StartupSourceKind.Run),
            (RegistryHive.LocalMachine, "HKEY_LOCAL_MACHINE", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder", CleanupScope.System, StartupSourceKind.StartupFolder)
        };

        foreach (var (hiveName, hiveText, subKey, scope, kind) in approvedLocations)
        {
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                var viewName = view == RegistryView.Registry32 ? "32" : "64";
                token.ThrowIfCancellationRequested();
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(hiveName, view);
                    using var key = baseKey.OpenSubKey(subKey);
                    if (key is null) continue;

                    foreach (var valueName in key.GetValueNames())
                    {
                        var correlationKey = new StartupCorrelationKey(hiveName, view, kind, valueName);

                        // Safe Correlation Requirement:
                        // 1. Must match exact correlation key against a pre-uninstall startup source captured with High/Certain confidence
                        var matchingSource = identity.CapturedStartupSources.FirstOrDefault(s =>
                            s.CorrelationKey == correlationKey
                            && s.Confidence.IsAtLeast(OwnershipConfidence.High));

                        // 2. Or fallback name match (strictly Medium confidence, not auto-selected)
                        var nameMatch = identity.CandidateNames.Any(c => c.Equals(valueName, StringComparison.OrdinalIgnoreCase));

                        if (matchingSource is null && !nameMatch) continue;

                        var rawBytes = key.GetValue(valueName) as byte[] ?? [];
                        var rawBase64 = Convert.ToBase64String(rawBytes);

                        var isCertain = matchingSource is not null;
                        var confidence = isCertain ? OwnershipConfidence.Certain : OwnershipConfidence.Medium;
                        var risk = RiskLevel.Low;
                        var autoSelect = isCertain;

                        var target = $@"{hiveText}\{subKey}";
                        var reason = isCertain
                            ? $"Stale Task Manager startup entry left behind after the '{valueName}' startup source was removed"
                            : $"Task Manager startup entry name '{valueName}' matches application candidate name; review before removal";

                        var evidence = new List<string> { $"Value name: {valueName}", $"View: {viewName}-bit" };
                        if (matchingSource is not null)
                        {
                            evidence.Add($"Pre-uninstall correlated source: {matchingSource.RegistryPath} ({matchingSource.CommandOrShortcutPath})");
                        }

                        candidates.Add(new CleanupCandidate
                        {
                            Target = target,
                            Auxiliary = valueName,
                            Kind = CleanupKind.RegistryValue,
                            RegistryViewName = viewName,
                            Risk = risk,
                            Confidence = confidence,
                            Scope = scope,
                            Reason = reason,
                            SourceProvider = Name,
                            RegistryValueKindName = "Binary",
                            RegistryRawValueBase64 = rawBase64,
                            AutoSelectable = autoSelect,
                            EvidenceList = evidence,
                            IsSelected = autoSelect
                        });
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    diagnostics.Add(new ScanDiagnostic(Name, $"Access denied reading StartupApproved key {hiveText}\\{subKey}", IsWarning: true, TargetPath: $@"{hiveText}\{subKey}", ExceptionDetail: ex.Message));
                }
                catch (Exception ex)
                {
                    diagnostics.Add(new ScanDiagnostic(Name, $"Failed scanning StartupApproved in {hiveText}\\{subKey}: {ex.Message}", IsWarning: true, TargetPath: $@"{hiveText}\{subKey}", ExceptionDetail: ex.Message));
                }
            }
        }
    }
}
