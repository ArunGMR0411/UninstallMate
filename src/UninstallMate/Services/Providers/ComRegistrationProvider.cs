using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using UninstallMate.Models;

namespace UninstallMate.Services.Providers;

public sealed class ComRegistrationProvider : ICleanupArtifactProvider
{
    public string Name => "ComRegistrations";

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
                ScanClsids(identity, context, candidates, diagnostics, token);
                ScanTypeLibs(identity, context, candidates, diagnostics, token);
            }
            catch (Exception ex)
            {
                diagnostics.Add(new ScanDiagnostic(Name, $"Error during COM scan: {ex.Message}", IsError: true, ExceptionDetail: ex.ToString()));
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

    private void ScanClsids(
        ApplicationIdentityGraph identity,
        CleanupScanContext context,
        List<CleanupCandidate> candidates,
        List<ScanDiagnostic> diagnostics,
        CancellationToken token)
    {
        const string rootPath = @"SOFTWARE\Classes\CLSID";
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

                    foreach (var clsid in root.GetSubKeyNames())
                    {
                        token.ThrowIfCancellationRequested();
                        using var key = root.OpenSubKey(clsid);
                        if (key is null) continue;

                        using var inprocKey = key.OpenSubKey("InprocServer32");
                        using var localKey = key.OpenSubKey("LocalServer32");
                        var inproc = Convert.ToString(inprocKey?.GetValue(null)) ?? "";
                        var local = Convert.ToString(localKey?.GetValue(null)) ?? "";
                        var combined = inproc + ";" + local;

                        if (!identity.ReferencesEvidence(combined)) continue;

                        var target = $@"{hiveText}\{rootPath}\{clsid}";
                        candidates.Add(new CleanupCandidate
                        {
                            Target = target,
                            Kind = CleanupKind.RegistryKey,
                            RegistryViewName = viewName,
                            Risk = RiskLevel.Medium,
                            Confidence = OwnershipConfidence.High,
                            Scope = scope,
                            Reason = $"COM CLSID registration loads binary from app installation ({viewName}-bit view)",
                            SourceProvider = Name,
                            EvidenceList = [$"CLSID: {clsid}", $"Target binary: {(inproc.Length > 0 ? inproc : local)}"],
                            IsSelected = false
                        });
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    diagnostics.Add(new ScanDiagnostic(Name, $"Access denied for COM CLSIDs in {hiveText}", IsWarning: true, TargetPath: $@"{hiveText}\{rootPath}", ExceptionDetail: ex.Message));
                }
                catch (Exception ex)
                {
                    diagnostics.Add(new ScanDiagnostic(Name, $"Failed scanning COM CLSIDs in {hiveText} ({viewName}-bit): {ex.Message}", IsWarning: true, TargetPath: $@"{hiveText}\{rootPath}", ExceptionDetail: ex.Message));
                }
            }
        }
    }

    private void ScanTypeLibs(
        ApplicationIdentityGraph identity,
        CleanupScanContext context,
        List<CleanupCandidate> candidates,
        List<ScanDiagnostic> diagnostics,
        CancellationToken token)
    {
        const string rootPath = @"SOFTWARE\Classes\TypeLib";
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

                    foreach (var libId in root.GetSubKeyNames())
                    {
                        token.ThrowIfCancellationRequested();
                        using var key = root.OpenSubKey(libId);
                        if (key is null) continue;

                        foreach (var ver in key.GetSubKeyNames())
                        {
                            using var verKey = key.OpenSubKey(ver);
                            if (verKey is null) continue;
                            foreach (var lang in verKey.GetSubKeyNames())
                            {
                                using var langKey = verKey.OpenSubKey(lang);
                                if (langKey is null) continue;
                                foreach (var platform in new[] { "win32", "win64" })
                                {
                                    using var platKey = langKey.OpenSubKey(platform);
                                    var path = Convert.ToString(platKey?.GetValue(null)) ?? "";
                                    if (identity.ReferencesEvidence(path))
                                    {
                                        var target = $@"{hiveText}\{rootPath}\{libId}";
                                        if (candidates.All(c => !c.Target.Equals(target, StringComparison.OrdinalIgnoreCase)))
                                        {
                                            candidates.Add(new CleanupCandidate
                                            {
                                                Target = target,
                                                Kind = CleanupKind.RegistryKey,
                                                RegistryViewName = viewName,
                                                Risk = RiskLevel.Medium,
                                                Confidence = OwnershipConfidence.High,
                                                Scope = scope,
                                                Reason = $"TypeLib registration points into app installation ({viewName}-bit view)",
                                                SourceProvider = Name,
                                                EvidenceList = [$"TypeLib: {libId} version {ver}", $"Path: {path}"],
                                                IsSelected = false
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                catch { }
            }
        }
    }
}
