using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
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
        var statusAcc = new ScanStatusAccumulator();

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return ProviderScanResult.Succeeded(Name, candidates, sw.Elapsed);
        }

        await Task.Run(() =>
        {
            try
            {
                ScanBrowserHosts(identity, context, candidates, diagnostics, statusAcc, token);
            }
            catch (Exception ex)
            {
                diagnostics.Add(new ScanDiagnostic(Name, $"Error during native messaging host scan: {ex.Message}", IsError: true, ExceptionDetail: ex.ToString()));
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

    private void ScanBrowserHosts(
        ApplicationIdentityGraph identity,
        CleanupScanContext context,
        List<CleanupCandidate> candidates,
        List<ScanDiagnostic> diagnostics,
        ScanStatusAccumulator statusAcc,
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
                            var manifestExePath = TryExtractHostExecutable(manifestPath);

                            var matchesManifestPath = !string.IsNullOrEmpty(manifestPath) && identity.ReferencesEvidence(manifestPath);
                            var matchesExePath = !string.IsNullOrEmpty(manifestExePath) && identity.ReferencesEvidence(manifestExePath);
                            var matchesEvidence = matchesManifestPath || matchesExePath;
                            var matchesName = identity.CandidateNames.Any(c => c.Equals(hostName, StringComparison.OrdinalIgnoreCase));

                            if (!matchesEvidence && !matchesName) continue;

                            var confidence = matchesEvidence ? OwnershipConfidence.Certain : OwnershipConfidence.Medium;
                            var risk = matchesEvidence ? RiskLevel.Low : RiskLevel.Medium;
                            var autoSelect = matchesEvidence;

                            var target = $@"{hiveText}\{subKeyPath}\{hostName}";
                            var reason = matchesEvidence
                                ? $"Browser native messaging host points to application manifest or executable '{manifestExePath}'"
                                : $"Browser native messaging host name '{hostName}' matches application name; review before removal";

                            var evidence = new List<string> { $"Host name: {hostName}", $"Manifest: {manifestPath}" };
                            if (!string.IsNullOrEmpty(manifestExePath)) evidence.Add($"Host binary: {manifestExePath}");

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
                        diagnostics.Add(new ScanDiagnostic(Name, $"Access denied reading native messaging hosts in {hiveText}\\{subKeyPath}", IsWarning: true, ExceptionDetail: ex.Message));
                        statusAcc.MarkAccessDenied();
                    }
                    catch (Exception ex)
                    {
                        diagnostics.Add(new ScanDiagnostic(Name, $"Error reading native messaging hosts in {hiveText}\\{subKeyPath}: {ex.Message}", IsWarning: true, ExceptionDetail: ex.Message));
                        statusAcc.MarkWarning();
                    }
                }
            }
        }
    }

    private static string TryExtractHostExecutable(string manifestPath)
    {
        if (string.IsNullOrWhiteSpace(manifestPath) || !File.Exists(manifestPath)) return "";
        try
        {
            var json = File.ReadAllText(manifestPath);
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("path", out var pathProp))
            {
                var pathVal = pathProp.GetString();
                if (!string.IsNullOrEmpty(pathVal))
                {
                    if (Path.IsPathRooted(pathVal)) return pathVal;
                    var dir = Path.GetDirectoryName(manifestPath);
                    return string.IsNullOrEmpty(dir) ? pathVal : Path.Combine(dir, pathVal);
                }
            }
        }
        catch { }
        return "";
    }
}
