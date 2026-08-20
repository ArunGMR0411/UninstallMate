using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using UninstallMate.Models;

namespace UninstallMate.Services.Providers;

public sealed class EventLogProvider : ICleanupArtifactProvider
{
    public string Name => "EventLogSources";

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
                ScanEventLogSources(identity, context, candidates, diagnostics, statusAcc, token);
            }
            catch (Exception ex)
            {
                diagnostics.Add(new ScanDiagnostic(Name, $"Error during event log source scan: {ex.Message}", IsError: true, ExceptionDetail: ex.ToString()));
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

    private void ScanEventLogSources(
        ApplicationIdentityGraph identity,
        CleanupScanContext context,
        List<CleanupCandidate> candidates,
        List<ScanDiagnostic> diagnostics,
        ScanStatusAccumulator statusAcc,
        CancellationToken token)
    {
        const string eventLogPath = @"SYSTEM\CurrentControlSet\Services\EventLog\Application";
        try
        {
            using var hive = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var root = hive.OpenSubKey(eventLogPath);
            if (root is null) return;

            foreach (var sourceName in root.GetSubKeyNames())
            {
                token.ThrowIfCancellationRequested();
                try
                {
                    using var sourceKey = root.OpenSubKey(sourceName);
                    if (sourceKey is null) continue;

                    var messageFile = Convert.ToString(sourceKey.GetValue("EventMessageFile", "", RegistryValueOptions.DoNotExpandEnvironmentNames)) ?? "";
                    var matchesEvidence = identity.ReferencesEvidence(messageFile);
                    var matchesName = identity.CandidateNames.Any(c => c.Equals(sourceName, StringComparison.OrdinalIgnoreCase));

                    if (!matchesEvidence && !matchesName) continue;

                    var target = $@"HKEY_LOCAL_MACHINE\{eventLogPath}\{sourceName}";
                    var candidate = new CleanupCandidate
                    {
                        Target = target,
                        Kind = CleanupKind.RegistryKey,
                        RegistryViewName = "64",
                        Risk = RiskLevel.Medium,
                        Confidence = matchesEvidence ? OwnershipConfidence.Certain : OwnershipConfidence.High,
                        Scope = CleanupScope.System,
                        Reason = "Application event log source registration",
                        SourceProvider = Name,
                        EvidenceList = [$"Event log source: {sourceName}", $"Message file: {messageFile}"],
                        AutoSelectable = false // Event log sources require review
                    };
                    candidate.IsSelected = CleanupSelectionPolicy.ShouldAutoSelect(candidate);
                    candidates.Add(candidate);
                }
                catch (UnauthorizedAccessException ex)
                {
                    diagnostics.Add(new ScanDiagnostic(Name, $"Access denied reading event log source '{sourceName}'", IsWarning: true, ExceptionDetail: ex.Message));
                    statusAcc.MarkAccessDenied();
                }
                catch (Exception ex)
                {
                    diagnostics.Add(new ScanDiagnostic(Name, $"Failed reading event log source '{sourceName}': {ex.Message}", IsWarning: true));
                    statusAcc.MarkWarning();
                }
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            diagnostics.Add(new ScanDiagnostic(Name, "Access denied reading EventLog sources", IsWarning: true, TargetPath: eventLogPath, ExceptionDetail: ex.Message));
            statusAcc.MarkAccessDenied();
        }
        catch (Exception ex)
        {
            diagnostics.Add(new ScanDiagnostic(Name, $"Failed reading EventLog sources: {ex.Message}", IsError: true, TargetPath: eventLogPath, ExceptionDetail: ex.Message));
            statusAcc.MarkFailed();
        }
    }
}
