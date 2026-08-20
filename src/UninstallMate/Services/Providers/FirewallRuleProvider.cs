using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using UninstallMate.Models;

namespace UninstallMate.Services.Providers;

public sealed class FirewallRuleProvider : ICleanupArtifactProvider
{
    public string Name => "Firewall";

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
                ScanRegistryFirewallRules(identity, context, candidates, diagnostics, statusAcc, token);
            }
            catch (Exception ex)
            {
                diagnostics.Add(new ScanDiagnostic(Name, $"Error during firewall rule scan: {ex.Message}", IsError: true, ExceptionDetail: ex.ToString()));
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

    private void ScanRegistryFirewallRules(
        ApplicationIdentityGraph identity,
        CleanupScanContext context,
        List<CleanupCandidate> candidates,
        List<ScanDiagnostic> diagnostics,
        ScanStatusAccumulator statusAcc,
        CancellationToken token)
    {
        const string firewallRulesPath = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
        try
        {
            using var hive = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var rulesKey = hive.OpenSubKey(firewallRulesPath);
            if (rulesKey is null) return;

            foreach (var ruleValueName in rulesKey.GetValueNames())
            {
                token.ThrowIfCancellationRequested();
                var ruleData = Convert.ToString(rulesKey.GetValue(ruleValueName, "", RegistryValueOptions.DoNotExpandEnvironmentNames)) ?? "";
                if (string.IsNullOrWhiteSpace(ruleData)) continue;

                // Rule format: v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|App=C:\path\app.exe|Name=App Name|...
                var appMatch = ExtractRuleProperty(ruleData, "App");
                var nameMatch = ExtractRuleProperty(ruleData, "Name");
                var svcMatch = ExtractRuleProperty(ruleData, "Svc");

                var matchesAppPath = !string.IsNullOrEmpty(appMatch) && identity.ReferencesEvidence(appMatch);
                var matchesSvc = !string.IsNullOrEmpty(svcMatch) && identity.CapturedServices.Any(s => s.ServiceName.Equals(svcMatch, StringComparison.OrdinalIgnoreCase));
                var matchesAppName = !string.IsNullOrEmpty(nameMatch) && identity.CandidateNames.Any(c => c.Equals(nameMatch, StringComparison.OrdinalIgnoreCase));

                if (!matchesAppPath && !matchesSvc && !matchesAppName) continue;

                var isStrong = matchesAppPath || matchesSvc;
                var confidence = isStrong ? OwnershipConfidence.Certain : OwnershipConfidence.Medium;
                var risk = isStrong ? RiskLevel.Low : RiskLevel.Medium;
                var autoSelect = isStrong;

                var target = $@"HKEY_LOCAL_MACHINE\{firewallRulesPath}";
                var reason = matchesAppPath
                    ? $"Windows Firewall rule references application executable '{appMatch}'"
                    : (matchesSvc
                        ? $"Windows Firewall rule references application service '{svcMatch}'"
                        : $"Windows Firewall rule name '{nameMatch}' matches candidate name; review before removal");

                var candidate = new CleanupCandidate
                {
                    Target = target,
                    Auxiliary = ruleValueName,
                    Kind = CleanupKind.FirewallRule,
                    RegistryViewName = "64",
                    Risk = risk,
                    Confidence = confidence,
                    Scope = CleanupScope.System,
                    Reason = reason,
                    SourceProvider = Name,
                    RegistryValueKindName = "String",
                    RegistryRawValueBase64 = ruleData,
                    AutoSelectable = autoSelect,
                    EvidenceList = [$"Firewall Rule: {nameMatch}", $"App: {appMatch}", $"Data: {ruleData}"]
                };
                candidate.IsSelected = CleanupSelectionPolicy.ShouldAutoSelect(candidate);
                candidates.Add(candidate);
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            diagnostics.Add(new ScanDiagnostic(Name, "Access denied reading Firewall Rules", IsWarning: true, TargetPath: firewallRulesPath, ExceptionDetail: ex.Message));
            statusAcc.MarkAccessDenied();
        }
        catch (Exception ex)
        {
            diagnostics.Add(new ScanDiagnostic(Name, $"Failed reading Firewall Rules: {ex.Message}", IsWarning: true, TargetPath: firewallRulesPath, ExceptionDetail: ex.Message));
            statusAcc.MarkWarning();
        }
    }

    private static string ExtractRuleProperty(string ruleData, string propertyName)
    {
        var tag = propertyName + "=";
        var start = ruleData.IndexOf(tag, StringComparison.OrdinalIgnoreCase);
        if (start < 0) return "";
        start += tag.Length;
        var end = ruleData.IndexOf('|', start);
        return end < 0 ? ruleData[start..].Trim() : ruleData[start..end].Trim();
    }
}
