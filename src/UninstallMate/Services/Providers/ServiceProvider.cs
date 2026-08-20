using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using UninstallMate.Models;

namespace UninstallMate.Services.Providers;

public sealed class ServiceProvider : ICleanupArtifactProvider
{
    public string Name => "Services";

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
                ScanServices(identity, context, candidates, diagnostics, statusAcc, token);
            }
            catch (Exception ex)
            {
                diagnostics.Add(new ScanDiagnostic(Name, $"Error during service scan: {ex.Message}", IsError: true, ExceptionDetail: ex.ToString()));
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

    private void ScanServices(
        ApplicationIdentityGraph identity,
        CleanupScanContext context,
        List<CleanupCandidate> candidates,
        List<ScanDiagnostic> diagnostics,
        ScanStatusAccumulator statusAcc,
        CancellationToken token)
    {
        const string servicesPath = @"SYSTEM\CurrentControlSet\Services";
        try
        {
            using var hive = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var services = hive.OpenSubKey(servicesPath);
            if (services is null) return;

            foreach (var serviceName in services.GetSubKeyNames())
            {
                token.ThrowIfCancellationRequested();
                try
                {
                    using var service = services.OpenSubKey(serviceName);
                    if (service is null) continue;

                    var imagePath = Convert.ToString(service.GetValue("ImagePath", "", RegistryValueOptions.DoNotExpandEnvironmentNames)) ?? "";
                    var serviceDll = "";
                    using (var paramsKey = service.OpenSubKey("Parameters"))
                    {
                        if (paramsKey is not null)
                            serviceDll = Convert.ToString(paramsKey.GetValue("ServiceDll", "", RegistryValueOptions.DoNotExpandEnvironmentNames)) ?? "";
                    }

                    var matchesEvidence = identity.ReferencesEvidence(imagePath) || identity.ReferencesEvidence(serviceDll);
                    var matchingPre = identity.CapturedServices.FirstOrDefault(s => s.ServiceName.Equals(serviceName, StringComparison.OrdinalIgnoreCase));
                    var matchesName = identity.CandidateNames.Any(c => c.Equals(serviceName, StringComparison.OrdinalIgnoreCase));

                    if (!matchesEvidence && matchingPre is null && !matchesName) continue;

                    var isPathBacked = matchesEvidence || (matchingPre is not null && matchingPre.Confidence == OwnershipConfidence.Certain);
                    var confidence = isPathBacked ? OwnershipConfidence.Certain : OwnershipConfidence.Medium;

                    var type = Convert.ToInt32(service.GetValue("Type") ?? 0);
                    var isDriver = (type & 0x3) != 0;
                    var target = $@"HKEY_LOCAL_MACHINE\{servicesPath}\{serviceName}";

                    var reason = isDriver
                        ? "Driver service loads a binary from the app's installation"
                        : (serviceDll.Length > 0
                            ? $"svchost-hosted service loads DLL '{serviceDll}' from the app's installation"
                            : (isPathBacked
                                ? "Windows service runs a binary from the app's installation"
                                : $"Windows service '{serviceName}' matches application name; review before removal"));

                    var evidence = new List<string>();
                    if (imagePath.Length > 0) evidence.Add($"ImagePath: {imagePath}");
                    if (serviceDll.Length > 0) evidence.Add($"ServiceDll: {serviceDll}");
                    if (matchingPre is not null) evidence.AddRange(matchingPre.Evidence);

                    var candidate = new CleanupCandidate
                    {
                        Target = target,
                        Auxiliary = serviceName,
                        Kind = CleanupKind.WindowsService,
                        RegistryViewName = "64",
                        Risk = RiskLevel.High,
                        Confidence = confidence,
                        Scope = CleanupScope.System,
                        Reason = reason,
                        SourceProvider = Name,
                        EvidenceList = evidence,
                        AutoSelectable = false // Services default unselected for safety
                    };
                    candidate.IsSelected = CleanupSelectionPolicy.ShouldAutoSelect(candidate);
                    candidates.Add(candidate);
                }
                catch (UnauthorizedAccessException ex)
                {
                    diagnostics.Add(new ScanDiagnostic(Name, $"Access denied inspecting service '{serviceName}': {ex.Message}", IsWarning: true, TargetPath: serviceName));
                    statusAcc.MarkAccessDenied();
                }
                catch (Exception ex)
                {
                    diagnostics.Add(new ScanDiagnostic(Name, $"Failed inspecting service '{serviceName}': {ex.Message}", IsWarning: true, TargetPath: serviceName));
                    statusAcc.MarkWarning();
                }
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            diagnostics.Add(new ScanDiagnostic(Name, "Access denied reading Services key", IsWarning: true, TargetPath: servicesPath, ExceptionDetail: ex.Message));
            statusAcc.MarkAccessDenied();
        }
        catch (Exception ex)
        {
            diagnostics.Add(new ScanDiagnostic(Name, $"Failed reading Services: {ex.Message}", IsError: true, TargetPath: servicesPath, ExceptionDetail: ex.Message));
            statusAcc.MarkFailed();
        }
    }
}
