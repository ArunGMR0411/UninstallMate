using System.Diagnostics;
using UninstallMate.Models;

namespace UninstallMate.Services.Providers;

public sealed class CrashDumpProvider : ICleanupArtifactProvider
{
    public string Name => "CrashDumps";

    public Task<ProviderScanResult> ScanAsync(
        ApplicationIdentityGraph identity,
        CleanupScanContext context,
        CancellationToken token)
    {
        var sw = Stopwatch.StartNew();
        var candidates = new List<CleanupCandidate>();
        var diagnostics = new List<ScanDiagnostic>();
        var statusAcc = new ScanStatusAccumulator();

        var crashRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CrashDumps");
        if (!Directory.Exists(crashRoot))
        {
            return Task.FromResult(ProviderScanResult.Succeeded(Name, candidates, sw.Elapsed));
        }

        var executableNames = identity.ExecutableNames.ToArray();
        if (executableNames.Length == 0)
        {
            return Task.FromResult(ProviderScanResult.Succeeded(Name, candidates, sw.Elapsed));
        }

        try
        {
            foreach (var file in Directory.EnumerateFiles(crashRoot, "*.dmp", SearchOption.TopDirectoryOnly))
            {
                token.ThrowIfCancellationRequested();
                var fileName = Path.GetFileName(file);
                if (executableNames.Any(exe => fileName.StartsWith(exe + ".", StringComparison.OrdinalIgnoreCase)))
                {
                    var size = 0L;
                    try { size = new FileInfo(file).Length; } catch { }
                    var candidate = new CleanupCandidate
                    {
                        Target = file,
                        Kind = CleanupKind.File,
                        Risk = RiskLevel.Low,
                        Confidence = OwnershipConfidence.High,
                        Reason = "Crash dump produced by an application executable",
                        SizeBytes = size,
                        Scope = CleanupScope.User,
                        SourceProvider = Name,
                        EvidenceList = [$"Crash dump: {file}"],
                        AutoSelectable = true
                    };
                    candidate.IsSelected = CleanupSelectionPolicy.ShouldAutoSelect(candidate);
                    candidates.Add(candidate);
                }
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            diagnostics.Add(new ScanDiagnostic(Name, $"Access denied scanning crash dumps: {ex.Message}", IsWarning: true, TargetPath: crashRoot));
            statusAcc.MarkAccessDenied();
        }
        catch (Exception ex)
        {
            diagnostics.Add(new ScanDiagnostic(Name, $"Failed scanning crash dumps: {ex.Message}", IsWarning: true, TargetPath: crashRoot));
            statusAcc.MarkWarning();
        }

        return Task.FromResult(new ProviderScanResult
        {
            ProviderName = Name,
            Status = statusAcc.Status,
            Candidates = candidates,
            Diagnostics = diagnostics,
            Elapsed = sw.Elapsed
        });
    }
}
