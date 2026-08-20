using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using UninstallMate.Models;

namespace UninstallMate.Services.Providers;

public sealed class ScheduledTaskProvider : ICleanupArtifactProvider
{
    public string Name => "ScheduledTasks";

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

        const string script = "$ProgressPreference='SilentlyContinue'; Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object { $t=$_; foreach($a in $_.Actions) { [pscustomobject]@{TaskName=$t.TaskName;TaskPath=$t.TaskPath;Execute=$a.Execute;Arguments=$a.Arguments;WorkingDirectory=$a.WorkingDirectory} } } | ConvertTo-Json -Compress";

        try
        {
            var result = await ToolRunner.RunAsync(
                "powershell.exe",
                ["-NoProfile", "-NonInteractive", "-Command", script],
                TimeSpan.FromSeconds(8),
                token);

            if (!result.Success)
            {
                diagnostics.Add(new ScanDiagnostic(Name, $"Get-ScheduledTask failed with exit code {result.ExitCode}: {result.StandardError}", IsWarning: true));
                statusAcc.MarkPartial();
            }
            else if (!string.IsNullOrWhiteSpace(result.StandardOutput))
            {
                using var document = JsonDocument.Parse(result.StandardOutput);
                var items = document.RootElement.ValueKind == JsonValueKind.Array
                    ? document.RootElement.EnumerateArray().ToArray()
                    : [document.RootElement];

                foreach (var item in items)
                {
                    token.ThrowIfCancellationRequested();
                    var taskName = JsonString(item, "TaskName");
                    var taskPath = JsonString(item, "TaskPath");
                    var execute = JsonString(item, "Execute");
                    var args = JsonString(item, "Arguments");
                    var workDir = JsonString(item, "WorkingDirectory");
                    var action = string.Join(';', execute, args, workDir);

                    var pathMatch = identity.ReferencesEvidence(action);
                    var exactNameMatch = identity.CandidateNames.Any(x => taskName.Equals(x, StringComparison.CurrentCultureIgnoreCase));

                    var matchingPre = identity.CapturedTasks.FirstOrDefault(t =>
                        t.TaskName.Equals(taskName, StringComparison.OrdinalIgnoreCase)
                        && (string.IsNullOrEmpty(t.TaskPath) || t.TaskPath.Equals(taskPath, StringComparison.OrdinalIgnoreCase)));

                    if (!pathMatch && !exactNameMatch && matchingPre is null) continue;

                    var fullTaskName = (taskPath.EndsWith('\\') ? taskPath : taskPath + "\\") + taskName;

                    OwnershipConfidence confidence;
                    RiskLevel risk;
                    bool autoSelect;

                    if (pathMatch)
                    {
                        confidence = OwnershipConfidence.Certain;
                        risk = RiskLevel.Low;
                        autoSelect = true;
                    }
                    else if (matchingPre is not null && matchingPre.Confidence == OwnershipConfidence.Certain)
                    {
                        confidence = OwnershipConfidence.Certain;
                        risk = RiskLevel.Low;
                        autoSelect = true;
                    }
                    else
                    {
                        // Name-only match remains Medium confidence, Medium risk, unselected
                        confidence = OwnershipConfidence.Medium;
                        risk = RiskLevel.Medium;
                        autoSelect = false;
                    }

                    var evidence = new List<string> { $"Task name: {fullTaskName}", $"Action: {execute} {args}".Trim() };
                    if (matchingPre is not null) evidence.AddRange(matchingPre.Evidence);

                    var candidate = new CleanupCandidate
                    {
                        Target = fullTaskName,
                        Kind = CleanupKind.ScheduledTask,
                        Risk = risk,
                        Confidence = confidence,
                        Scope = CleanupScope.System,
                        Reason = pathMatch
                            ? "Scheduled task launches a program from the app's installation"
                            : (matchingPre is not null && matchingPre.Confidence == OwnershipConfidence.Certain
                                ? "Pre-uninstall verified application task"
                                : "Scheduled task matches the app name; review before removal"),
                        SourceProvider = Name,
                        EvidenceList = evidence,
                        AutoSelectable = autoSelect
                    };
                    candidate.IsSelected = CleanupSelectionPolicy.ShouldAutoSelect(candidate);
                    candidates.Add(candidate);
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            diagnostics.Add(new ScanDiagnostic(Name, $"Scheduled task scan failed: {ex.Message}", IsError: true, ExceptionDetail: ex.ToString()));
            statusAcc.MarkFailed();
        }

        return new ProviderScanResult
        {
            ProviderName = Name,
            Status = statusAcc.Status,
            Candidates = candidates,
            Diagnostics = diagnostics,
            Elapsed = sw.Elapsed
        };
    }

    private static string JsonString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) ? value.ToString() : "";
}
