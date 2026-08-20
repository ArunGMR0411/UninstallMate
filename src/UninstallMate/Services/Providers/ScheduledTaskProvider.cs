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

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return ProviderScanResult.Succeeded(Name, candidates, sw.Elapsed);
        }

        const string script = "$ProgressPreference='SilentlyContinue'; Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object { $t=$_; foreach($a in $_.Actions) { [pscustomobject]@{TaskName=$t.TaskName;TaskPath=$t.TaskPath;Execute=$a.Execute;Arguments=$a.Arguments;WorkingDirectory=$a.WorkingDirectory} } } | ConvertTo-Json -Compress";
        var start = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-NonInteractive");
        start.ArgumentList.Add("-Command");
        start.ArgumentList.Add(script);

        try
        {
            using var process = Process.Start(start);
            if (process is not null)
            {
                var outputTask = process.StandardOutput.ReadToEndAsync(token);
                var errorTask = process.StandardError.ReadToEndAsync(token);
                await process.WaitForExitAsync(token);
                var json = await outputTask;
                var err = await errorTask;

                if (process.ExitCode != 0)
                {
                    diagnostics.Add(new ScanDiagnostic(Name, $"Get-ScheduledTask returned exit code {process.ExitCode}: {err}", IsWarning: true));
                }
                else if (!string.IsNullOrWhiteSpace(json))
                {
                    using var document = JsonDocument.Parse(json);
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
                        var preMatch = identity.CapturedTasks.Any(t => t.TaskName.Equals(taskName, StringComparison.OrdinalIgnoreCase));

                        if (!pathMatch && !exactNameMatch && !preMatch) continue;

                        var fullTaskName = (taskPath.EndsWith('\\') ? taskPath : taskPath + "\\") + taskName;
                        var confidence = (preMatch || pathMatch) ? OwnershipConfidence.Certain : OwnershipConfidence.Medium;
                        var risk = pathMatch ? RiskLevel.Medium : RiskLevel.High;

                        candidates.Add(new CleanupCandidate
                        {
                            Target = fullTaskName,
                            Kind = CleanupKind.ScheduledTask,
                            Risk = risk,
                            Confidence = confidence,
                            Scope = CleanupScope.System,
                            Reason = pathMatch
                                ? "Scheduled task launches a program from the app's installation"
                                : "Scheduled task matches the app name; review its actions",
                            SourceProvider = Name,
                            EvidenceList = [$"Action: {execute} {args}".Trim()],
                            IsSelected = false // Tasks require review
                        });
                    }
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            diagnostics.Add(new ScanDiagnostic(Name, $"Scheduled task scan failed: {ex.Message}", IsError: true, ExceptionDetail: ex.ToString()));
        }

        return new ProviderScanResult
        {
            ProviderName = Name,
            Status = diagnostics.Any(d => d.IsError) ? ScanStatus.CompleteWithWarnings : ScanStatus.Complete,
            Candidates = candidates,
            Diagnostics = diagnostics,
            Elapsed = sw.Elapsed
        };
    }

    private static string JsonString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) ? value.ToString() : "";
}
