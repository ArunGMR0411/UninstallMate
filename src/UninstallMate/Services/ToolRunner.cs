using System.Diagnostics;

namespace UninstallMate.Services;

public sealed record ToolResult(
    int ExitCode,
    string StandardOutput,
    string StandardError,
    bool TimedOut)
{
    public bool Success => !TimedOut && ExitCode == 0;
}

public static class ToolRunner
{
    public static async Task<ToolResult> RunAsync(
        string executable,
        IEnumerable<string> arguments,
        TimeSpan timeout,
        CancellationToken token)
    {
        var start = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        foreach (var arg in arguments)
        {
            start.ArgumentList.Add(arg);
        }

        using var process = Process.Start(start)
            ?? throw new InvalidOperationException($"Could not start process '{executable}'.");

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeoutCts.CancelAfter(timeout);

        var stdoutTask = process.StandardOutput.ReadToEndAsync(token);
        var stderrTask = process.StandardError.ReadToEndAsync(token);

        try
        {
            await process.WaitForExitAsync(timeoutCts.Token);
            var stdout = await stdoutTask;
            var stderr = await stderrTask;
            return new ToolResult(process.ExitCode, stdout, stderr, false);
        }
        catch (OperationCanceledException)
        {
            var timedOut = !token.IsCancellationRequested && timeoutCts.IsCancellationRequested;
            try
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                }
            }
            catch { }

            return new ToolResult(-1, "", timedOut ? "Process timed out." : "Process cancelled.", timedOut);
        }
    }
}
