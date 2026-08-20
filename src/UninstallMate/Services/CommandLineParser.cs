using System.Runtime.InteropServices;
using System.Text;

namespace UninstallMate.Services;

public static class CommandLineParser
{
    public static bool TrySplit(string commandLine, out string executable, out string arguments)
    {
        executable = "";
        arguments = "";
        if (string.IsNullOrWhiteSpace(commandLine)) return false;

        commandLine = commandLine.Trim();

        // 1. Quoted executable path
        if (commandLine.StartsWith('"'))
        {
            var closingQuote = commandLine.IndexOf('"', 1);
            if (closingQuote > 0)
            {
                executable = commandLine.Substring(1, closingQuote - 1).Trim();
                arguments = commandLine.Substring(closingQuote + 1).TrimStart();
                return executable.Length > 0;
            }
        }

        // 2. Windows API parser if on Windows
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            try
            {
                var argv = CommandLineToArgvW(commandLine, out var count);
                if (argv != IntPtr.Zero && count > 0)
                {
                    try
                    {
                        var firstArg = Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv)) ?? "";
                        if (!string.IsNullOrWhiteSpace(firstArg))
                        {
                            // If the first argument extracted by Windows is an existing file or has .exe extension
                            if (firstArg.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || File.Exists(firstArg))
                            {
                                executable = firstArg;
                                var firstArgEnd = FindFirstArgumentEnd(commandLine);
                                arguments = firstArgEnd < commandLine.Length ? commandLine[firstArgEnd..].TrimStart() : "";
                                return true;
                            }
                        }
                    }
                    finally { LocalFree(argv); }
                }
            }
            catch { }
        }

        // 3. Unquoted executable path containing spaces and ending with .exe
        // Find .exe that is NOT part of a directory name (i.e. followed by space or end of string, not \ or /)
        var exeIndices = FindExeBoundaries(commandLine);
        foreach (var index in exeIndices)
        {
            var candidateExe = commandLine[..index].Trim();
            var candidateArgs = commandLine[index..].TrimStart();

            // On Windows, if the file exists on disk, that's an exact match
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && File.Exists(Environment.ExpandEnvironmentVariables(candidateExe)))
            {
                executable = candidateExe;
                arguments = candidateArgs;
                return true;
            }

            // Otherwise take the first valid executable boundary where arguments look plausible
            if (string.IsNullOrEmpty(executable))
            {
                executable = candidateExe;
                arguments = candidateArgs;
            }
        }

        if (!string.IsNullOrEmpty(executable))
        {
            return true;
        }

        // 4. Single token without spaces or quotes
        var spaceIdx = commandLine.IndexOf(' ');
        if (spaceIdx < 0)
        {
            executable = commandLine;
            arguments = "";
            return true;
        }

        executable = commandLine[..spaceIdx].Trim();
        arguments = commandLine[spaceIdx..].TrimStart();
        return executable.Length > 0;
    }

    private static List<int> FindExeBoundaries(string text)
    {
        var results = new List<int>();
        var target = ".exe";
        var pos = 0;

        while (pos < text.Length)
        {
            var idx = text.IndexOf(target, pos, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) break;

            var end = idx + target.Length;
            // Check if followed by end of string, space, tab, or quote (NOT a directory separator)
            if (end == text.Length || char.IsWhiteSpace(text[end]) || text[end] is '"' or ',' or '/')
            {
                results.Add(end);
            }
            pos = idx + 1;
        }

        return results;
    }

    private static int FindFirstArgumentEnd(string text)
    {
        var quoted = false;
        var slashCount = 0;
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (c == '\\') { slashCount++; continue; }
            if (c == '"' && slashCount % 2 == 0) quoted = !quoted;
            else if (char.IsWhiteSpace(c) && !quoted) return i;
            slashCount = 0;
        }
        return text.Length;
    }

    [DllImport("shell32.dll", SetLastError = true)]
    private static extern IntPtr CommandLineToArgvW([MarshalAs(UnmanagedType.LPWStr)] string commandLine, out int argumentCount);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
