using System.Runtime.InteropServices;

namespace UninstallMate.Services;

internal static class CommandLineParser
{
    public static bool TrySplit(string commandLine, out string executable, out string arguments)
    {
        executable = "";
        arguments = "";
        if (string.IsNullOrWhiteSpace(commandLine)) return false;
        commandLine = commandLine.Trim();
        if (!commandLine.StartsWith('"'))
        {
            var exeEnd = commandLine.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            if (exeEnd >= 0)
            {
                exeEnd += 4;
                executable = commandLine[..exeEnd].Trim();
                arguments = commandLine[exeEnd..].TrimStart();
                return executable.Length > 0;
            }
        }
        var argv = CommandLineToArgvW(commandLine, out var count);
        if (argv == IntPtr.Zero || count == 0) return false;
        try
        {
            executable = Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv)) ?? "";
            var firstArgEnd = FindFirstArgumentEnd(commandLine);
            arguments = firstArgEnd < commandLine.Length ? commandLine[firstArgEnd..].TrimStart() : "";
            return executable.Length > 0;
        }
        finally { LocalFree(argv); }
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
