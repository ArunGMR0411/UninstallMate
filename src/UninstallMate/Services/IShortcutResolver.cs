using System.Runtime.InteropServices;
using System.Text;

namespace UninstallMate.Services;

public sealed record ShortcutResolution(
    string TargetPath,
    string Arguments,
    string WorkingDirectory,
    string IconLocation)
{
    public static ShortcutResolution Empty { get; } = new("", "", "", "");
    public bool HasTarget => !string.IsNullOrWhiteSpace(TargetPath);
}

public interface IShortcutResolver
{
    ShortcutResolution Resolve(string shortcutPath);
}

public sealed class WindowsShortcutResolver : IShortcutResolver
{
    public ShortcutResolution Resolve(string shortcutPath)
    {
        if (string.IsNullOrWhiteSpace(shortcutPath) || !File.Exists(shortcutPath))
            return ShortcutResolution.Empty;

        // 1. Try Windows Shell COM if on Windows
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            try
            {
                var type = Type.GetTypeFromProgID("WScript.Shell");
                if (type is not null)
                {
                    dynamic? shell = Activator.CreateInstance(type);
                    if (shell is not null)
                    {
                        dynamic shortcut = shell.CreateShortcut(shortcutPath);
                        string target = shortcut.TargetPath ?? "";
                        string args = shortcut.Arguments ?? "";
                        string workDir = shortcut.WorkingDirectory ?? "";
                        string icon = shortcut.IconLocation ?? "";
                        Marshal.FinalReleaseComObject(shortcut);
                        Marshal.FinalReleaseComObject(shell);

                        if (!string.IsNullOrWhiteSpace(target))
                        {
                            return new ShortcutResolution(target, args, workDir, icon);
                        }
                    }
                }
            }
            catch { }
        }

        // 2. Fallback: Parse binary LNK file structures directly (cross-platform compatible)
        return ParseLnkBinary(shortcutPath);
    }

    public static ShortcutResolution ParseLnkBinary(string shortcutPath)
    {
        try
        {
            var bytes = File.ReadAllBytes(shortcutPath);
            if (bytes.Length < 0x4C) return ShortcutResolution.Empty;

            // Verify LNK Header CLSID (00021401-0000-0000-c000-000000000046)
            if (bytes[0] != 0x4C || bytes[1] != 0x00 || bytes[2] != 0x02 || bytes[3] != 0x00)
                return ShortcutResolution.Empty;

            var flags = BitConverter.ToUInt32(bytes, 0x14);
            var hasLinkTargetIdList = (flags & 0x01) != 0;
            var hasLinkInfo = (flags & 0x02) != 0;

            var pos = 0x4C;

            // Skip IDList if present
            if (hasLinkTargetIdList && pos + 2 <= bytes.Length)
            {
                var idListSize = BitConverter.ToUInt16(bytes, pos);
                pos += 2 + idListSize;
            }

            // LinkInfo
            if (hasLinkInfo && pos + 4 <= bytes.Length)
            {
                var linkInfoSize = BitConverter.ToUInt32(bytes, pos);
                if (linkInfoSize >= 0x1C && pos + linkInfoSize <= bytes.Length)
                {
                    var linkInfoHeaderSize = BitConverter.ToUInt32(bytes, pos + 0x04);
                    var linkInfoFlags = BitConverter.ToUInt32(bytes, pos + 0x08);
                    var localBasePathOffset = BitConverter.ToUInt32(bytes, pos + 0x10);

                    // Check for local base path (VolumeID and LocalBasePath)
                    if ((linkInfoFlags & 0x01) != 0 && localBasePathOffset > 0 && pos + localBasePathOffset < bytes.Length)
                    {
                        var strStart = (int)(pos + localBasePathOffset);
                        var strEnd = Array.IndexOf(bytes, (byte)0, strStart);
                        if (strEnd > strStart)
                        {
                            var target = Encoding.Default.GetString(bytes, strStart, strEnd - strStart);
                            return new ShortcutResolution(target, "", "", "");
                        }
                    }

                    // Check for Unicode LocalBasePath if header size >= 0x24
                    if (linkInfoHeaderSize >= 0x24 && pos + 0x1C + 4 <= bytes.Length)
                    {
                        var localBasePathOffsetUnicode = BitConverter.ToUInt32(bytes, pos + 0x1C);
                        if (localBasePathOffsetUnicode > 0 && pos + localBasePathOffsetUnicode < bytes.Length)
                        {
                            var strStart = (int)(pos + localBasePathOffsetUnicode);
                            var strEnd = strStart;
                            while (strEnd + 1 < bytes.Length && (bytes[strEnd] != 0 || bytes[strEnd + 1] != 0))
                                strEnd += 2;
                            if (strEnd > strStart)
                            {
                                var target = Encoding.Unicode.GetString(bytes, strStart, strEnd - strStart);
                                return new ShortcutResolution(target, "", "", "");
                            }
                        }
                    }
                }
            }
        }
        catch { }

        return ShortcutResolution.Empty;
    }
}
