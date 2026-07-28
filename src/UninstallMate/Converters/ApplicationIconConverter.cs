using System.Globalization;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Data;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace UninstallMate.Converters;

public sealed class ApplicationIconConverter : IValueConverter
{
    private const int MaximumCachedIcons = 256;
    private static readonly Dictionary<string, ImageSource?> Cache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly Queue<string> CacheOrder = new();
    private static readonly object CacheLock = new();

    public object? Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var source = Environment.ExpandEnvironmentVariables(value as string ?? "").Trim();
        if (source.Length == 0) return null;
        lock (CacheLock)
            if (Cache.TryGetValue(source, out var cached)) return cached;

        var image = LoadImage(source);
        lock (CacheLock)
        {
            if (Cache.Count >= MaximumCachedIcons && CacheOrder.TryDequeue(out var oldest))
                Cache.Remove(oldest);
            Cache[source] = image;
            CacheOrder.Enqueue(source);
        }
        return image;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();

    private static ImageSource? LoadImage(string source)
    {
        try
        {
            var (path, iconIndex) = ParseIconLocation(source);
            if (!File.Exists(path)) return null;
            var extension = Path.GetExtension(path);
            if (extension.Equals(".png", StringComparison.OrdinalIgnoreCase)
                || extension.Equals(".jpg", StringComparison.OrdinalIgnoreCase)
                || extension.Equals(".jpeg", StringComparison.OrdinalIgnoreCase)
                || extension.Equals(".bmp", StringComparison.OrdinalIgnoreCase))
            {
                var bitmap = new BitmapImage();
                bitmap.BeginInit();
                bitmap.CacheOption = BitmapCacheOption.OnLoad;
                bitmap.DecodePixelWidth = 64;
                bitmap.UriSource = new Uri(path, UriKind.Absolute);
                bitmap.EndInit();
                bitmap.Freeze();
                return bitmap;
            }

            var large = new IntPtr[1];
            var small = new IntPtr[1];
            if (ExtractIconEx(path, iconIndex, large, small, 1) == 0) return null;
            var handle = large[0] != IntPtr.Zero ? large[0] : small[0];
            if (handle == IntPtr.Zero) return null;
            try
            {
                var bitmap = Imaging.CreateBitmapSourceFromHIcon(
                    handle, Int32Rect.Empty, BitmapSizeOptions.FromWidthAndHeight(48, 48));
                bitmap.Freeze();
                return bitmap;
            }
            finally
            {
                if (large[0] != IntPtr.Zero) DestroyIcon(large[0]);
                if (small[0] != IntPtr.Zero && small[0] != large[0]) DestroyIcon(small[0]);
            }
        }
        catch { return null; }
    }

    private static (string Path, int Index) ParseIconLocation(string source)
    {
        source = source.Trim().TrimStart('@');
        var index = 0;
        var comma = source.LastIndexOf(',');
        if (comma > 0 && int.TryParse(source[(comma + 1)..].Trim(), out var parsed))
        {
            index = parsed;
            source = source[..comma];
        }
        return (source.Trim().Trim('"'), index);
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern uint ExtractIconEx(
        string szFileName, int nIconIndex, IntPtr[] phiconLarge, IntPtr[] phiconSmall, uint nIcons);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyIcon(IntPtr handle);
}
