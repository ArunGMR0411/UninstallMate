using Microsoft.Win32;
using System.Text;
using UninstallMate.Models;

namespace UninstallMate.Services;

public static class ExportService
{
    public static async Task ExportCsvAsync(IEnumerable<InstalledApplication> apps, string path)
    {
        var output = new StringBuilder("Name,Publisher,Version,Size,Type,Scope,Install Location\r\n");
        foreach (var app in apps)
        {
            output.AppendLine(string.Join(',', new[]
            {
                Csv(app.DisplayName), Csv(app.Publisher), Csv(app.Version), Csv(app.SizeText), Csv(app.SourceText),
                Csv(app.Scope.ToString()), Csv(app.InstallLocation)
            }));
        }
        await File.WriteAllTextAsync(path, output.ToString(), new UTF8Encoding(true));
    }

    private static string Csv(string value) => $"\"{value.Replace("\"", "\"\"")}\"";
}
