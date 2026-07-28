using System.Windows;
using System.Windows.Media;
using UninstallMate.Services;
using Wpf.Ui.Appearance;

namespace UninstallMate;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        // Keep the Fluent palette predictable and readable instead of inheriting
        // accent colors that may have poor contrast over an Acrylic backdrop.
        ApplicationAccentColorManager.Apply(
            Color.FromRgb(0x00, 0x78, 0xD4),
            ApplicationTheme.Dark,
            systemGlassColor: false,
            systemAccentColor: false);
        DispatcherUnhandledException += async (_, args) =>
        {
            args.Handled = true;
            await DialogService.ShowAsync("Unexpected error", args.Exception.Message, tone: DialogTone.Error);
        };
        base.OnStartup(e);
    }
}
