using System.Windows;
using Wpf.Ui.Controls;

namespace UninstallMate.Services;

public enum DialogTone
{
    Information,
    Warning,
    Danger,
    Error
}

public static class DialogService
{
    public static async Task<bool> ShowAsync(
        string heading,
        string message,
        string primaryText = "OK",
        string? secondaryText = null,
        DialogTone tone = DialogTone.Information)
    {
        var hasChoice = !string.IsNullOrWhiteSpace(secondaryText);
        var dialog = new Wpf.Ui.Controls.MessageBox
        {
            Title = heading,
            Content = message,
            ShowTitle = true,
            PrimaryButtonText = hasChoice ? primaryText : "",
            CloseButtonText = hasChoice ? secondaryText! : primaryText,
            PrimaryButtonAppearance = tone switch
            {
                DialogTone.Danger or DialogTone.Error => ControlAppearance.Danger,
                DialogTone.Warning => ControlAppearance.Caution,
                _ => ControlAppearance.Primary
            },
            CloseButtonAppearance = ControlAppearance.Secondary,
            Owner = Application.Current?.MainWindow,
            WindowStartupLocation = WindowStartupLocation.CenterOwner
        };

        var result = await dialog.ShowDialogAsync();
        return hasChoice && result == Wpf.Ui.Controls.MessageBoxResult.Primary;
    }
}
