using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using UninstallMate.ViewModels;
using Wpf.Ui.Controls;

namespace UninstallMate;

public partial class MainWindow : FluentWindow
{
    private readonly MainViewModel _viewModel = new();

    public MainWindow()
    {
        InitializeComponent();
        DataContext = _viewModel;
        Loaded += (_, _) =>
        {
            UpdateResponsiveLayout(animate: false);
            _viewModel.RefreshCommand.Execute(null);
        };
        SizeChanged += (_, _) => UpdateResponsiveLayout(animate: true);
        Closed += (_, _) =>
        {
            _viewModel.CancelPendingOperation();
            Application.Current.Shutdown();
        };
    }

    private void UpdateResponsiveLayout(bool animate)
    {
        if (!IsLoaded && animate) return;
        var compact = ActualWidth < 1180;
        var targetWidth = compact ? 210d : 240d;
        var duration = animate ? TimeSpan.FromMilliseconds(180) : TimeSpan.Zero;
        NavigationPane.BeginAnimation(WidthProperty, new DoubleAnimation(targetWidth, duration)
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
        });
        NavigationPane.Padding = compact ? new Thickness(9, 18, 9, 14) : new Thickness(12, 18, 12, 14);
    }

    private void ApplicationSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        DetailsPanel.BeginAnimation(OpacityProperty, new DoubleAnimation(0.45, 1, TimeSpan.FromMilliseconds(170)));
        if (DetailsPanel.RenderTransform is TranslateTransform transform)
        {
            transform.BeginAnimation(TranslateTransform.XProperty,
                new DoubleAnimation(12, 0, TimeSpan.FromMilliseconds(190))
                {
                    EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
                });
        }
    }
}
