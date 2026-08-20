using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using System.Windows.Data;
using UninstallMate.Infrastructure;
using UninstallMate.Models;
using UninstallMate.Services;
using UninstallMate.Services.Providers;

namespace UninstallMate.ViewModels;

public sealed class MainViewModel : ObservableObject
{
    private readonly AppDiscoveryService _discovery = new();
    private readonly UninstallService _uninstaller = new();
    private readonly CleanupScanner _scanner = new();
    private readonly CleanupService _cleaner = new();
    private readonly VerificationService _verifier = new();
    private readonly ICollectionView _appsView;
    private InstalledApplication? _selectedApp;
    private ApplicationIdentityGraph? _activeIdentity;
    private string _searchText = "";
    private string _status = "Ready";
    private bool _isBusy;
    private bool _includeSystem;
    private bool _quietUninstall;
    private bool _createRestorePoint;
    private bool _preserveCleanupBackups = true; // Safe default: recovery enabled
    private bool _isDeepScan;
    private bool _isCleanupReviewVisible;
    private string _lastSessionFolder = QuarantineService.FindLatestRestorableSession() ?? "";
    private CancellationTokenSource? _operation;

    public ObservableCollection<InstalledApplication> Applications { get; } = [];
    public ObservableCollection<CleanupCandidate> CleanupCandidates { get; } = [];
    public ObservableCollection<CleanupCandidate> ApplicationCleanupCandidates { get; } = [];
    public ObservableCollection<CleanupCandidate> UserCleanupCandidates { get; } = [];
    public ObservableCollection<CleanupCandidate> SystemCleanupCandidates { get; } = [];
    public ICollectionView ApplicationsView => _appsView;

    public string AppVersionText =>
        Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? Assembly.GetExecutingAssembly().GetName().Version?.ToString()
        ?? "2.0.0";

    public InstalledApplication? SelectedApp
    {
        get => _selectedApp;
        set
        {
            if (!SetProperty(ref _selectedApp, value)) return;
            CleanupCandidates.Clear();
            _activeIdentity = null;
            IsCleanupReviewVisible = false;
            RaisePropertyChanged(nameof(HasSelection));
            RaisePropertyChanged(nameof(HasNoSelection));
            RaiseCommandStates();
        }
    }

    public string SearchText
    {
        get => _searchText;
        set
        {
            if (!SetProperty(ref _searchText, value)) return;
            _appsView.Refresh();
            RaisePropertyChanged(nameof(VisibleCountText));
        }
    }

    public string Status { get => _status; private set => SetProperty(ref _status, value); }
    public bool IsBusy
    {
        get => _isBusy;
        private set
        {
            if (!SetProperty(ref _isBusy, value)) return;
            RaiseCommandStates();
        }
    }
    public bool IncludeSystem
    {
        get => _includeSystem;
        set
        {
            if (!SetProperty(ref _includeSystem, value)) return;
            if (!value && SelectedApp?.IsSystemComponent == true) SelectedApp = null;
            _appsView.Refresh();
            RaisePropertyChanged(nameof(VisibleCountText));
            Status = value ? "Showing applications and system components." : "System components are hidden.";
        }
    }
    public bool QuietUninstall { get => _quietUninstall; set => SetProperty(ref _quietUninstall, value); }
    public bool CreateRestorePoint { get => _createRestorePoint; set => SetProperty(ref _createRestorePoint, value); }
    public bool PreserveCleanupBackups
    {
        get => _preserveCleanupBackups;
        set
        {
            if (!SetProperty(ref _preserveCleanupBackups, value)) return;
            RaisePropertyChanged(nameof(CleanupActionLabel));
        }
    }
    public bool IsDeepScan
    {
        get => _isDeepScan;
        set => SetProperty(ref _isDeepScan, value);
    }
    public bool HasSelection => SelectedApp is not null;
    public bool HasNoSelection => SelectedApp is null;
    public bool IsCleanupReviewVisible
    {
        get => _isCleanupReviewVisible;
        private set => SetProperty(ref _isCleanupReviewVisible, value);
    }
    public string VisibleCountText => $"{_appsView.Cast<object>().Count():N0} apps";
    public string SelectedCleanupText => $"{CleanupCandidates.Count(x => x.IsSelected)} selected";
    public string ApplicationCleanupCountText => $"Application files ({ApplicationCleanupCandidates.Count})";
    public string UserCleanupCountText => $"User files ({UserCleanupCandidates.Count})";
    public string SystemCleanupCountText => $"System files ({SystemCleanupCandidates.Count})";
    public string CleanupActionLabel
    {
        get
        {
            var count = CleanupCandidates.Count(x => x.IsSelected);
            if (count == 0) return PreserveCleanupBackups ? "Clean selected" : "Delete selected";
            return PreserveCleanupBackups ? $"Confirm & clean {count}" : $"Confirm & delete {count}";
        }
    }
    public string RecoveryStatusText => Directory.Exists(_lastSessionFolder)
        ? "Protected cleanup available"
        : "No restorable cleanup yet";

    public AsyncRelayCommand RefreshCommand { get; }
    public AsyncRelayCommand UninstallCommand { get; }
    public AsyncRelayCommand CleanCommand { get; }
    public AsyncRelayCommand ExportCommand { get; }
    public RelayCommand CancelCommand { get; }
    public RelayCommand OpenQuarantineCommand { get; }
    public AsyncRelayCommand RestoreQuarantineCommand { get; }
    public RelayCommand SelectSafeCommand { get; }
    public RelayCommand SelectAllCommand { get; }
    public RelayCommand ClearSelectionCommand { get; }

    public MainViewModel()
    {
        _appsView = CollectionViewSource.GetDefaultView(Applications);
        _appsView.Filter = FilterApplication;
        RefreshCommand = new(RefreshAsync, () => !IsBusy);
        UninstallCommand = new(UninstallAsync, () => !IsBusy && SelectedApp is not null);
        CleanCommand = new(CleanAsync, () => !IsBusy && CleanupCandidates.Any(x => x.IsSelected));
        ExportCommand = new(ExportAsync, () => !IsBusy && Applications.Count > 0);
        CancelCommand = new(() => _operation?.Cancel(), () => IsBusy);
        OpenQuarantineCommand = new(OpenQuarantine, () => !IsBusy);
        RestoreQuarantineCommand = new(RestoreQuarantineAsync, () => !IsBusy && Directory.Exists(_lastSessionFolder));
        SelectSafeCommand = new(() => SetCandidateSelection(safeOnly: true), () => CleanupCandidates.Count > 0);
        SelectAllCommand = new(() =>
        {
            foreach (var candidate in CleanupCandidates) candidate.IsSelected = true;
            RaiseCleanupState();
        }, () => CleanupCandidates.Count > 0);
        ClearSelectionCommand = new(() => SetCandidateSelection(safeOnly: false), () => CleanupCandidates.Count > 0);
        CleanupCandidates.CollectionChanged += CleanupCollectionChanged;
    }

    public void CancelPendingOperation() => _operation?.Cancel();

    private bool FilterApplication(object item)
    {
        if (item is not InstalledApplication app) return false;
        if (!IncludeSystem && app.IsSystemComponent) return false;
        if (string.IsNullOrWhiteSpace(SearchText)) return true;
        return app.DisplayName.Contains(SearchText, StringComparison.CurrentCultureIgnoreCase)
            || app.Publisher.Contains(SearchText, StringComparison.CurrentCultureIgnoreCase)
            || app.Version.Contains(SearchText, StringComparison.CurrentCultureIgnoreCase);
    }

    private async Task RefreshAsync()
    {
        await RunBusyAsync("Scanning installed applications…", async token =>
        {
            var previousId = SelectedApp?.Id;
            var apps = await _discovery.DiscoverAsync(includeSystem: true, token);
            Applications.Clear();
            foreach (var app in apps) Applications.Add(app);
            SelectedApp = Applications.FirstOrDefault(x => x.Id == previousId);
            _appsView.Refresh();
            RaisePropertyChanged(nameof(VisibleCountText));
            Status = $"Showing {_appsView.Cast<object>().Count():N0} of {Applications.Count:N0} discovered entries.";
        });
    }

    private async Task UninstallAsync()
    {
        var app = SelectedApp;
        if (app is null) return;
        CleanupCandidates.Clear();
        IsCleanupReviewVisible = false;

        if (!app.HasUninstaller)
        {
            var scan = await DialogService.ShowAsync(
                "Uninstaller unavailable",
                $"Windows does not have a registered uninstaller for {app.DisplayName}.\n\nUninstallMate can scan for the application's files and registrations so you can review them before anything is removed.",
                "Scan leftovers",
                "Cancel",
                DialogTone.Warning);
            if (scan) await ScanForCleanupOnlyAsync(app);
            return;
        }

        await RunBusyAsync($"Preparing to uninstall {app.DisplayName}…", async token =>
        {
            Status = $"Capturing pre-uninstall evidence for {app.DisplayName}…";
            var captureResult = await ApplicationIdentityGraph.CaptureWithDiagnosticsAsync(app, token);
            _activeIdentity = captureResult.Identity;

            if (CreateRestorePoint) Status = await RestorePointService.TryCreateAsync(app.DisplayName, token);
            Status = $"Running {app.DisplayName}'s uninstaller…";
            var result = await _uninstaller.UninstallAsync(app, QuietUninstall, token);
            if (!result.Success)
            {
                await DialogService.ShowAsync(
                    "Uninstall needs attention",
                    result.Message,
                    tone: DialogTone.Warning);
                Status = result.Message;
                return;
            }
            Status = result.Message + " Verifying that Windows no longer reports the app as installed…";
            var stillRegistered = await _uninstaller.IsApplicationRegisteredAsync(app, token);
            if (stillRegistered != false)
            {
                CleanupCandidates.Clear();
                Status = stillRegistered == true
                    ? "The uninstaller closed, but Windows still reports this application as installed. Leftover cleanup is disabled to protect its live files."
                    : "Windows could not verify that the application was removed. Leftover cleanup is disabled to protect its live files.";
                return;
            }

            Status = result.Message + " Windows confirms removal; scanning for leftovers…";
            await ScanCoreAsync(_activeIdentity ?? ApplicationIdentityGraph.Create(app), token);
            if (CleanupCandidates.Count == 0)
            {
                var rediscovered = await RefreshInventoryCoreAsync(app, token);
                Status = rediscovered
                    ? "The uninstaller finished, but Windows still has an application registration."
                    : result.Message + " Inventory refreshed.";
            }
        });
    }

    private async Task ScanForCleanupOnlyAsync(InstalledApplication app)
    {
        await RunBusyAsync($"Scanning leftovers for {app.DisplayName}…", async token =>
        {
            _activeIdentity = await ApplicationIdentityGraph.CaptureAsync(app, token);
            await ScanCoreAsync(_activeIdentity, token);
        });
    }

    private async Task ScanCoreAsync(ApplicationIdentityGraph identity, CancellationToken token)
    {
        IsCleanupReviewVisible = false;
        var progress = new Progress<string>(p => Status = p);
        var context = new CleanupScanContext
        {
            IsDeepScan = IsDeepScan,
            InstalledApplications = Applications.ToList(),
            PreUninstallIdentity = identity
        };

        var scanResult = await _scanner.ScanWithDetailsAsync(identity, context, progress, token);
        CleanupCandidates.Clear();
        foreach (var candidate in scanResult.Candidates)
        {
            // Scanner dedup computes selection via CleanupSelectionPolicy
            CleanupCandidates.Add(candidate);
        }

        IsCleanupReviewVisible = CleanupCandidates.Count > 0;
        var autoSelectedCount = CleanupCandidates.Count(x => x.IsSelected);
        var totalCount = CleanupCandidates.Count;

        if (totalCount == 0)
        {
            Status = scanResult.Status == ScanStatus.Complete
                ? "No high-confidence leftovers were found."
                : $"Scan completed with status: {scanResult.Status}. No leftovers found.";
        }
        else
        {
            Status = $"Found {totalCount} leftover item(s) ({autoSelectedCount} safe item(s) selected). Review items on the right and confirm cleanup.";
        }

        RaiseCleanupState();
    }

    private async Task CleanAsync()
    {
        var app = SelectedApp;
        var selected = CleanupCandidates.Where(x => x.IsSelected).ToList();
        if (app is null || selected.Count == 0) return;
        var identity = _activeIdentity ?? ApplicationIdentityGraph.Create(app);

        await RunBusyAsync(PreserveCleanupBackups ? "Creating backup and quarantine…" : "Permanently deleting selected leftovers…", async token =>
        {
            if (CreateRestorePoint) Status = await RestorePointService.TryCreateAsync(app.DisplayName, token);
            var progress = new Progress<string>(message => Status = message);
            var (report, folder) = await _cleaner.ExecuteAsync(app, selected, PreserveCleanupBackups, progress, token);
            if (PreserveCleanupBackups) _lastSessionFolder = folder;

            // Remove successfully cleaned items from candidate list
            foreach (var completed in report.Items.Where(x => x.Success))
            {
                var candidate = CleanupCandidates.FirstOrDefault(x =>
                    x.Target.Equals(completed.Target, StringComparison.OrdinalIgnoreCase)
                    && x.Kind == completed.Kind
                    && x.RegistryViewName == completed.RegistryViewName
                    && x.Auxiliary == completed.Auxiliary
                    && x.EvidencePath == completed.EvidencePath);
                if (candidate is not null) CleanupCandidates.Remove(candidate);
            }

            // Run post-clean verification scan!
            Status = "Verifying cleanup status across all providers…";
            var verification = await _verifier.VerifyAsync(identity, report, progress, token);
            Status = verification.OutcomeMessage;

            // Atomically update final report with verification results
            await CleanupService.SaveReportAtomicallyAsync(report, folder, token);

            if (verification.Outcome == VerificationOutcome.Clean)
            {
                await RefreshInventoryCoreAsync(app, token);
            }

            RaiseCleanupState();
            if (verification.Outcome is VerificationOutcome.CleanupIncomplete or VerificationOutcome.ScanIncomplete)
            {
                await DialogService.ShowAsync(
                    "Cleanup needs attention",
                    Status + $"\n\nSession report: {Path.Combine(folder, "cleanup-report.json")}",
                    tone: DialogTone.Warning);
            }
        });
    }

    private async Task<bool> RefreshInventoryCoreAsync(InstalledApplication removedApp, CancellationToken token)
    {
        var apps = await _discovery.DiscoverAsync(includeSystem: true, token);
        Applications.Clear();
        foreach (var discovered in apps) Applications.Add(discovered);
        SelectedApp = null;
        _appsView.Refresh();
        RaisePropertyChanged(nameof(VisibleCountText));
        return Applications.Any(x => AppDiscoveryService.SameApplicationIdentity(x, removedApp));
    }

    private async Task ExportAsync()
    {
        var dialog = new SaveFileDialog
        {
            Title = "Export installed application inventory",
            Filter = "CSV file (*.csv)|*.csv",
            FileName = $"installed-apps-{DateTime.Now:yyyy-MM-dd}.csv"
        };
        if (dialog.ShowDialog() != true) return;
        await RunBusyAsync("Exporting inventory…", async _ =>
        {
            await ExportService.ExportCsvAsync(_appsView.Cast<InstalledApplication>(), dialog.FileName);
            Status = $"Exported to {dialog.FileName}";
        });
    }

    private async Task RunBusyAsync(string status, Func<CancellationToken, Task> operation)
    {
        if (IsBusy) return;
        _operation = new CancellationTokenSource();
        IsBusy = true;
        Status = status;
        try { await operation(_operation.Token); }
        catch (OperationCanceledException) { Status = "Operation cancelled."; }
        catch (Exception ex)
        {
            Status = ex.Message;
            await DialogService.ShowAsync("Something went wrong", ex.Message, tone: DialogTone.Error);
        }
        finally
        {
            _operation.Dispose();
            _operation = null;
            IsBusy = false;
        }
    }

    private void SetCandidateSelection(bool safeOnly)
    {
        foreach (var candidate in CleanupCandidates)
        {
            candidate.IsSelected = safeOnly && CleanupSelectionPolicy.ShouldAutoSelect(candidate);
        }
        RaiseCleanupState();
    }

    private void CandidateChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(CleanupCandidate.IsSelected)) RaiseCleanupState();
    }

    private void CleanupCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (e.Action == NotifyCollectionChangedAction.Reset)
        {
            ApplicationCleanupCandidates.Clear();
            UserCleanupCandidates.Clear();
            SystemCleanupCandidates.Clear();
        }
        if (e.OldItems is not null)
            foreach (CleanupCandidate candidate in e.OldItems)
            {
                candidate.PropertyChanged -= CandidateChanged;
                ApplicationCleanupCandidates.Remove(candidate);
                UserCleanupCandidates.Remove(candidate);
                SystemCleanupCandidates.Remove(candidate);
            }
        if (e.NewItems is not null)
            foreach (CleanupCandidate candidate in e.NewItems)
            {
                candidate.PropertyChanged += CandidateChanged;
                switch (candidate.Scope)
                {
                    case CleanupScope.Application:
                        ApplicationCleanupCandidates.Add(candidate);
                        break;
                    case CleanupScope.User:
                        UserCleanupCandidates.Add(candidate);
                        break;
                    default:
                        SystemCleanupCandidates.Add(candidate);
                        break;
                }
            }
        RaiseCleanupState();
    }

    private void RaiseCleanupState()
    {
        RaisePropertyChanged(nameof(SelectedCleanupText));
        RaisePropertyChanged(nameof(ApplicationCleanupCountText));
        RaisePropertyChanged(nameof(UserCleanupCountText));
        RaisePropertyChanged(nameof(SystemCleanupCountText));
        RaisePropertyChanged(nameof(CleanupActionLabel));
        CleanCommand.RaiseCanExecuteChanged();
        SelectSafeCommand.RaiseCanExecuteChanged();
        SelectAllCommand.RaiseCanExecuteChanged();
        ClearSelectionCommand.RaiseCanExecuteChanged();
    }

    private void RaiseCommandStates()
    {
        RefreshCommand.RaiseCanExecuteChanged();
        UninstallCommand.RaiseCanExecuteChanged();
        CleanCommand.RaiseCanExecuteChanged();
        ExportCommand.RaiseCanExecuteChanged();
        CancelCommand.RaiseCanExecuteChanged();
        OpenQuarantineCommand.RaiseCanExecuteChanged();
        RestoreQuarantineCommand.RaiseCanExecuteChanged();
        RaisePropertyChanged(nameof(RecoveryStatusText));
    }

    private void OpenQuarantine()
    {
        Directory.CreateDirectory(QuarantineService.DefaultQuarantineRoot);
        Process.Start(new ProcessStartInfo("explorer.exe", QuarantineService.DefaultQuarantineRoot) { UseShellExecute = true });
    }

    private async Task RestoreQuarantineAsync()
    {
        if (!Directory.Exists(_lastSessionFolder)) return;
        if (!await DialogService.ShowAsync(
            "Restore last cleanup?",
            "Files and registry keys from the last cleanup session will be restored. If an original location is already occupied, its newer data will not be overwritten.",
            "Restore items",
            "Cancel")) return;
        await RunBusyAsync("Restoring the last cleanup session…", async token =>
        {
            var (restored, failed) = await QuarantineService.RestoreAsync(_lastSessionFolder, token);
            Status = $"Restored {restored} item(s)" + (failed > 0 ? $"; {failed} could not be restored." : ".");
            _lastSessionFolder = QuarantineService.FindLatestRestorableSession() ?? "";
            RaiseCommandStates();
            if (failed > 0) await DialogService.ShowAsync("Some items were not restored", Status, tone: DialogTone.Warning);
        });
    }
}
