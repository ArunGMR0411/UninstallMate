# UninstallMate

UninstallMate is a Windows 11 desktop uninstaller built with C# and WPF on .NET 8. It inventories classic desktop, MSI, and Microsoft Store/MSIX apps, launches the app's own registered removal mechanism, and then presents high-confidence leftovers for review.

The interface uses the open-source [WPF UI](https://github.com/lepoco/wpfui) Fluent control library with a Windows Settings-inspired responsive layout, a consistent high-contrast dark palette, a Windows-blue accent, an Acrylic backdrop, layered translucent surfaces, and native motion. The bundled WPF UI license is embedded in the application and kept under `src/UninstallMate/Assets`.

The important design rule is that cleanup is never based on a blind whole-disk name search. Every high-confidence candidate is selected for the single right-panel review requested by the user, with risk and scope kept visible so anything that should remain can be unchecked. Optional quarantine moves files and exports system definitions before cleanup; it can be enabled from the left sidebar.

## Features

- Discovers 32-bit and 64-bit machine installs, per-user installs, MSI products, and current-user Store/MSIX packages.
- Hides frameworks, runtimes, drivers, inbox packages and OEM hardware-support components by default; the system-component toggle filters immediately.
- Resolves packaged-app manifest and Windows AppsFolder metadata so application and publisher columns use friendly names instead of raw identities, certificate subjects, or `ms-resource:` strings.
- Uses packaged application IDs and executable metadata as safe fallbacks, preventing GUID package identities from being broken into fake application names.
- Shows installed-application icons by extracting registered EXE/DLL/ICO resources and resolving Store/MSIX `Square44x44Logo` assets, with an initial tile only when Windows provides no usable artwork.
- Opens registered uninstallers immediately without routine confirmation or completion popups, with dialogs reserved for missing uninstallers and actual operation failures.
- Shows only the uninstall action before removal; leftover scanning starts automatically after Windows confirms that the registered uninstaller completed.
- Collapses duplicate registry views and duplicate per-user/machine registrations while keeping different versions and genuinely separate install locations.
- Finds and cleans every equivalent uninstall registration across user/machine and 32/64-bit registry views, then refreshes inventory automatically after completed cleanup.
- Search by app, publisher, or version; inspect size, source, install scope, location, and uninstall availability.
- Uses the exact registered uninstall command, converts MSI install commands to uninstall commands, and understands restart-required MSI exit codes.
- Verifies Windows registration after nonzero vendor/MSIX exit codes, preventing false “uninstall failed” messages when removal actually succeeded.
- Offers cleanup-only mode when an uninstaller is missing or broken.
- Refuses to scan a registered application's live files as leftovers; cleanup starts only after Windows confirms that removal completed, except for the explicit cleanup-only path when no uninstaller exists.
- Scans registered install locations, exact app/publisher data directories, Store private-data folders, uninstall records, and exact app registry keys.
- Finds exact application remnants in Local, Roaming, LocalLow, ProgramData, temporary, Program Files, Common Files, Start menu, desktop, startup, Documents, Saved Games, and crash-dump locations.
- Detects path-backed startup and environment values, App Paths entries, COM registrations, file-association application keys, Windows services and drivers, and scheduled tasks.
- Separates low-, medium-, and high-risk leftovers. After scanning, every result is selected for a single in-panel review; uncheck anything that should be kept.
- Keeps the entire leftover-review section hidden during ordinary app browsing and reveals it only after removal is confirmed and leftover results exist.
- Splits leftovers into dedicated **Application files**, **User files**, and **System files** tabs so custom install directories are never mislabeled as Windows system files; provides Select safe, Select all, and Clear actions.
- Can create a Windows restore point before changing the system (optional, off by default, and non-blocking).
- Moves files to a dated quarantine, including same-drive quarantine for apps installed outside C:.
- Exports registry, service, and scheduled-task definitions before deletion in the default safety mode and always writes a JSON cleanup report.
- Restores the last cleanup without overwriting anything that now exists at the original location.
- Keeps quiet uninstall, restore points, and recovery backups off by default; each can be enabled independently from the left sidebar.
- Remembers the newest restorable quarantine session across restarts and keeps the quarantine folder directly accessible.
- Exits completely when the main window is closed; UninstallMate has no tray or background mode.
- Exports the installed-app inventory as CSV and supports cancellation of scans.

## Build and run

Requirements: Windows 11 and the [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0).

```powershell
dotnet build .\UninstallMate.sln
dotnet run --project .\src\UninstallMate\UninstallMate.csproj
```

The application requests administrator access at startup because machine-wide uninstallers and registry keys require it.

To create a portable, self-contained executable (the target PC does not need .NET installed):

```powershell
.\scripts\Publish.ps1
```

The executable is written to `artifacts\win-x64\UninstallMate.exe`, with a ZIP beside it. For Windows on ARM, run `.\scripts\Publish.ps1 -Runtime win-arm64`.

Run the build and dependency-free logic checks with `.\scripts\Test.ps1`.

## Recommended workflow

1. Close the application you want to remove.
2. Select it in UninstallMate and choose **Uninstall app**. If no uninstaller exists, choose **Cleanup only**.
3. Complete any prompts from the vendor's uninstaller.
4. UninstallMate automatically scans after confirmed removal and selects every detected leftover. Review the right panel and uncheck anything you want to keep.
5. Choose the **Confirm & clean/delete** action in that panel. Cleanup starts immediately without another confirmation window.

Restore points and recovery backups start unchecked. In this mode the right-panel button says **Confirm & delete N** and clicking it performs the reviewed cleanup without another confirmation window. Permanent mode still writes a JSON audit report under `%ProgramData%\UninstallMate\Logs`; this report lists actions but cannot restore deleted data. Enable **Keep backups and quarantine** first if recovery may be needed.

Cleanup reports and the primary quarantine live at `%ProgramData%\UninstallMate\Quarantine`. A secondary hidden `.UninstallMate-Quarantine` directory may be created at the root of another drive so large folders can be moved safely without crossing volumes.

## Safety boundaries

No general-purpose uninstaller can prove that every vaguely named file belongs exclusively to one app. Applications may share runtimes, publisher folders, services, drivers, databases, and user documents. UninstallMate therefore uses registered paths or exact identities and labels uncertain items as medium/high risk. In the requested one-panel workflow all findings are initially selected, so those labels and the Application/User/System tabs must be reviewed before confirmation. It intentionally avoids fuzzy whole-disk matches, Windows component-store content, installer/package caches, arbitrary documents, unrelated browser data, and driver-store packages.

Store application discovery covers packages registered to the current user. Windows-protected/non-removable packages are shown only when system components are enabled and are not forcibly removed.

## Project structure

- `Services/AppDiscoveryService.cs` — registry and Store package inventory
- `Services/UninstallService.cs` — registered uninstaller/MSI/MSIX execution
- `Services/CleanupScanner.cs` — conservative leftover discovery and risk grading
- `Services/CleanupService.cs` — backups, quarantine, and JSON audit report
- `Services/QuarantineService.cs` — guarded restore workflow
- `ViewModels/MainViewModel.cs` and `MainWindow.xaml` — UI workflow

## License

MIT — see [LICENSE](LICENSE).
