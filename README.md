# UninstallMate

UninstallMate is a modern Windows 11 desktop uninstaller built with C# and WPF on .NET 8. It discovers classic desktop, MSI, and Microsoft Store/MSIX applications, runs the vendor's uninstaller, captures pre-uninstall evidence in an Application Identity Graph, and presents verified leftover candidates for review with granular confidence and risk grading.

The interface uses the open-source [WPF UI](https://github.com/lepoco/wpfui) Fluent control library with a Windows Settings-inspired responsive layout, a consistent high-contrast dark palette, a Windows-blue accent, an Acrylic backdrop, layered translucent surfaces, and native motion.

---

## Safety & Architectural Principles

1. **Evidence Over Loose Names**: Cleanup targets require positive path/provenance attribution correlated against pre-uninstall evidence. Name-only matches are never promoted to `Certain` and are never auto-selected.
2. **Safe Selection Defaults**: Only **Low Risk + High/Certain Confidence** items are selected by default. User data folders, system services, and environment PATH edits remain unselected by default for safety.
3. **Value-Level Isolated Backups**: Replaces whole-key registry exports with isolated, value-level JSON records. Restoring a value (such as a Task Manager `StartupApproved` entry) never reverts sibling application values.
4. **Merge-Safe PATH Restores**: PATH cleanup removes only the application's specific segments; restoring merges only the missing segment without overwriting subsequent unrelated PATH modifications.
5. **Fail-Closed Recovery**: When recovery mode is active (enabled by default), any failure during backup creation immediately aborts the destructive operation on that item.
6. **Task Manager / Neat Startup Remnant Purge**: Stale `StartupApproved` binary values in HKCU/HKLM `Run`, `Run32`, and `StartupFolder` are safely identified and cleaned after uninstallation without collateral impact on other apps.
7. **Modular Artifact Providers**: Monolithic scanning is refactored into 15 specialized providers with structured status reporting (`Complete`, `CompleteWithWarnings`, `Partial`, `AccessDenied`, `Failed`).
8. **Post-Clean Verification**: Re-runs scan across all providers and verifies application inventory removal to produce graded verification outcomes (`Clean`, `CleanAfterRestart`, `ResidualItemsRequireReview`, `CleanupIncomplete`, `ScanIncomplete`).

---

## Features

- Discovers 32-bit and 64-bit machine installs, per-user installs, MSI products, and current-user Store/MSIX packages.
- Resolves packaged-app manifest and Windows AppsFolder metadata so application and publisher columns use friendly names instead of raw identities, certificate subjects, or `ms-resource:` strings.
- Hides frameworks, runtimes, drivers, inbox packages, and OEM hardware-support components by default; the system-component toggle filters immediately.
- Shows installed-application icons by extracting registered EXE/DLL/ICO resources and resolving Store/MSIX `Square44x44Logo` assets.
- Converts MSI install commands (`/I`) to uninstall commands (`/X`), and handles restart-required MSI exit codes.
- Pre-uninstall snapshotting captures active startup entries, `.lnk` shortcut targets, services, and scheduled tasks before vendor uninstallers run.
- Scans registered install locations, exact app/publisher data directories, Store private-data folders, uninstall records, App Paths, COM registrations, Windows services, scheduled tasks, firewall rules, crash dumps, and event logs.
- Splits leftovers into dedicated **Application files**, **User files**, and **System files** tabs with explicit **Select safe**, **Select all**, and **Clear** actions.
- Protected cleanup enabled by default: saves value-level registry JSON records, service definitions, scheduled-task XMLs, and moves files to dated quarantine.
- Restores previous cleanup sessions without overwriting newer data at the destination.
- Exports the installed-app inventory as CSV and supports cancellation of running operations.

---

## Build and Run

Requirements: Windows 11 and the [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0).

```powershell
dotnet build .\UninstallMate.sln
dotnet run --project .\src\UninstallMate\UninstallMate.csproj
```

The application requests administrator access at startup because machine-wide uninstallers, registry keys, and services require elevation.

To build the self-contained executable:

```powershell
.\scripts\Publish.ps1
```

The executable is written to `artifacts\win-x64\UninstallMate.exe`, with a ZIP archive beside it. For Windows on ARM, run `.\scripts\Publish.ps1 -Runtime win-arm64`.

Run the automated test suite with:

```powershell
dotnet run --project .\tests\UninstallMate.LogicTests\UninstallMate.LogicTests.csproj
```

---

## Recommended Workflow

1. Close the application you wish to remove.
2. Select the application in UninstallMate and choose **Uninstall app** (or **Cleanup only** if no registered uninstaller exists).
3. Follow any vendor uninstaller prompts.
4. After Windows confirms removal, UninstallMate automatically scans for leftovers and selects only safe, low-risk items.
5. Review the items in the tabs on the right, toggle any items as needed, and click **Confirm & clean**.
6. Post-cleanup verification runs automatically and confirms system state.

---

## Project Structure

- `src/UninstallMate/Models/` — `ApplicationIdentityGraph`, `CleanupCandidate`, `OwnershipConfidence`, `OperationResult`, `TrackedInstallManifest`
- `src/UninstallMate/Services/Providers/` — 15 modular artifact providers implementing `ICleanupArtifactProvider`
- `src/UninstallMate/Services/CleanupScanner.cs` — provider orchestration, candidate deduplication, and shared-ownership protection
- `src/UninstallMate/Services/CleanupService.cs` — fail-closed deletion, value-level backups, and reboot deletion scheduling
- `src/UninstallMate/Services/QuarantineService.cs` — typed value restore, bundle view restore, and merge-safe PATH restore
- `src/UninstallMate/Services/VerificationService.cs` — post-clean multi-provider verification and outcome grading
- `src/UninstallMate/ViewModels/MainViewModel.cs` & `MainWindow.xaml` — UI layout, data binding, and selection commands
- `tests/UninstallMate.LogicTests/Program.cs` — automated regression and safety test suite

---

## License

MIT — see [LICENSE](LICENSE).
