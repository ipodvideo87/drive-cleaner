# Drive Cleanup Safety Knowledge Base

## Safety summary

- Leave unclear paths untouched. Treat an unfamiliar file or application as protected until the user identifies it.
- Review every exact path before cleanup. A classification is a suggestion, not permission to delete.
- Create and verify a complete backup on a different drive before removing anything. Stop if any selected target is skipped or the backup is incomplete.
- Treat restore manifests and archives as untrusted: validate every destination before writing, reject network/device/traversal targets, and do not extract through reparse points.
- Never directly remove Windows component stores, restore points, installed-program repair data, personal files, messaging data, or credentials.
- Prefer allocated size when available. Hard links and nested folder totals can inflate estimated reclaimable space.
- Omit cache-like candidates beneath recognized project roots (for example `.git`, `pyproject.toml`, `package.json`, or `Cargo.toml`) because project contents can mix generated files with source and local state.
- For a project without a recognized marker, the user can place `.drive-cleanr-protect` in the project root to exclude that entire tree.
- Do not directly clean `SoftwareDistribution\\Download`; Windows update state can be hard to assess, so use Windows Storage or Disk Cleanup.
- Do not suggest recovered previous-installation data, `$WinREAgent`, Windows Update logs, or Service Worker storage for direct cleanup.
- A scan is complete when the selected scanner exits and its export is stable, not merely when file growth pauses.

These rules are based on practical cleanup cases. In one case, 28.9 GB was recovered from one computer; roughly two-thirds came from items that required case-by-case review beyond the pattern list. These figures are examples only. Results vary by system and scan.

See the [user guide](../docs/GUIDE.md) and [project overview](../README.md) for the workflow.

## Protected paths and data

| Path or data | Why it is protected |
|---|---|
| `C:\$MFT`, `$Extend`, and the `$Recycle.Bin` structure | NTFS file-system metadata |
| `C:\System Volume Information\` | System restore points; manage only through Windows tools |
| `pagefile.sys`, `swapfile.sys`, and `hiberfil.sys` | Virtual memory and hibernation; change through Windows settings, never by deleting the files |
| `C:\Windows\Installer\` | Repair and uninstall data required by installed software |
| `C:\Windows\SoftwareDistribution\Download\` | Windows Update state can be difficult to assess; use Windows Storage or Disk Cleanup |
| `C:\ProgramData\Package Cache\` and application `InstallerCache` folders | Installer repair data |
| `C:\Windows\System32\config\` and its `.bak` files | Registry data and backups |
| `C:\Windows\System32\DriverStore\FileRepository\` | Active driver packages; driver maintenance is an advanced operation |
| The WinSxS component store, including `WinSxS\Temp` | Use DISM for supported maintenance; do not delete files directly |
| `C:\$WinREAgent`, `C:\ProgramData\USOShared\Logs`, and `Recovered-WindowsOld` | Windows recovery/update state and data retained from a previous installation |
| Browser `Service Worker` storage | Can contain offline site data and application state; clear it only through the browser or app |
| `.codex`, `.agents`, and container-machine cache trees | Hold tool configuration, installed skills, extension data, or container state that may be actively in use |
| `Documents`, `Desktop`, `Pictures`, `Videos`, `Downloads`, `Tencent Files`, and `xwechat_files` | Personal files, project sources, installers, and messaging data |
| `.ssh`, `.gnupg`, certificates, and application settings folders | Credentials and configuration |
| Anything the user does not recognize | Ask first; leave it untouched if its purpose is still unclear |

## Tier 0: Lower-risk, recreatable data

| Item | Example paths | Notes |
|---|---|---|
| Crash dumps | `C:\Windows\LiveKernelReports\*.dmp`, `C:\Windows\MEMORY.DMP`, `Minidump` | Diagnostic snapshots that can occupy several gigabytes; review before removal |
| Temporary folders | `C:\Windows\Temp`, `C:\Windows\SystemTemp`, `%TEMP%` | Check for installers or builds in progress. Preserve every `claude*` item and subtree under `%TEMP%`. Folders under `Downloads` remain protected because they may be project inputs. |
| Recycle Bin contents | Use the Windows Recycle Bin interface | Confirm the user does not need to recover anything first |
| Driver or downloader leftovers | `MyDrivers\update\*.td`, `KDubaSoftDownloads` | May be incomplete installer downloads |
| Package-manager caches | npm, pip, Scoop, and Electron caches | Prefer each package manager's own cleanup command |

## Tier 1: Review the side effects

| Item | Typical size | Side effects and notes |
|---|---:|---|
| Chrome on-device AI model at `...\Chrome\User Data\OptGuideOnDeviceModel` | About 4 GB | Close Chrome first. Consider disabling `optimization-guide-on-device-model` in `chrome://flags` to avoid a re-download. |
| DISM component cleanup | 2–4 GB | Use `DISM /Online /Cleanup-Image /StartComponentCleanup`. Never add `/ResetBase`; that removes the ability to uninstall updates. WinSxS and System32 share hard links, so apparent size can exceed recovered space. |
| VS Code caches at `%APPDATA%\Code\{CachedExtensionVSIXs,CachedData,Cache,Crashpad}` | 1–2 GB | Close VS Code first. Preserve `WebStorage` and `User`, which hold extension state and settings. |
| Build caches such as `.gradle\caches`, Go modules, `.nuget\packages`, and `.m2` | Varies | Builds may need to download the data again. Confirm no build is running. |
| Updater cache at `GoogleUpdater\crx_cache` | Varies | Usually recreated automatically; may require administrator rights. |
| Error reports at `ProgramData\...\WER\{ReportQueue,ReportArchive}` | Varies | Removes diagnostic history. |
| Delivery Optimization cache | Varies | Use the supported `Delete-DeliveryOptimizationCache -Force` cmdlet. |

## Tier 2: Require an item-by-item user decision

- **Driver backups**, such as `C:\MyDrivers\backup`: consider moving them to a data drive instead of deleting them.
- **Development toolchains**, such as VS Build Tools, Windows Kits, and `.rustup`: ask whether the user builds native software. Native npm modules can depend on Build Tools.
- **Multiple installations of the same application**, such as a Store app, standalone CLI, and global npm package: ask which installation the user uses.
- **Store apps**, such as Power Automate, Skype, GamingApp, or Clipchamp: remove through Windows Settings or `winget`, not by deleting their folders.
- **Jianying and other editing apps**: Jianying's `User Data` may contain drafts. Do not delete it directly; clear caches in the app. Clear WeChat or QQ data from their own storage controls, and preserve chat history.
- **Global npm packages**: show `npm ls -g` and let the user choose packages.
- **Test browser runtimes**, such as `ms-playwright`: they can be reinstalled with `npx playwright install`, but require a deliberate choice.

## Path patterns to review

```text
Temporary folders       \\Temp\\$
Windows Update cache    SoftwareDistribution|DeliveryOptimization
Crash dumps             LiveKernelReports|CrashDumps|Minidump
Installer caches        Package Cache|Downloaded Installations|InstallerCache|crx_cache
Driver utilities        MyDrivers|DriverGenius|Driver
Development toolchains  \.rustup|\.cargo|\.nuget|\.gradle|\.m2|go\\pkg|\.ollama|huggingface|conda
Package caches          npm-cache|pip\\cache|\.cache\\
Messaging data          Tencent|WeChat|WXWork|QQ
Browsers                Chrome|Edge|360se|Firefox
Testing and virtual     ms-playwright|wsl|\.vhdx?$
Large applications      Jianying|SodaMusic|BaiduNetdisk|Thunder|Kingsoft|DingTalk|Feishu
Apple backups            Apple|MobileSync
Error reports            \\WER\\|CrashReports
Large caches             Cache\\$|cache\\$
```

The installer-cache patterns are shown as reminders of protected data; their presence in a path does not make them cleanup candidates. Messaging folders also contain personal data and remain protected.

## Execution rules

1. **Back up or move before deleting.** Back up non-cache data first. For hidden or system folders, preserve attributes and inspect the backup with `Get-ChildItem -Force`.
2. **Check running processes before removing application caches.** For example, check Chrome, Edge, VS Code, and Java processes; defer affected items while those apps are running.
3. **Measure actual space reclaimed.** Compare `(Get-Volume C).SizeRemaining` before and after cleanup and keep a log.
4. **Handle permissions in separate steps.** Use user-level access first. Elevate only for items that require it and keep an operation log.
5. **Parse scanner exports as data.** WizTree GUI exports may start with a `Generated by...` note. Paths may be quoted, directory rows may end in `\\`, and folder sizes are cumulative. Parse large exports as a stream.
6. **Keep reclaimable-space estimates conservative.** Explain hard links and overlapping folder totals; the displayed sum can exceed the space actually recovered.
7. **Keep backups through an observation period.** The default is seven days; remove a backup only after the user confirms everything still works.
