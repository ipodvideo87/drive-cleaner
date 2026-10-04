# Drive Cleanup Safety Knowledge Base

## Safety summary

- Leave unclear paths untouched. Treat an unfamiliar file or application as protected until the user identifies it.
- Review every exact path before cleanup. A classification is a suggestion, not permission to delete.
- Offer an optional recovery backup. If the user chooses one, create and verify a complete backup on a different drive before removing anything; if a target is skipped, storage is unavailable, or verification fails, stop cleanup. If the user declines, clearly warn that Drive Cleanr cannot restore removed data and require the cleanup script's distinct `DELETE WITHOUT BACKUP` confirmation. For a reviewed noninteractive plan, `-Force` confirms cleanup without a backup by default; add `-Backup` to opt in to a verified backup.
- Treat restore manifests and archives as untrusted: validate every destination before writing, reject network/device/traversal targets, and do not extract through reparse points.
- Never directly remove Windows component stores, restore points, installed-program repair data, personal files, messaging data, or credentials.
- Prefer allocated size when available. WizTree-marked hard-link file rows are excluded, and nested suggestions are counted once in the report total; folder rows still show full sizes, protected contents remain, and actual free-space gains can differ from the estimate.
- Omit cache-like candidates beneath recognized project roots (for example `.git` and Git metadata files, `.idea`/`.vscode`/`.vs` workspace folders, agent/editor project settings folders such as `.claude`, `.cursor`, `.gemini`, `.github`, `.opencode`, and `.windsurf`, VS Code `*.code-workspace` files, project guidance such as `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `SKILL.md`, `.cursorrules`, and `copilot-instructions.md`, Unreal `.uproject`/`.uplugin` descriptors, Godot `project.godot`, Unity `ProjectSettings`, Python/JavaScript/Rust manifests, Visual Studio `.sln`/`.csproj` files, or Docker build files) because project contents can mix generated files with source and local state. Protect `.vscode` paths because the user-profile `~/.vscode/extensions` folder stores installed VS Code extensions. At a user-profile root, shared editor and agent settings files/folders and common Node metadata do not mark the entire profile as a project. Treat directories that cannot be checked for project markers as protected.
- For a project without a recognized marker, the user can place `.drive-cleanr-protect` in the project root to exclude that entire tree.
- Do not directly clean `SoftwareDistribution\\Download`; Windows update state can be hard to assess, so use Windows Storage or Disk Cleanup.
- Do not suggest recovered previous-installation data, `$WinREAgent`, Windows Update logs, or Service Worker storage for direct cleanup.
- A scan is complete when the selected scanner exits and its export is stable, not merely when file growth pauses.
- Before selected file removal, verify the saved backup against the live source when a backup was enabled. In all modes, remove a selected file through a Windows handle after matching its captured file identity and SHA-256 hash, holding a shared byte-range lock against ordinary file-handle writes during the final check and removal. Windows does not enforce byte-range locks for writes through an existing memory-mapped view, so close applications that may be using a candidate before cleanup. Reject reparse points or identity changes rather than reopening an untrusted path for deletion. Remove directories by handle only when they are still empty.
- Automated cleanup patterns match complete Windows path components; multi-component patterns must appear as adjacent components. Similar names embedded in larger words are not sufficient to label a path. The most-specific matching pattern wins, and equally specific overlaps use the more cautious tier. Generated plans revalidate every target against the selected tier and exact cleanup label before writing the script.
- Dump folders and filenames are candidates only under the drive's `Windows` directory; similarly named user archives and project folders stay untouched.
- Protect OneDrive's standard organization-root form (`OneDrive - <organization>`) while leaving unrelated sibling names such as `OneDriveBackup` to normal path review.
- Do not label app-specific Bcut (`BCUT`) cache data as lower-risk disposable based on its name alone. Its contents and rebuild behavior are not established in verified vendor documentation; the generic cache rule can surface it only as a caution item requiring exact path/content review. Prefer the app's own controls when available.

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
| `AppData\Local\Packages\<package>\` | Store app data and state; manage Store apps through Windows Settings or `winget` rather than deleting their package data |
| `.codex`, legacy `.codex-old` profiles, `.agents`, Microsoft Store `OpenAI.Codex_*` package data, `AppData\Roaming\Codex`, and container-machine cache trees | Hold tool configuration, installed skills, extension data, app state, or container state that may be actively in use |
| `.claude`, `.cursor`, `.gemini`, `.github`, `.opencode`, and `.windsurf` settings folders | May contain agent authentication, prompt history, editor state, account configuration, or project instructions; keep them out of cleanup suggestions |
| `Documents`, `Desktop`, `Pictures`, `Videos`, `Downloads`, `Music`, `Contacts`, `Favorites`, `Links`, `Saved Games`, `Saved Pictures`, `Camera Roll`, `Searches`, `3D Objects`, `Tencent Files`, and `xwechat_files` | Personal files, project sources, installers, and messaging data |
| `.ssh`, `.gnupg`, `.aws`, `.azure`, `.kube`, `.docker`, `.config\gcloud`, `.config\gh`, certificates, and application settings folders | Credentials and configuration |
| Anything the user does not recognize | Ask first; leave it untouched if its purpose is still unclear |

## Tier 0: Lower-risk, recreatable data

| Item | Example paths | Notes |
|---|---|---|
| Known temporary folders | `C:\Windows\Temp`, `C:\Windows\SystemTemp`, `%TEMP%`, `%TMP%` | Check for installers or builds in progress. Preserve every `claude*` item and subtree under `%TEMP%`. Folders under `Downloads` remain protected because they may be project inputs. Other folders merely named `Temp` or `Tmp` stay in the caution tier. |
| Recycle Bin contents | Use the Windows Recycle Bin interface | Manual only; Drive Cleanr does not create cleanup candidates for the Recycle Bin. Confirm the user does not need to recover anything first. |
| Driver or downloader leftovers | `MyDrivers\update\*.td`, `KDubaSoftDownloads` | Manual-review examples only; Drive Cleanr does not classify these paths automatically because they may be incomplete installer downloads. |
| Known package caches | npm, pip, Yarn, Puppeteer, and Electron caches | Drive Cleanr only suggests its recognized cache locations. Prefer each package manager or app's own cleanup command and check that no install or download is using them. |

## Tier 1: Review the side effects

| Item | Typical size | Side effects and notes |
|---|---:|---|
| Chrome on-device AI model at `...\Chrome\User Data\OptGuideOnDeviceModel` | About 4 GB | Drive Cleanr places this in its caution tier. Close Chrome first; Chrome may download the model again. Consider disabling `optimization-guide-on-device-model` in `chrome://flags` if you do not want it downloaded again. |
| Windows crash dumps under `C:\Windows\LiveKernelReports`, `C:\Windows\CrashDumps`, `C:\Windows\Minidump`, or `C:\Windows\MEMORY.DMP` | Varies; can be several GB | Keep while troubleshooting or waiting on support. Dump types can contain memory data; review privacy before copying or sharing. Only these Windows-root locations match automatically, and each target still needs review. |
| DISM component cleanup | 2–4 GB | Use `DISM /Online /Cleanup-Image /StartComponentCleanup`. Never add `/ResetBase`; that removes the ability to uninstall updates. WinSxS and System32 share hard links, so apparent size can exceed recovered space. |
| VS Code caches at `%APPDATA%\Code\{CachedExtensionVSIXs,CachedData,Cache,Crashpad}` | 1–2 GB | Close VS Code first. Preserve `WebStorage` and `User`, which hold extension state and settings. |
| Build caches such as `.gradle\caches`, `.cargo\registry`, Go modules, and `.nuget\packages` | Varies | These recognized paths are placed in the confirm-impact tier. Builds may need to download the data again; confirm no build is running. Maven `.m2` is a manual-review cue and is not an automatic candidate rule. |
| Cargo install output and Chocolatey staging under known temp roots | Varies | These locations can contain compiled executables or installer payloads, not disposable scratch files. Confirm the install/build finished and inspect contents before selecting them. |
| Updater cache at `GoogleUpdater\crx_cache` | Varies | Manual review only; Drive Cleanr has no specific automatic rule for this path. Usually recreated automatically; may require administrator rights. |
| Error reports at `ProgramData\...\WER\{ReportQueue,ReportArchive}` | Varies | Manual review only; Drive Cleanr has no specific automatic rule for these reports. Removing them loses diagnostic history. |
| Delivery Optimization cache | Varies | Use the supported `Delete-DeliveryOptimizationCache -Force` cmdlet. A folder named `Cache` may still appear under the generic caution rule, so review its exact location. |
| Folders named `Temp` or `Tmp` outside known Windows and user temp locations | — | The name alone does not establish that contents are temporary; inspect the owner and contents before considering cleanup. |

## Tier 2: Require an item-by-item user decision

- **Chrome and Edge IndexedDB profile data** can hold offline site data and sign-in state. Clear it through the browser when possible; Drive Cleanr only recognizes standard Chrome/Edge User Data profile paths, and custom browser data paths without those expected components are not automatically classified.
- **NVIDIA App update artifacts** at ProgramData\NVIDIA Corporation\NVIDIA App\UpdateFramework\ota-artifacts or ProgramData\NVIDIA Corporation\NvApp-UpdateFramework\ota-artifacts: confirm that no driver download or installation is active. Treat these as update data, not disposable cache, until you know they are no longer needed.
- **Driver backups**, such as `C:\MyDrivers\backup`: consider moving them to a data drive instead of deleting them.
- **Development toolchains**, such as VS Build Tools, Windows Kits, and `.rustup`: ask whether the user builds native software. Native npm modules can depend on Build Tools.
- **Multiple installations of the same application**, such as a Store app, standalone CLI, and global npm package: ask which installation the user uses.
- **Store apps**, such as Power Automate, Skype, GamingApp, or Clipchamp: remove through Windows Settings or `winget`, not by deleting their folders.
- **Jianying and other editing apps**: Jianying's `User Data` may contain drafts. Do not delete it directly; clear caches in the app. Clear WeChat or QQ data from their own storage controls, and preserve chat history.
- **Global npm packages**: show `npm ls -g` and let the user choose packages.
- **Test browser runtimes**, such as `ms-playwright`: they can be reinstalled with `npx playwright install`, but require a deliberate choice.
- **Scoop downloaded installers** under `scoop\cache`: these may be useful for offline reinstalls. Prefer Scoop's own cache controls after reviewing what will be removed; see the [Scoop folder layout](https://github.com/ScoopInstaller/Scoop/wiki/Scoop-Folder-Layout) and [command list](https://github.com/ScoopInstaller/Scoop/wiki/Commands).

## What Drive Cleanr suggests automatically

Only entries matching the rules in `analyze.py` appear as cleanup candidates. The tiers currently cover:

- **High:** contents of recognized Windows or user temporary folders, plus known pip, Puppeteer, Electron, npm, and Yarn cache locations.
- **Medium:** Windows crash dumps; Cargo install output and Chocolatey staging; Chrome's on-device model; recognized VS Code caches; generic cache, log, GPU, shader, and code-cache folders; and `Temp`/`Tmp` folders outside recognized temporary locations.
- **Low:** Gradle, Cargo registry, NuGet, and Go module caches; Scoop downloaded installers; NVIDIA App update artifacts; Playwright browser runtimes; and Chrome/Edge profile IndexedDB data.

Other examples in this guide, including the Recycle Bin, DISM component cleanup, `MyDrivers` leftovers, Maven `.m2`, GoogleUpdater `crx_cache`, and WER reports, are manual guidance rather than automatic Drive Cleanr cleanup candidates. Review the exact listed paths and labels before selecting anything.

## Path patterns to review

```text
Temporary folders       \\Temp\\$
Windows Update cache    SoftwareDistribution|DeliveryOptimization
Crash dumps             Windows\LiveKernelReports|Windows\CrashDumps|Windows\Minidump|Windows\MEMORY.DMP
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

The patterns in this review list are locating cues, not an exhaustive list of automated cleanup rules. Only entries in `analyze.py` are classified automatically; those rules use exact path components or adjacent component sequences. Generic Cache, Logs, GPUCache, ShaderCache, and Code Cache names are caution cues, not proof the contents can be discarded; review the exact location and contents.

## Execution rules

1. **Offer an optional verified recovery backup.** When enabled, create and verify a complete backup before the first removal. Stop if the backup is incomplete, any selected target was skipped, the source no longer matches, or verification fails. When declined, warn that removal cannot be restored through Drive Cleanr and require the distinct typed confirmation for interactive cleanup. For a reviewed noninteractive plan, `-Force` confirms cleanup without a backup by default; pass `-Backup` to opt in. For hidden or system folders, preserve attributes and inspect any backup with `Get-ChildItem -Force`.
2. **Check running processes before removing application caches.** For example, check Chrome, Edge, VS Code, and Java processes; defer affected items while those apps are running.
3. **Measure actual space reclaimed.** Compare `(Get-Volume C).SizeRemaining` before and after cleanup and keep a log.
4. **Handle permissions in separate steps.** Use user-level access first. Elevate only for items that require it and keep an operation log.
5. **Parse scanner exports as data.** WizTree GUI exports may start with a `Generated by...` note. Paths may be quoted, directory rows may end in `\\`, and folder sizes are cumulative. Parse large exports as a stream.
6. **Keep reclaimable-space estimates conservative.** Explain hard links and overlapping folder totals; the displayed sum can exceed the space actually recovered.
7. **Keep created backups through an observation period.** The default is seven days; remove a backup only after the user confirms everything still works. If no backup was created, do not imply that the cleanup can be restored.
