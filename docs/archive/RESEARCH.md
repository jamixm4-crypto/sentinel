# Sentinel — Phase 0: Deep Research Report

> **Date**: 2026-10-04  
> **Methodology**: 4 parallel research subagents with extensive web search  
> **Scope**: Windows 10/11, Linux (X11/Wayland), macOS 10.15–15 Sequoia

---

## Table of Contents
1. [Existing Open-Source Projects & Lessons](#1-existing-open-source-projects--lessons)
2. [Windows Detection Techniques](#2-windows-detection-techniques)
3. [Linux Detection Techniques](#3-linux-detection-techniques)
4. [macOS Detection Techniques](#4-macos-detection-techniques)
5. [Cross-Platform: Network, Remote Access, Known Families](#5-cross-platform)
6. [Rule Format Design](#6-rule-format-design)
7. [Removal Architecture Research](#7-removal-architecture-research)
8. [Legal & Ethical Analysis](#8-legal--ethical-analysis)
9. [Rust Ecosystem Crate Evaluation](#9-rust-ecosystem-crate-evaluation)
10. [Applicability Matrix](#10-applicability-matrix)
11. [Sources](#11-sources)

---

## 1. Existing Open-Source Projects & Lessons

| Project | Approach | License | Learnings for Sentinel | Why Not Fork/Copy |
|---------|----------|---------|----------------------|-------------------|
| **stalkerware-indicators** (AssoEchap) | YAML IoC database (packages, domains, hashes) | CC-BY-4.0 | YAML format for signatures; layered IoCs | Data license OK with attribution; code is Android-focused |
| **MVT** (Amnesty Int.) | Post-compromise forensic triage (iOS/Android) | MVT License v1.2 (MPL-2.0 + ethical clause) | SQLite/plist forensic parsing approach | **Cannot copy** — custom license incompatible with MIT/Apache-2.0 |
| **Sysinternals Autoruns** | 200+ Windows ASEP enumeration | Proprietary freeware | Exhaustive ASEP list; Authenticode + VT | Closed source — clean-room only |
| **osquery** | SQL schema over OS state | Apache-2.0 | Relational querying model; table plugin arch | Too heavy as dependency; learn from approach |
| **YARA** | Compiled byte/string matching | BSD-3-Clause | Aho-Corasick patterns; PE module inspection | File-only; can't query registry/WMI/network |
| **Sigma** | YAML log detection rules | DRL 1.1 / CC0 | YAML schema with value modifiers | Reactive (post-event); needs SIEM |
| **LOKI / THOR-lite** | Multi-stage IoC host scanner | **GPL-3.0** / Proprietary | Multi-tier pipeline: name→hash→YARA→net | **GPL-3.0 — cannot copy** into permissive project |
| **KnockKnock / BlockBlock** (Objective-See) | macOS persistence enum / real-time monitoring | **GPL-3.0** | Persistence-first catches nearly all consumer spyware | **GPL-3.0 — clean-room reimplementation only** |
| **chkrootkit / rkhunter** | Binary discrepancy / baseline hashing | BSD-2 / GPL-2.0+ | Cross-ref kernel vs userland data | Outdated signatures; high FP rate |
| **TinyCheck** (Kaspersky) | Out-of-band network traffic analysis | MIT | Zero device footprint; C2 beacon detection | Requires dedicated hardware (Raspberry Pi) |

> [!IMPORTANT]
> **Clean-room implementation mandate**: KnockKnock, BlockBlock, LOKI, and MVT code **cannot** be incorporated. All persistence paths, API calls, and TCC schemas are public OS specifications — reimplementing independently in Rust creates zero copyright liability.

---

## 2. Windows Detection Techniques

### 2.1 Persistence Mechanisms (User-Mode Accessible)

| Mechanism | Registry / Path | Key Values | Admin Required? |
|-----------|----------------|------------|-----------------|
| **Run/RunOnce keys** | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` (+ HKCU, WOW6432Node, RunOnce, RunOnceEx) | REG_SZ command strings | HKCU: No; HKLM: Read OK |
| **StartupApproved** | `HKLM\...\Explorer\StartupApproved\Run` (+ HKCU) | Binary: `02`=enabled, `03`=disabled | No |
| **Startup Folders** | `shell:startup`, `shell:common startup` | .lnk, .exe, .vbs, .bat, .ps1 | No |
| **Scheduled Tasks** | `schtasks /query /fo CSV /v` or COM `ITaskService` | XML in `C:\Windows\System32\Tasks\` | No for query |
| **Services** | `HKLM\SYSTEM\CurrentControlSet\Services\*` | `ImagePath`, `Start`, `Type`, `Parameters\ServiceDll` | Read OK; modify needs admin |
| **WMI Event Subscriptions** | `root\subscription` namespace | `__EventFilter`, `CommandLineEventConsumer`, `ActiveScriptEventConsumer`, `__FilterToConsumerBinding` | No for WQL query |
| **AppInit_DLLs** | `HKLM\...\Windows NT\CurrentVersion\Windows` (+ WOW6432Node) | `AppInit_DLLs`, `LoadAppInit_DLLs` | Read OK |
| **IFEO** | `HKLM\...\Image File Execution Options\<exe>` | `Debugger`, `GlobalFlag` (0x200), `SilentProcessExit\MonitorProcess` | Read OK |
| **Winlogon** | `HKLM\...\Winlogon` (+ HKCU) | `Shell` (default: `explorer.exe`), `Userinit` (default: `userinit.exe,`), `Notify` subkeys | Read OK |
| **BHO / Shell Extensions** | `HKLM\...\Browser Helper Objects\{GUID}` | InprocServer32 DLL path via HKCR\CLSID\{GUID} | Read OK |

### 2.2 Keyboard & Screen Capture Indicators

| Signal | API / Mechanism | Detection Method | Reliability | FP Risk |
|--------|----------------|------------------|-------------|---------|
| **Low-level keyboard hook** | `SetWindowsHookExW(WH_KEYBOARD_LL)` | PE import analysis of running process binaries | High | Medium — accessibility tools, password managers use this |
| **Polling keylogger** | `GetAsyncKeyState` / `GetKeyState` in tight loop | PE imports + heuristic (no UI window + short Sleep intervals) | Medium | Medium — game anti-cheat, hotkey managers |
| **Raw Input sink** | `RegisterRawInputDevices` with `RIDEV_INPUTSINK` flag | PE imports; `RIDEV_INPUTSINK` = definitive spy indicator | High | Low — legitimate use is rare |
| **GDI screen capture** | `GetDC(NULL)` → `BitBlt` / `PrintWindow` | PE imports in `GDI32.dll` + `USER32.dll` | Medium | High — screenshot tools, screen recorders |
| **DXGI Desktop Dup** | `IDXGIOutputDuplication::AcquireNextFrame` | PE imports `DXGI.dll` | Medium | High — game capture, streaming |
| **WinRT Capture** | `Windows.Graphics.Capture` + `IsBorderRequired=false` | API usage analysis | Medium | Medium |

> [!NOTE]
> **Hook owner identification is NOT possible via public Win32 API.** Windows manages hook chains in `win32kbase.sys`/`win32kfull.sys`. User-mode `gSharedInfo->aheList` was hardened in Win10/11. Detection relies on PE static analysis and behavioral heuristics.

### 2.3 CapabilityAccessManager ConsentStore

- **Path**: `HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\<capability>`
- **Capabilities**: `webcam`, `microphone`, `graphicsCaptureProgrammatic`, `location`
- **NonPackaged apps**: subkey name = full path with `\` → `#` (e.g., `C:#Program Files#Agent#spy.exe`)
- **Active capture indicator**: `LastUsedTimeStop == 0` OR `LastUsedTimeStart > LastUsedTimeStop`
- **Windows 11 DB**: `C:\ProgramData\Microsoft\Windows\CapabilityAccessManager\CapabilityAccessManager.db` (SQLite, ~30 day history)

### 2.4 Keyboard Filter Drivers

- **Path**: `HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E96B-E325-11CE-BFC1-08002BE10318}`
- **Baseline**: `UpperFilters` = `kbdclass` only; `LowerFilters` = empty
- **Any other entry** = potential kernel-level keylogger
- ⚠️ **Critical**: Removing `.sys` without cleaning `UpperFilters` causes **Device Manager Code 10/19** — keyboard disabled on reboot

### 2.5 Code Signing Verification

- **Embedded**: `WinVerifyTrust` with `WINTRUST_ACTION_GENERIC_VERIFY_V2`
- **Catalog fallback** (for OS binaries): `CryptCATAdminAcquireContext2` → `CryptCATAdminCalcHashFromFileHandle2` → `CryptCATAdminEnumCatalogFromHash`
- **CVE-2013-3900**: Check `EnableCertPaddingCheck` registry value; inspect PE size vs Authenticode boundary

### 2.6 Process Monitoring Detection

| Signal | Method | What It Detects |
|--------|--------|----------------|
| `SeDebugPrivilege` | `GetTokenInformation(TokenPrivileges)` | Processes that can inspect/modify other processes |
| Handle enumeration | `NtQuerySystemInformation(SystemExtendedHandleInformation)` | Processes holding `PROCESS_ALL_ACCESS` to many PIDs |
| WMI process watchers | WQL: `SELECT * FROM __EventFilter` in `root\subscription` | Process creation/termination subscriptions |
| Anti-kill drivers | `OpenProcess(PROCESS_TERMINATE)` returns `ACCESS_DENIED` despite `SeDebugPrivilege` | Kernel `ObRegisterCallbacks` stripping terminate right |
| Filesystem minifilters | `FilterFindFirst` / `fltmc instances` | Drivers protecting files from deletion |
| Foreground polling | `GetForegroundWindow` + `GetWindowText` in 1-5s loop | Activity/time tracking software |

### 2.7 Proxy / Certificate / Hosts Tampering

- **Proxy**: `HKCU\...\Internet Settings` → `ProxyEnable`, `ProxyServer`, `AutoConfigURL`
- **Root certs**: `HKLM/HKCU\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates` — compare against MS Trusted Root CTL
- **Hosts file**: `%SystemRoot%\System32\drivers\etc\hosts` — check for security vendor domain redirects

---

## 3. Linux Detection Techniques

### 3.1 Input Device Monitoring

| Signal | Path / Method | Permissions | Reliability |
|--------|--------------|-------------|-------------|
| **evdev fd access** | `/proc/<PID>/fd/*` → `/dev/input/event*` or `/dev/uinput` | Own processes: unprivileged; others: need `CAP_SYS_PTRACE` or root | High |
| **X11 XRecord/XInput2** | Check `/proc/<PID>/maps` for `libXtst.so`, `libXi.so` among X11 socket clients | Unprivileged (session clients) | Medium |
| **Wayland PipeWire** | `pw-dump \| jq` filter `media.class == "Stream/Input/Video"` — shows PID, binary | Unprivileged (session user) | High |
| **XDG Portal ScreenCast** | `dbus-monitor --session "interface='org.freedesktop.portal.ScreenCast'"` | Unprivileged | High |

> [!NOTE]
> **X11 vs Wayland**: X11 has NO client isolation — any client can snoop all keystrokes via XRecord without prompts. Wayland blocks inter-client input access; spyware must use kernel `/dev/input/` (needs root/`input` group) or PipeWire (visible in `pw-dump`). Wayland is significantly more defensible.

### 3.2 Persistence Mechanisms

| Mechanism | Locations | Unprivileged Readable? |
|-----------|-----------|----------------------|
| **systemd (system)** | `/etc/systemd/system/`, `/usr/lib/systemd/system/`, `/run/systemd/system/`, generators | Unit files: yes; manage: no |
| **systemd (user)** | `~/.config/systemd/user/`, `~/.local/share/systemd/user/` | Yes |
| **Cron** | `/etc/crontab`, `/etc/cron.d/`, `/var/spool/cron/crontabs/`, anacron | System crons: yes; user spool: own only |
| **XDG autostart** | `~/.config/autostart/*.desktop`, `/etc/xdg/autostart/` | Yes |
| **Shell rc files** | `~/.bashrc`, `~/.zshrc`, `~/.profile`, `~/.config/fish/config.fish`, `/etc/profile.d/` | Yes |
| **LD_PRELOAD** | `/etc/ld.so.preload`, `LD_PRELOAD` env in rc files | Yes |
| **Kernel modules** | `/proc/modules`, `lsmod`, `/etc/modules-load.d/`, `/etc/modprobe.d/` (install hooks) | `/proc/modules`: yes |
| **eBPF programs** | `bpftool prog list` | Needs `CAP_BPF`/`CAP_SYS_ADMIN`; but `anon_inode:bpf-*` in `/proc/<PID>/fd/` visible for own processes |

### 3.3 Process Monitoring Detection

| Signal | Method | Permissions |
|--------|--------|-------------|
| **ptrace attach** | `/proc/<PID>/status` → `TracerPid: >0` | Unprivileged |
| **High-freq /proc polling** | `/proc/<PID>/io` → high `syscr` with low `read_bytes` | Unprivileged (own processes) |
| **auditd execve rules** | Check `auditd` process existence + `/proc/net/netlink` for NETLINK_AUDIT | Unprivileged (detect presence only) |
| **eBPF tracers** | `/proc/<PID>/fd/*` → `anon_inode:bpf-prog/map/link` | Unprivileged (own processes) |
| **inotify on sensitive files** | `/proc/<PID>/fdinfo/<FD>` → inode numbers → `find -inum` | Unprivileged (own processes) |

### 3.4 Package Ownership Verification

| Distro | Query Ownership | Verify Integrity | Flags |
|--------|----------------|------------------|-------|
| Debian/Ubuntu | `dpkg -S /path` | `dpkg -V <pkg>` / `debsums -c` | `5`=checksum, `S`=size, `M`=perms |
| RHEL/Fedora | `rpm -qf /path` | `rpm -V <pkg>` / `rpm -Va` | Same flags |
| Arch | `pacman -Qo /path` | `pacman -Qk <pkg>` / `pacman -Qkk` | Modified files count |

### 3.5 Removal Procedures

- **Package manager**: `apt purge --autoremove`, `dnf remove`, `pacman -Rns`
- **systemd**: `stop` → `disable` → `mask` → delete unit file → `daemon-reload` → `reset-failed`
- **LD_PRELOAD**: ⚠️ Clear `/etc/ld.so.preload` **BEFORE** deleting `.so` (otherwise all commands break); check `chattr +i` immutable flag first
- **XDG autostart**: `rm ~/.config/autostart/<malware>.desktop`
- **Residual cleanup**: `~/.local/share/<app>/`, `~/.config/<app>/`, `/opt/<app>/`, `/var/log/<app>/`

---

## 4. macOS Detection Techniques

### 4.1 TCC Permissions

| Service | User-Facing Name | Introduced | Detection Without FDA |
|---------|-----------------|------------|----------------------|
| `kTCCServiceAccessibility` | Accessibility | 10.9 | `AXIsProcessTrustedWithOptions()` (own process) |
| `kTCCServiceListenEvent` | Input Monitoring | 10.15 | Event tap creation succeeds/fails |
| `kTCCServiceScreenCapture` | Screen Recording | 10.15 | `CGPreflightScreenCaptureAccess()` (≥11.0) |
| `kTCCServiceCamera` | Camera | 10.14 | `AVCaptureDevice authorizationStatusForMediaType:` |
| `kTCCServiceMicrophone` | Microphone | 10.14 | Same as camera |
| `kTCCServiceSystemPolicyAllFiles` | Full Disk Access | 10.14 | Probe: try reading `~/Library/Safari/Bookmarks.plist` |

- **TCC.db** (SQLite): `~/Library/Application Support/com.apple.TCC/TCC.db` (user) and `/Library/Application Support/com.apple.TCC/TCC.db` (system) — **requires FDA to read**
- **Active capture indicator**: `auth_value = 2` + `auth_reason = 6` (MDM silently granted) is suspicious
- **Other apps' permissions**: Not queryable via public API without FDA; use `CGGetEventTapList()` and `systemextensionsctl list` as indirect probes

### 4.2 Event Taps (`CGGetEventTapList`)

- Returns array of `CGEventTapInformation` structs with **exact PID** (`tappingProcess`), tap point, options, and event mask
- **Keyboard spy indicators**: `eventsOfInterest & ((1 << kCGEventKeyDown) | (1 << kCGEventKeyUp)) != 0`
- **Passive snooping**: `options == kCGEventTapOptionListenOnly`
- **Needs Accessibility permission** to call; unprivileged gets `tapCount = 0`

### 4.3 Persistence Mechanisms

| Mechanism | Locations | Writable By |
|-----------|-----------|-------------|
| **User LaunchAgents** | `~/Library/LaunchAgents/` | User — **primary unprivileged spyware location** |
| **Global LaunchAgents** | `/Library/LaunchAgents/` | Admin/root |
| **LaunchDaemons** | `/Library/LaunchDaemons/` | Admin/root — **primary stealth spyware location** |
| **Login Items (BTM)** | `SMAppService` / `BackgroundItems.btm` | Registered apps |
| **Legacy Login Items** | `com.apple.LSSharedFileList.SessionLoginItems.sfl2` | User |
| **System Extensions** | `/Library/SystemExtensions/` | Admin + user approval |
| **KEXTs** (deprecated) | `/Library/Extensions/` | Admin + reduced security on Apple Silicon |
| **MDM Profiles** | `/var/db/ConfigurationProfiles/` | MDM server or admin |
| **Cron** | `/usr/lib/cron/tabs/`, `/etc/crontab` | User (own) / root |
| **Shell rc files** | `~/.zshrc`, `~/.bash_profile`, `/etc/profile` | User / root |

- **Key plist indicators**: `KeepAlive: true` + `RunAtLoad: true` = aggressive persistence
- **BTM diagnostics**: `sudo sfltool dumpbtm`

### 4.4 Code Signing & Notarization

- `codesign --verify --deep --strict --verbose=4 /path/to/binary`
- `spctl --assess --type exec -vvv /path/to/binary` — checks notarization
- **Rust**: `security-framework` + `security-framework-sys` crates → `SecStaticCodeCreateWithPath` → `SecCodeCheckValidity`
- Extract Team ID, bundle ID, entitlements

### 4.5 Process Monitoring Detection

| Signal | Method |
|--------|--------|
| **task_for_pid abuse** | Check entitlements: `com.apple.security.get-task-allow`, `com.apple.system-task-ports` |
| **ESF clients** | `systemextensionsctl list` for `endpoint-security` category |
| **MDM restrictions** | `defaults read /Library/Managed Preferences/com.apple.applicationaccess.plist` |
| **Screen Time** | `screentimed`, `parentalcontrolsd` processes; DB at `/private/var/db/screentime/` |

### 4.6 Removal Procedures

- **LaunchAgents/Daemons**: `launchctl bootout gui/$(id -u)/label` or `system/label` → `launchctl disable` → delete plist
- **App bundles**: `rm -rf /Applications/App.app` + purge `~/Library/{Application Support,Preferences,Caches,Saved Application State}/com.bundle.id*`
- **TCC reset**: `tccutil reset <service> com.bundle.id` (per-app) or `tccutil reset All com.bundle.id`
- **MDM profiles**: `sudo profiles remove -identifier "com.suspicious.payload"` (fails if DEP-enrolled)
- **KEXTs**: `sudo kmutil unload -b com.bundle.kext` → delete → `kmutil clear-staging` → `kmutil rebuild` → reboot
- **BTM cleanup**: `sudo sfltool resetbtm`

---

## 5. Cross-Platform

### 5.1 Remote Access / Screen Sharing Ports

| Protocol | Ports | Common Processes |
|----------|-------|-----------------|
| VNC (RFB) | 5900–5910 | `winvnc`, `x11vnc`, `screensharingd`, `vino` |
| RDP | 3389 | `mstsc`, `xrdp`, `gnome-remote-desktop` |
| TeamViewer | Dynamic (HTTPS 443) | `TeamViewer`, `TeamViewer_Service` |
| AnyDesk | 7070 | `AnyDesk` |
| ScreenConnect | Dynamic (HTTPS) | `ScreenConnect.ClientService` |
| SSH tunnels | 22 (or custom) | `ssh -R`, `autossh` |

### 5.2 Known Software Families Catalog (partial — full list in rules/)

#### Stalkerware (`removal_policy: safe_auto`)
mSpy, FlexiSPY, Spyrix, Refog, Actual Keylogger, KidLogger, pcTattletale, Cocospy, Hoverwatch

#### Corporate Monitoring (`removal_policy: manual_review` or `do_not_remove`)
Teramind, ActivTrak, Hubstaff, Veriato/SpectorSoft, InterGuard, Kickidler, Time Doctor, DeskTime

#### Remote Access (`removal_policy: manual_review`)
TeamViewer, AnyDesk, RustDesk, VNC variants, ScreenConnect, NetSupport Manager, Splashtop

#### EDR / MDM (`removal_policy: do_not_remove`)
CrowdStrike Falcon, SentinelOne, Microsoft Defender/Intune, Carbon Black, Jamf, Mosyle, Kandji

#### Legitimate (allowlist with explanation)
OBS, Zoom, Teams, Discord, Steam overlay, NVIDIA ShadowPlay, AutoHotkey, password managers (1Password, Bitwarden, KeePass)

---

## 6. Rule Format Design

### Rationale
YARA excels at raw byte matching but cannot query registry, WMI, network sockets, or TCC. Sigma is log-based. Our rules must be **multi-modal**: correlating persistence, processes, network, and optionally file content.

### Proposed YAML Schema (`sentinel-rule.v1.yaml`)
```yaml
id: STK-WIN-0042
name: "Spyrix Keylogger & Monitor"
version: 1
severity: high           # critical | high | medium | low | info
category: stalkerware    # stalkerware | corporate_monitor | remote_access | edr_mdm | legitimate | parental_control | process_watcher
confidence: high         # high | medium | low
removal_policy: safe_auto  # safe_auto | manual_review | do_not_remove
platforms: [windows]     # windows | linux | macos

vendor: "Spyrix Software"
description: "Commercial keylogger and screen capture tool marketed for covert monitoring."
is_legitimate_use_likely: false
safety_warning: "Removing may alert the person who installed it."

detection:
  registry_keys:
    - { root: HKLM, path: 'SOFTWARE\Spyrix', match: key_exists }
    - { root: HKCU, path: 'Software\Microsoft\Windows\CurrentVersion\Run', value_name: 'Spyrix*', match: value_exists }
  processes:
    - { name: 'spx.exe' }
    - { name: 'spm.exe' }
  services:
    - { name: 'spxsvc' }
  scheduled_tasks:
    - { pattern: '^SpyrixMonitor.*' }
  paths:
    - 'C:\Program Files (x86)\Spyrix Personal Monitor\'
    - 'C:\ProgramData\Spyrix\'
  network:
    - { domain: 'api.spyrix.com' }

condition:
  any_of:
    - all_of: [registry_keys.0, processes.0]
    - services.0
    - paths.0

removal:
  uninstall_key: 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Spyrix*'
  services_to_stop: ['spxsvc']
  processes_to_kill: ['spx.exe', 'spm.exe', 'unins000.exe']
  paths_to_remove:
    - 'C:\Program Files (x86)\Spyrix Personal Monitor\'
    - 'C:\ProgramData\Spyrix\'
  registry_to_clean:
    - { root: HKLM, path: 'SOFTWARE\Spyrix' }
    - { root: HKCU, path: 'Software\Microsoft\Windows\CurrentVersion\Run', value: 'Spyrix*' }
  manual_steps:
    windows: |
      1. Open Settings → Apps → Installed Apps
      2. Search for "Spyrix" and click Uninstall
      3. If not listed: Open Task Manager → End "spx.exe" / "spm.exe"
      4. Delete C:\Program Files (x86)\Spyrix Personal Monitor\
      5. Run regedit, delete HKLM\SOFTWARE\Spyrix
      6. Check Task Scheduler for remaining Spyrix tasks

references:
  - 'https://stopstalkerware.org/'
  - 'MITRE ATT&CK T1056.001 (Input Capture: Keylogging)'
```

---

## 7. Removal Architecture Research

### 7.1 Removal Policy Classification

| Policy | Criteria | UI Behavior |
|--------|----------|-------------|
| `safe_auto` | Known malicious/stalkerware with no dual-use ambiguity; clear uninstall path | Auto-quarantine/remove available with confirmation |
| `manual_review` | Dual-use software (VNC, TeamViewer, time trackers, parental controls) | User must confirm each item individually |
| `do_not_remove` | Corporate EDR/MDM, enterprise-managed agents | Explain only; no remove/quarantine buttons; link to IT department guidance |

### 7.2 Quarantine Design

1. **Stop persistence** (disable, don't delete): registry Run value → rename to `_sentinel_disabled_<original>`; service → `sc config start= disabled`; systemd → `mask`; launchctl → `disable`
2. **Move executables** to `~/.sentinel/quarantine/<id>/` with restricted permissions (`0700` / deny ACL)
3. **Save manifest** (`quarantine-manifest.json`): original locations, backup of modified registry/configs, timestamps
4. **Restore**: `sentinel restore <id>` reverses all changes using the manifest

### 7.3 OS-Specific Removal Safeguards

| OS | Critical Safeguard |
|----|-------------------|
| **Windows** | Clean `UpperFilters` registry BEFORE deleting keyboard filter `.sys` files; use `UninstallString` from registry when available; create System Restore point via `SRSetRestorePointW` |
| **Linux** | Clear `/etc/ld.so.preload` BEFORE deleting preloaded `.so`; check `chattr +i` immutable flag; use package manager (`apt purge`) when binary is package-owned |
| **macOS** | `launchctl bootout` before deleting plist; `tccutil reset` to revoke lingering permissions; `sudo sfltool resetbtm` for ghost login items |

### 7.4 Watchdog / Anti-Kill Detection (Critical for Removal)

Some spyware deploys a "watchdog" process that monitors and restarts the main surveillance component:
- **Windows**: Kernel `ObRegisterCallbacks` stripping `PROCESS_TERMINATE`; WMI `Win32_ProcessStopTrace` subscriptions; secondary service with `KeepAlive` restart
- **Linux**: systemd `Restart=always` + `RestartSec=5`; secondary cron job polling for process
- **macOS**: `KeepAlive: true` in plist; secondary LaunchDaemon monitoring primary

**Removal strategy**: Always identify and neutralize watchdog FIRST, then main component.

---

## 8. Legal & Ethical Analysis

### 8.1 License Choice: Apache-2.0 (Recommended)

| Factor | Apache-2.0 | MIT | GPL-3.0 |
|--------|-----------|-----|---------|
| Patent grant | ✅ Explicit (§3) | ❌ None | ✅ Implicit |
| Corporate adoption | ✅ Welcomed | ✅ Welcomed | ❌ Copyleft barrier |
| Signature/IoC data | Use CC-BY-4.0 separately | Use CC-BY-4.0 | Overkill for data |
| Contribution friction | Low | Low | Medium |

**Decision**: Apache-2.0 for code, CC-BY-4.0 for rule/signature database.

### 8.2 Auto-Removal of Corporate Software — Legal Risks

- **CFAA (18 U.S.C. § 1030)**: Disabling corporate MDM/EDR on employer equipment can = "intentionally causing damage without authorization"
- **Employment contracts**: Violates Acceptable Use Policies → termination risk
- **Sentinel mitigation**: `do_not_remove` category with **no quarantine/remove functionality** for detected enterprise tools

### 8.3 Coalition Against Stalkerware — Key Mandates

1. **Never auto-remove without user consent** — removal may alert abuser (lost C2 connection, watchdog alert)
2. **Provide safety advice before action** — hotlines, safety planning
3. **`--personal-safety-mode`**: Disable auto-removal entirely; show report + help resources only

### 8.4 Privacy & GDPR

- Zero telemetry by default; no cloud uploads
- Optional hash lookups (SHA-256 only) behind `--online-lookups` flag
- EU workplace monitoring: continuous covert keystroke logging is virtually always unlawful (EDPB Opinion 2/2017, *Bărbulescu v. Romania* ECtHR 2017)

---

## 9. Rust Ecosystem Crate Evaluation

| Purpose | Primary Crate | Notes |
|---------|--------------|-------|
| Windows Registry | `winreg` (0.56+) | Idiomatic; `RegKey::predef()`, `open_subkey_with_flags()` |
| PE Parsing | `pelite` (0.10+) | Zero-alloc, malformed-PE resilient; import/export tables |
| Process Enumeration | `sysinfo` (0.31+) | Cross-platform; `System::processes()`, PIDs, exe paths, cmdlines |
| Network Connections | `netstat2` (0.9+) | Wraps `GetExtendedTcpTable`; socket→PID mapping |
| Win32 Code Signing | `windows` crate | `WinVerifyTrust` + Catalog fallback via `CryptCATAdmin*` |
| macOS Code Signing | `security-framework` (3.7+) | `SecStaticCodeCreateWithPath`, `SecCodeCheckValidity` |
| HTML Templating | `askama` (0.12+) | Compile-time Jinja; zero runtime overhead; type-safe |
| CLI | `clap` (4.5+) | Derive API; subcommands; shell completions |
| Serialization | `serde` + `serde_yaml` + `serde_json` | Universal; rule parsing + JSON report output |
| Localization | `rust-i18n` or custom `HashMap<&str, &str>` | Simple key-value; embed en/ru at compile time |
| Hashing | `sha2` | SHA-256 for file hashing |
| Filesystem | `walkdir` | Recursive directory traversal |
| Cross-platform paths | `dirs` | `home_dir()`, `config_dir()`, etc. |

---

## 10. Applicability Matrix

| Signal | Windows | Linux | macOS | Reliability | Admin Needed? | FP Risk | Removal Available? |
|--------|---------|-------|-------|-------------|--------------|---------|-------------------|
| Registry Run keys | ✅ | — | — | High | Read: No | Low | Yes: delete value |
| Startup folder items | ✅ | — | — | High | No | Low | Yes: delete file |
| Scheduled Tasks | ✅ | — | — | High | Query: No | Low | Yes: schtasks /delete |
| Services | ✅ | — | — | High | Read: No | Low | Yes: sc delete |
| WMI subscriptions | ✅ | — | — | High | No | Low | Yes: WQL delete |
| systemd units | — | ✅ | — | High | Read: No | Low | Yes: mask + delete |
| Cron jobs | — | ✅ | ✅ | High | Own: No | Low | Yes: crontab -r |
| XDG autostart | — | ✅ | — | High | No | Low | Yes: delete .desktop |
| LaunchAgents/Daemons | — | — | ✅ | High | User agents: No | Low | Yes: bootout + delete |
| Login Items (BTM) | — | — | ✅ | High | No | Low | Yes: sfltool resetbtm |
| PE import analysis | ✅ | — | — | Medium | No | Medium | N/A (heuristic) |
| /dev/input fd scan | — | ✅ | — | High | Own: No | Low | Yes: kill process |
| X11 client library scan | — | ✅ | — | Medium | No | Medium | Yes: kill process |
| PipeWire stream detection | — | ✅ | — | High | No | Low | Yes: kill process |
| CGGetEventTapList | — | — | ✅ | High | Accessibility | Low | Yes: kill process |
| TCC.db query | — | — | ✅ | High | FDA required | Low | Yes: tccutil reset |
| ConsentStore registry | ✅ | — | — | High | No | Low | N/A (forensic) |
| Keyboard filter drivers | ✅ | — | — | High | Read: No | Low | Yes: clean UpperFilters |
| Authenticode/codesign | ✅ | — | ✅ | High | No | Low | N/A (trust signal) |
| Package ownership | — | ✅ | — | High | No | Low | N/A (trust signal) |
| Network connections→PID | ✅ | ✅ | ✅ | High | No | Medium | Yes: kill process |
| ptrace detection | — | ✅ | — | High | No | Low | Yes: kill tracer |
| eBPF fd detection | — | ✅ | — | Medium | Own only | Low | Needs root |
| ESF/SysExt enumeration | — | — | ✅ | High | No | Low | Needs admin |
| MDM profiles | — | — | ✅ | High | No | Low | May require DEP unenroll |
| Proxy/cert/hosts check | ✅ | ✅ | ✅ | High | No | Low | Yes: reset/delete |
| Known process/path match | ✅ | ✅ | ✅ | High | No | Low | Yes: per-family |
| Known domain match | ✅ | ✅ | ✅ | High | No | Low | N/A (indicator) |

---

## 11. Sources

### Windows
- [Microsoft Learn: WinVerifyTrust](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust)
- [Microsoft Learn: SetWindowsHookExW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexw)
- [Microsoft Learn: Desktop Duplication API](https://learn.microsoft.com/en-us/windows/win32/direct3ddxgi/desktop-dup-api)
- [Microsoft Learn: Device Setup Classes](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors)
- [MITRE ATT&CK T1546.003 (WMI Persistence)](https://attack.mitre.org/techniques/T1546/003/)
- [MITRE ATT&CK T1546.012 (IFEO)](https://attack.mitre.org/techniques/T1546/012/)

### Linux
- [Linux Kernel /proc Filesystem](https://www.kernel.org/doc/Documentation/filesystems/proc.txt)
- [PipeWire pw-dump Documentation](https://docs.pipewire.org/page_man_pw-dump_1.html)
- [XDG Desktop Portal ScreenCast](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.ScreenCast.html)
- [X.Org XRECORD Protocol](https://www.x.org/releases/X11R7.7/doc/recordproto/record.html)
- [ptrace(2) man page](https://man7.org/linux/man-pages/man2/ptrace.2.html)

### macOS
- [Apple: CoreGraphics Event Taps](https://developer.apple.com/documentation/coregraphics)
- [Apple: SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice)
- [Apple: Endpoint Security](https://developer.apple.com/documentation/endpointsecurity)
- [Apple: Security Framework (Code Signing)](https://developer.apple.com/documentation/security)
- [Objective-See: The Art of Mac Malware](https://taomm.org/)
- [HackTricks macOS Security](https://hacktricks.wiki)

### Legal / Ethical
- [Coalition Against Stalkerware](https://stopstalkerware.org/)
- [EDPB Opinion 2/2017 on workplace monitoring](https://edpb.europa.eu/)
- [ECtHR Bărbulescu v. Romania (2017)](https://hudoc.echr.coe.int/)
- [FSF GPL Compatibility Guide](https://www.fsf.org/licensing)
- [Van Buren v. United States (2021) — CFAA](https://www.supremecourt.gov/opinions/20pdf/19-783_k53l.pdf)
