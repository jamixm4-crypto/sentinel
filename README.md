# Sentinel — Defensive Spyware, Stalkerware & Surveillance Detector

**English** | [📖 Читать на русском (Russian Version)](README_RU.md)

[![CI](https://github.com/jamixm4-crypto/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/jamixm4-crypto/sentinel/actions/workflows/ci.yml)
[![GitHub Release](https://img.shields.io/github/v/release/jamixm4-crypto/sentinel?color=green)](https://github.com/jamixm4-crypto/sentinel/releases)
[![Code License](https://img.shields.io/badge/Code-Apache--2.0-blue.svg)](LICENSE)
[![Rules License](https://img.shields.io/badge/Rules-CC--BY--4.0-orange.svg)](LICENSE-CC-BY)
[![Zero Telemetry](https://img.shields.io/badge/Telemetry-Zero%20(100%25%20Offline)-brightgreen.svg)](#security-principles)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](#supported-platforms)
[![Rust](https://img.shields.io/badge/Rust-1.78%2B%20stable-red.svg)](https://www.rust-lang.org)

**Sentinel** is an open-source, offline-first defensive security scanner designed to detect covert surveillance software: keyloggers, commercial stalkerware, remote access trojans (RATs), employee monitoring agents, corporate EDR/MDM sensors, and process watchdogs.

Operating strictly **read-only by default**, Sentinel requires **zero telemetry**, performs **no remote network calls**, and leaves minimal forensic trace on audited systems.

---

## Verified Installation

As a security application designed for users facing active threats, downloading verified binaries with cryptographic checksum validation is strongly recommended over direct shell pipes.

### 1. Download Verified Release (Recommended)

1. Download the archive for your operating system from [GitHub Releases](https://github.com/jamixm4-crypto/sentinel/releases/latest).
2. Verify the SHA-256 checksum against the official `SHA256SUMS` file:

```powershell
# Windows (PowerShell)
$hash = (Get-FileHash -Path sentinel-windows-x86_64.zip -Algorithm SHA256).Hash.ToLower()
$expected = (Get-Content SHA256SUMS | Select-String "sentinel-windows-x86_64.zip").Line.Split(" ")[0].ToLower()
if ($hash -eq $expected) { Write-Host "✔ Checksum Verified!" -ForegroundColor Green }
```

```bash
# Linux / macOS
sha256sum -c SHA256SUMS
```

3. Extract the archive and execute `sentinel scan`.

### 2. Automated Installer Scripts (Convenience Option)

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/jamixm4-crypto/sentinel/main/install.ps1 | iex
```

**Linux & macOS (Bash):**
```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/sentinel/main/install.sh | bash
```

---

## Quick Usage

```bash
# 1. Standard scan (generates terminal summary + standalone offline HTML report):
sentinel scan

# 2. Personal Safety Mode (in-memory terminal output only; no files saved to local disk):
sentinel scan --personal-safety-mode

# 3. Forensic Mode (inspect an unmounted disk image or directory without live execution):
sentinel scan --scan-path /mnt/target_image

# 4. SIEM / Pipeline Mode (streams findings as single-line NDJSON to stdout):
sentinel scan --format ndjson

# 5. Interface language selection (Russian):
sentinel scan --lang ru
```

---

## Architecture & Detection Engines

```
                               ┌────────────────────────────────┐
                               │       Sentinel Scanner         │
                               └───────────────┬────────────────┘
                                               │
             ┌───────────────────┬─────────────┴───────┬───────────────────┐
             ▼                   ▼                     ▼                   ▼
     ┌──────────────┐    ┌──────────────┐      ┌──────────────┐    ┌──────────────┐
     │  Processes & │    │ Persistence  │      │  Network C2  │    │ Masquerading │
     │  Input Sinks │    │ Registry/ASEP│      │  Inspection  │    │ (T1036.005)  │
     └───────┬──────┘    └───────┬──────┘      └───────┬──────┘    └───────┬──────┘
             │                   │                     │                   │
             └───────────────────┼─────────────────────┴───────────────────┘
                                 ▼
                     ┌───────────────────────┐
                     │ Multi-Modal Correlator│
                     │  (75+ Rules, 280+ C2) │
                     └───────────┬───────────┘
                                 │
                 ┌───────────────┴───────────────┐
                 ▼                               ▼
       ┌───────────────────┐           ┌───────────────────┐
       │   HTML/JSON/NDJSON│           │ Reversible Vault  │
       │    Audit Report   │           │ (Dry-Run / Undo)  │
       └───────────────────┘           └───────────────────┘
```

- **Process Masquerading Detection (MITRE ATT&CK T1036.005)**:
  Flags processes mimicking system components (`svchost.exe`, `csrss.exe`, `lsass.exe`, `services.exe`) running out of user profiles (`%APPDATA%`, `%TEMP%`, `C:\ProgramData`).
- **75+ Embedded YAML Signatures & 280+ Stalkerware C2 Domains**:
  Inspects active sockets and DNS client cache records (`ipconfig /displaydns`) against validated threat intelligence feeds (Coalition Against Stalkerware, AssoEchap, TinyCheck).
- **Multi-Modal Rule Correlation**:
  Requires corroborating evidence (`condition.min_matches: 2`) combining process execution, registry hooks, and network activity to eliminate single-point false alarms.
- **Deep Benign Allowlist**:
  Suppresses false positives for legitimate streaming software (OBS Studio), gaming overlays (Discord, Steam), accessibility tools (NVDA, Narrator), and developer IDEs.

---

## Interactive HTML Report Preview

When running `sentinel scan`, Sentinel generates a zero-dependency, single-file HTML report:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ 🛡️  SENTINEL AUDIT REPORT                     [Verdict: Review Recommended] │
│ Target: Windows 11 x86_64 | 237 Inspected Processes | Scan Duration: 1.67s   │
├──────────────────────────────────────────────────────────────────────────────┤
│ ┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────────┐ │
│ │ 0 Critical Detected  │  │ 1 Medium (Dual-Use)  │  │ 236 Verified Clean   │ │
│ └──────────────────────┘  └──────────────────────┘  └──────────────────────┘ │
│                                                                              │
│ ▼ [MEDIUM] VNC Server (UltraVNC / TightVNC / RealVNC)   Confidence: 100%     │
│   Category: Remote Access & Control | Removal Policy: ManualReviewRequired   │
│   • What is this: Virtual Network Computing server providing remote desktop  │
│   • Why flagged: Process 'vncserver.exe' listening on TCP port 5900          │
│   • Legitimate use: Very common in enterprise support and homelabs.          │
│   • Remediation: Dry-run available via 'sentinel quarantine <id>'            │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Personal Safety Mode (`--personal-safety-mode`)

In intimate partner violence or domestic stalking scenarios, modifying or removing spyware can immediately alert the perpetrator via remote disconnection notifications, carrying severe risk of retaliatory confrontation:

- **Zero Local Disk Artifacts**: No HTML or JSON reports are created on disk; findings are output exclusively to the terminal in memory.
- **Browser Suppression**: The default web browser is not launched, leaving no browser history, cache, or tabs.
- **Modifications Locked**: All `remove` and `quarantine` commands are **strictly blocked**.
- **Support Resources**: The scan displays international hotlines and safety resources:
  - [Coalition Against Stalkerware](https://stopstalkerware.org)
  - Global Support Directory: [Lila.help](https://lila.help)
  - US National Domestic Violence Hotline: `1-800-799-SAFE` (SMS: text "START" to 88788)

---

## Safe Remediation & Dry-Run by Default

All modification operations execute in **dry-run mode by default**:

```bash
# 1. Preview quarantine actions without modifying files:
sentinel quarantine <finding-id>

# 2. Execute quarantine into encrypted vault:
sentinel quarantine <finding-id> --execute

# 3. Restore quarantined item to original state:
sentinel restore <quarantine-id>

# 4. Preview automated removal for all SafeAuto findings:
sentinel remove --all-safe

# 5. Execute permanent removal:
sentinel remove --all-safe --execute
```

---

## Custom User Allowlist

Manage your local allowlist to suppress expected administrative tools:

```bash
sentinel allow list
sentinel allow add "my_admin_tool.exe"
sentinel allow remove "my_admin_tool.exe"
```

---

## Technical Limitations & Boundaries

1. **Mobile Devices (Android & iOS)**:
   The majority of modern consumer stalkerware targets mobile smartphones. Sentinel is a desktop workstation scanner. Direct filesystem analysis of smartphones requires specialized physical tools like **Amnesty International's MVT (Mobile Verification Toolkit)** or **TinyCheck**. Sentinel includes mobile C2 indicators to audit local workstation network traffic for smartphone sync beacons.
2. **Kernel Rootkits (Ring 0)**:
   If an attacker has installed custom kernel drivers modifying dispatch tables, user-mode scans cannot guarantee complete visibility. If a rootkit is suspected, run Sentinel from an offline bootable live medium.
3. **Hardware Keyloggers**:
   Inline physical hardware keyloggers connected to keyboard cables or USB ports cannot be detected via operating system software APIs. Conduct physical hardware inspections.

---

## Documentation Links

- [Threat Model & Security Scope](docs/threat-model.md)
- [Architecture & Correlation Engine](docs/architecture.md)
- [Reproducible Builds & Verification](docs/reproducible-builds.md)
- [Removal Policy & Safety Tiers](docs/removal-policy.md)
- [YAML Rule Specification](docs/rule-format.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security Policy](SECURITY.md)

---

## License

- **Source Code**: [Apache License 2.0](LICENSE)
- **Detection Rules**: [Creative Commons Attribution 4.0 International](LICENSE-CC-BY)
