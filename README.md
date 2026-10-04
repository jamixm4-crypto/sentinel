# 🛡️ Sentinel — Open-Source Spyware & Surveillance Software Detector

<p align="center">
  <img src="https://raw.githubusercontent.com/sentinel-sec/sentinel/main/assets/sentinel-banner.png" alt="Sentinel Banner" width="700" onerror="this.style.display='none'"/>
</p>

<p align="center">
  <strong>A defensive, read-only-by-default, zero-telemetry scanner detecting keyloggers, stalkerware, screen recorders, corporate monitors, and stealth process watchers across Windows, Linux, and macOS.</strong>
</p>

<p align="center">
  <a href="https://github.com/sentinel-sec/sentinel/actions/workflows/ci.yml"><img src="https://github.com/sentinel-sec/sentinel/actions/workflows/ci.yml/badge.svg" alt="CI"/></a>
  <a href="LICENSE-APACHE"><img src="https://img.shields.io/badge/Code%20License-Apache--2.0-blue.svg" alt="License"/></a>
  <a href="LICENSE-CC-BY"><img src="https://img.shields.io/badge/Rules%20License-CC--BY--4.0-orange.svg" alt="Rules License"/></a>
  <a href="https://stopstalkerware.org"><img src="https://img.shields.io/badge/Coalition%20Against%20Stalkerware-Aligned-green.svg" alt="Coalition"/></a>
</p>

---

## ⚡ Key Highlights

- **🛡️ 100% Defensive & Read-Only by Default**: No system hooks, no driver injection, no kernel modifications. Operates safely without root/admin, with optional elevated mode for deep kernel filter inspection.
- **🔒 Zero Telemetry & Offline First**: Zero network connections during scan. Nothing leaves your machine. All detection rules and report templates are self-contained.
- **📊 Plain-Language, Non-Alarmist Reports**: Generates an interactive, accessible HTML report explaining *what* was found, *why* it was flagged, *how likely* it is legitimate, and *how to remediate* safely.
- **🔄 Safe, Reversible Quarantine**:
  ```bash
  sentinel quarantine <id>
  sentinel restore <id>
  ```
  Stops processes, masks services, and isolates files into `~/.sentinel/quarantine/` with a verifiable rollback manifest.
- **⚙️ Strict Categorization Before Removal**:
  - `SafeAuto`: Known commercial keyloggers and stalkerware with established cleanup procedures.
  - `ManualReview`: Dual-use software (VNC, AnyDesk, TeamViewer, time trackers, parental controls) requiring individual confirmation.
  - `DoNotRemove`: Enterprise-managed EDR and MDM agents (CrowdStrike, SentinelOne, Intune, Jamf). **Automated removal is strictly blocked** to prevent breaking employer-managed devices or violating acceptable use policies.
- **🆘 Personal Safety Mode**:
  ```bash
  sentinel scan --personal-safety-mode
  ```
  In domestic surveillance situations, abrupt removal of stalkerware can immediately alert the monitor. Personal Safety Mode disables automated removal and provides guidance aligned with [Coalition Against Stalkerware](https://stopstalkerware.org) safety recommendations.

---

## 🚀 Quick Start

### Installation

#### Windows (PowerShell)
```powershell
irm https://raw.githubusercontent.com/sentinel-sec/sentinel/main/install.ps1 | iex
```

#### Linux & macOS (Bash)
```bash
curl -fsSL https://raw.githubusercontent.com/sentinel-sec/sentinel/main/install.sh | bash
```

#### Cargo (from source)
```bash
cargo install --path crates/cli
```

---

## 💻 Usage

### 1. Perform a System Scan
```bash
# Standard user scan (fast, clean, read-only)
sentinel scan

# Scan in Russian language
sentinel scan --lang ru

# Output to custom directory without opening browser
sentinel scan --out ./reports --no-open
```

### 2. Inspect a Finding
```bash
sentinel explain STK-WIN-0042-1
```

### 3. Reversibly Quarantine a Suspicious Item
```bash
sentinel quarantine STK-WIN-0042-1
```

### 4. Restore an Item from Quarantine
```bash
sentinel restore STK-WIN-0042-1
```

### 5. Permanently Remove Confirmed Stalkerware
```bash
# Remove a single item (with interactive confirmation)
sentinel remove STK-WIN-0042-1

# Remove all SafeAuto items after reviewing prompt
sentinel remove --all-safe
```

---

## 🏗️ Architecture & Crates

```
sentinel/
├── crates/
│   ├── core/         # Domain model: Finding, Evidence, RemovalPolicy, i18n
│   ├── collectors/   # OS-specific collectors (Windows, Linux, macOS)
│   ├── rules/        # Multi-modal YAML rule engine & embedded rules
│   ├── scoring/      # Confidence scoring engine & allowlisting
│   ├── removal/      # Quarantine, manifest, rollback & removal
│   ├── report/       # Offline HTML, JSON, and Terminal exporters
│   └── cli/          # Command-line interface (`sentinel`)
└── rules/            # Declarative YAML detection rules database
```

---

## 📋 What Sentinel Detects

| Category | Typical Signatures | Policy |
| :--- | :--- | :--- |
| **Keyboard Capture** | Spyrix, Refog, Actual Keylogger, mSpy, FlexiSPY, low-level hooks | `SafeAuto` |
| **Screen Recording** | pcTattletale, Kickidler, unapproved desktop streamers | `SafeAuto` / `ManualReview` |
| **Remote Access** | TeamViewer, AnyDesk, RustDesk, VNC, ScreenConnect, NetSupport | `ManualReview` |
| **Corporate Monitoring** | Teramind, ActivTrak, Hubstaff, Veriato, InterGuard, Time Doctor | `DoNotRemove` / `ManualReview` |
| **Organization Managed** | CrowdStrike Falcon, SentinelOne, Intune, Jamf, Carbon Black | `DoNotRemove` |
| **Process Watchers** | Anti-kill watchdog processes, ptrace snooping, eBPF sniffers | `SafeAuto` / `ManualReview` |
| **Legitimate Tools** | OBS, Zoom, Teams, Discord, Steam Overlay, AutoHotkey, 1Password | `Info` (Suppressed/Explained) |

---

## 🔒 Security & Privacy Commitments

1. **Zero Telemetry**: No pings, no analytics, no third-party API calls.
2. **Minimal Footprint**: Operates entirely in memory and exits cleanly. Leaves no background services or persistent registry keys.
3. **No Anti-Forensics**: Sentinel never modifies event logs or tampers with system auditing tools.
4. **Safety Guidance**: Direct access to domestic violence hotlines and safety planning resources.

---

## 📜 Licenses

- **Engine and Code**: [Apache License 2.0](LICENSE-APACHE)
- **Rule Signatures & Indicators**: [Creative Commons Attribution 4.0 (CC-BY-4.0)](LICENSE-CC-BY)
