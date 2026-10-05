# Sentinel — Defensive Spyware, Stalkerware & Surveillance Detector

**English** | [📖 Читать на русском (Russian Version)](README_RU.md)

[![CI](https://github.com/jamixm4-crypto/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/jamixm4-crypto/sentinel/actions/workflows/ci.yml)
[![GitHub Release](https://img.shields.io/github/v/release/jamixm4-crypto/sentinel?color=green)](https://github.com/jamixm4-crypto/sentinel/releases)
[![Crates.io](https://img.shields.io/crates/v/sentinel-cli.svg?color=blue)](https://crates.io/crates/sentinel-cli)
[![Code License](https://img.shields.io/badge/Code-Apache--2.0-blue.svg)](LICENSE)
[![Rules License](https://img.shields.io/badge/Rules-CC--BY--4.0-orange.svg)](LICENSE-CC-BY)
[![Zero Telemetry](https://img.shields.io/badge/Telemetry-Zero%20(100%25%20Offline)-brightgreen.svg)](#security-principles)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](#supported-platforms)
[![Rust](https://img.shields.io/badge/Rust-1.80%2B%20stable-red.svg)](https://www.rust-lang.org)

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
# 1. Standard scan (interactive spinner + terminal summary + offline HTML report):
sentinel scan

# 2. Quiet mode (minimal terminal output, suppresses spinners and banners):
sentinel scan -q

# 3. Verbose mode (displays collector execution time, evidence count, and privilege warnings):
sentinel scan -v

# 4. Personal Safety Mode (in-memory execution; zero report files saved to disk):
sentinel scan --personal-safety-mode

# 5. Forensic Offline Mode (audit an unmounted disk image or directory):
sentinel scan --scan-path /mnt/target_image

# 6. SIEM & Pipeline Export (streams findings as NDJSON or Elastic Common Schema ECS):
sentinel scan --format ecs
sentinel scan --format ndjson

# 7. Threat intelligence walkthrough & incident response triage guidance:
sentinel explain STK-WIN-0042
sentinel explain stalkerware_c2_network_beacon

# 8. Offline rules & C2 domain feed updates:
sentinel rules update --from /path/to/custom_rules/
sentinel rules update --from /path/to/c2_domains.txt
```

---

## Terminal Output Preview

### Live Console Summary Example

```text
  🛡️ Sentinel Defensive Audit Summary
  Verdict: SURVEILLANCE LIKELY [1 High-Risk Stalkerware Finding]
  Platform: Windows 11 Pro (x86_64) | Duration: 1.48s | Inspected Processes: 242

  [CRITICAL] Stalkerware C2 Communication (api.flexispy.com)
  • Category: Network Activity & MITM | Confidence: 100% (High)
  • Description: Active socket matched known commercial stalkerware C2 endpoint.
  • Action Policy: SafeAuto (Firewall/hosts block available)
  • Remediation: sentinel quarantine C2-api-flexispy-com --execute

  [HIGH] Spyrix Personal Monitor & Keylogger
  • Category: Keyboard Capture | Confidence: 95% (High)
  • Description: Identified active process 'spx.exe' and persistent service 'spxsvc'.
  • Action Policy: SafeAuto (Automated vault quarantine available)
  • Dry-Run: sentinel quarantine STK-WIN-0042

  HTML report generated: C:\Users\user\sentinel-report-20261005_120000.html
```

---

## Architecture & Modular Crates

For complete architecture diagrams and sequence charts, see **[ARCHITECTURE.md](ARCHITECTURE.md)**.

```
                                ┌────────────────────────────────┐
                                │       sentinel-cli (CLI)       │
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
       │   sentinel-report │           │ sentinel-removal  │
       │ HTML/JSON/NDJSON/ │           │ Reversible Vault  │
       │ Elastic ECS v8.11 │           │ (Dry-Run / Undo)  │
       └───────────────────┘           └───────────────────┘
```

Sentinel is engineered as a collection of modular Rust crates publishable to crates.io:

| Crate | Purpose | Key Responsibilities |
|---|---|---|
| [`sentinel-core`](crates/core/) | Core Domain Types | Platform detection, evidence representations, finding models, verdicts. |
| [`sentinel-collectors`](crates/collectors/) | Evidence Gathering | Cross-platform process enumeration, registry ASEPs, consent stores, socket auditing. |
| [`sentinel-rules`](crates/rules/) | Declarative Rules Engine | 75+ embedded YAML signatures, 280+ C2 domains, regex matcher. |
| [`sentinel-scoring`](crates/scoring/) | Multi-Factor Correlation | Process masquerading detection, multi-modal corroboration, user allowlisting. |
| [`sentinel-removal`](crates/removal/) | Remediation & Vault | Encrypted quarantine, SHA-256 state tracking, dry-run safety, clean restore. |
| [`sentinel-report`](crates/report/) | Multi-Format Exporters | Self-contained HTML report, raw JSON, NDJSON, and Elastic Common Schema (ECS). |
| [`sentinel-cli`](crates/cli/) | User Application | Command-line interface with interactive progress spinner, safety checks, explain. |

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

## CI & Security Assurance

All pull requests and release tags undergo rigorous automated quality and supply-chain audits across Windows, Linux, and macOS GitHub Actions runners:

- **Formatting Standards**: `cargo fmt --check` ensures consistent code layout.
- **Strict Linting**: `cargo clippy --all-targets --all-features -- -D warnings` forbids all compiler and style warnings.
- **Vulnerability Auditing**: `cargo audit` verifies zero known CVEs or supply-chain advisories across all Cargo dependencies.
- **License & Dependency Health**: `cargo deny check` prevents licensing conflicts and unapproved dependencies.
- **100% Deterministic Offline Testing**: Automated suite verifies zero outbound sockets and validates rule precision against synthetic telemetry.

---

## Contributing & Community

Contributions of new detection rules, threat feeds, or bug fixes are welcome!

- [Pull Request Template](.github/PULL_REQUEST_TEMPLATE.md)
- [Bug Report Template](.github/ISSUE_TEMPLATE/bug_report.yml)
- [Contributing Guide](CONTRIBUTING.md)
- [Threat Intelligence Feed Guidelines](docs/threat-intel-curation.md)

---

## Documentation Links

- [Root Architecture Specification](ARCHITECTURE.md)
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
