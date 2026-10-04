# Sentinel System Architecture

## Overview

Sentinel is designed as a modular, high-performance Rust workspace. Each subsystem is strictly decoupled into independent crates with clear responsibilities:

```
                           ┌─────────────────────────┐
                           │      sentinel-cli       │
                           │  (Command-line UX/Clap) │
                           └────────────┬────────────┘
                                        │
           ┌────────────────────────────┼────────────────────────────┐
           ▼                            ▼                            ▼
┌──────────────────────┐     ┌──────────────────────┐     ┌──────────────────────┐
│  sentinel-collectors │     │    sentinel-rules    │     │   sentinel-scoring   │
│  (OS State Evidence) │     │ (YAML Database/Match)│     │  (Correlation Engine)│
└──────────┬───────────┘     └──────────┬───────────┘     └──────────┬───────────┘
           │                            │                            │
           └────────────────────────────┼────────────────────────────┘
                                        ▼
                           ┌─────────────────────────┐
                           │      sentinel-core      │
                           │ (Finding, Evidence, DTO)│
                           └────────────┬────────────┘
                                        │
                         ┌──────────────┴──────────────┐
                         ▼                             ▼
              ┌──────────────────────┐      ┌──────────────────────┐
              │   sentinel-removal   │      │   sentinel-report    │
              │ (Quarantine/Rollback)│      │ (HTML / JSON Output) │
              └──────────────────────┘      └──────────────────────┘
```

---

## Crate Responsibilities

### 1. `sentinel-core`
- Defines foundational domain types: `Finding`, `Evidence`, `RemovalPolicy`, `Severity`, `Confidence`, and `ScanResult`.
- Houses the compile-time localization system (`i18n`) supporting English and Russian.
- Detects host operating system capabilities, architecture, and current privilege level (`StandardUser` vs `ElevatedAdmin`).

### 2. `sentinel-collectors`
- Implements the unified `Collector` trait.
- Organizes OS-specific probes via compile-time feature gates:
  - `windows`: Run keys, scheduled tasks, services, WMI subscriptions, CapabilityAccessManager ConsentStore, UpperFilters drivers, installed software, proxy/certificates.
  - `linux`: `/dev/input` fds, X11 libraries, PipeWire ScreenCast, systemd units, XDG autostart, LD_PRELOAD, ptrace TracerPid.
  - `macos`: LaunchAgents/Daemons, Login items, MDM configuration profiles, event taps.
  - `common`: Cross-platform process enumeration and network socket listeners.

### 3. `sentinel-rules`
- Provides the declarative schema for multi-modal detection rules.
- Includes embedded rules compiled directly into the binary for 100% offline usage.
- Implements `RuleMatcher` to evaluate gathered evidence against active rules.

### 4. `sentinel-scoring`
- Normalizes and correlates multiple evidence items into unified findings.
- Applies confidence weighting algorithms.
- Evaluates allowlists to suppress false positives on legitimate operating system binaries.

### 5. `sentinel-removal`
- Safely manages remediation workflows.
- `QuarantineManager`: Neutralizes processes/services and moves binaries into `~/.sentinel/quarantine/` with a verifiable `quarantine-manifest.json`.
- `RestoreManager`: Atomically reverses quarantine actions back to the original operating system locations.
- `RemovalManager`: Executes safe, permanent uninstallation steps.
- `verify`: Conducts immediate post-removal verification scans to ensure watchdogs have not respawned.

### 6. `sentinel-report`
- Exports detailed machine-readable JSON reports.
- Generates beautiful, self-contained HTML reports with inline styling, dark/light theme toggles, search/filtering, and domestic safety guidance.
- Displays colored terminal summaries.

### 7. `sentinel-cli`
- Top-level entry point parsing user commands and options via `clap`.
- Orchestrates scan execution, quarantine commands, restore commands, and rule validation.
