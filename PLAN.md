# Sentinel — Phase 1: Architecture Plan (PLAN.md)

> **Status**: ⏳ Awaiting approval before Phase 2  
> **Date**: 2026-10-04

---

## 1. Skill Audit

| Skill | Found? | Used? | Reason |
|-------|--------|-------|--------|
| `generative_ui` | ✅ | ✅ Will use for HTML report preview | Tailwind-based self-contained HTML artifact rendering |
| `agy-customizations` | ✅ | ❌ Rejected | Not relevant — about Antigravity config, not security tooling |
| `antigravity-guide` | ✅ | ❌ Rejected | Antigravity product docs, not needed for Sentinel |
| `migrate-workflows` | ✅ | ❌ Rejected | Legacy workflow migration, not applicable |
| `research` subagent | ✅ | ✅ Used extensively | 4 parallel deep-research subagents for Phase 0 |
| Web search | ✅ | ✅ Used extensively | Registry paths, API docs, known spyware families, legal analysis |
| File/code analysis | ✅ | ✅ Will use | Code review, test verification |

> No specialized reverse-engineering, binary analysis, or OS-forensics skills were available in the environment. All detection logic is implemented from scratch based on research findings, public API documentation, and clean-room design principles.

---

## 2. Project Layout

```
sentinel/
├── Cargo.toml                    # Workspace root
├── LICENSE-APACHE                # Apache-2.0 (code)
├── LICENSE-CC-BY                 # CC-BY-4.0 (rules database)
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── RESEARCH.md                   # Phase 0 research (committed)
├── PLAN.md                       # This document
├── crates/
│   ├── core/                     # Data model, i18n, shared types
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── finding.rs        # Finding, Evidence, Category, Severity
│   │       ├── removal.rs        # RemovalPolicy, RemovalStep, QuarantineManifest
│   │       ├── i18n.rs           # Compile-time string tables (en, ru)
│   │       └── platform.rs       # PlatformInfo, PrivilegeLevel, SkippedCheck
│   ├── collectors/               # OS-specific evidence collectors
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs            # Collector trait + registry
│   │       ├── common/           # Cross-platform collectors
│   │       │   ├── mod.rs
│   │       │   ├── process.rs    # Running process enumeration
│   │       │   └── network.rs    # TCP/UDP connections → PID mapping
│   │       ├── windows/          # cfg(target_os = "windows")
│   │       │   ├── mod.rs
│   │       │   ├── persistence.rs  # Run keys, services, tasks, WMI, IFEO, etc.
│   │       │   ├── input.rs        # PE import analysis for keyboard/screen APIs
│   │       │   ├── consent.rs      # CapabilityAccessManager ConsentStore
│   │       │   ├── drivers.rs      # Keyboard filter drivers
│   │       │   ├── signature.rs    # Authenticode + Catalog verification
│   │       │   ├── certificates.rs # Root cert store + proxy + hosts
│   │       │   ├── installed.rs    # Uninstall registry entries
│   │       │   └── watchers.rs     # Process monitoring detection
│   │       ├── linux/            # cfg(target_os = "linux")
│   │       │   ├── mod.rs
│   │       │   ├── persistence.rs  # systemd, cron, XDG, shell rc, LD_PRELOAD, modules
│   │       │   ├── input.rs        # /dev/input fds, X11 libs, PipeWire streams
│   │       │   ├── packages.rs     # dpkg/rpm/pacman ownership verification
│   │       │   ├── watchers.rs     # ptrace, eBPF fds, auditd, /proc polling
│   │       │   └── ebpf.rs         # eBPF program detection
│   │       └── macos/            # cfg(target_os = "macos")
│   │           ├── mod.rs
│   │           ├── persistence.rs  # LaunchAgents/Daemons, Login Items, BTM, KEXTs
│   │           ├── tcc.rs          # TCC.db query (if FDA), API probing (if not)
│   │           ├── event_taps.rs   # CGGetEventTapList
│   │           ├── signature.rs    # codesign / notarization via Security.framework
│   │           ├── profiles.rs     # MDM configuration profiles
│   │           └── watchers.rs     # ESF clients, task_for_pid entitlements
│   ├── rules/                    # YAML rule engine
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── schema.rs         # Rule struct definitions (serde)
│   │       ├── loader.rs         # YAML parsing + validation
│   │       ├── matcher.rs        # Match evidence against rules
│   │       └── updater.rs        # Signed bundle update from GitHub Releases
│   ├── scoring/                  # Confidence scoring + allowlisting
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── engine.rs         # Correlate evidence → findings with scores
│   │       ├── allowlist.rs      # Known legitimate software suppression
│   │       └── explanation.rs    # Human-readable explanations
│   ├── removal/                  # Quarantine / Restore / Remove
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── quarantine.rs     # Move to quarantine + disable persistence
│   │       ├── restore.rs        # Reverse quarantine using manifest
│   │       ├── remove.rs         # Full removal with OS-specific logic
│   │       ├── restore_point.rs  # System Restore (Win) / config snapshot
│   │       ├── verify.rs         # Post-removal verification scan
│   │       └── log.rs            # Local removal-log.json
│   ├── report/                   # Output generation
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── json.rs           # JSON report
│   │       ├── html.rs           # Self-contained HTML report
│   │       ├── terminal.rs       # Terminal summary output
│   │       └── templates/
│   │           └── report.html   # Askama template
│   └── cli/                      # CLI entry point
│       ├── Cargo.toml
│       └── src/
│           └── main.rs           # clap-based CLI
├── rules/                        # YAML rule database
│   ├── schema.json               # JSON Schema for rule validation
│   ├── stalkerware/
│   │   ├── mspy.yml
│   │   ├── flexispy.yml
│   │   ├── spyrix.yml
│   │   └── ...
│   ├── corporate/
│   │   ├── teramind.yml
│   │   ├── activtrak.yml
│   │   └── ...
│   ├── remote_access/
│   │   ├── teamviewer.yml
│   │   ├── anydesk.yml
│   │   └── ...
│   ├── edr_mdm/
│   │   ├── crowdstrike.yml
│   │   ├── sentinelone.yml
│   │   └── ...
│   └── legitimate/
│       ├── obs.yml
│       ├── zoom.yml
│       └── ...
├── tests/
│   ├── golden/                   # Golden file tests for scoring + reports
│   ├── mock_collectors/          # Mocked collector outputs
│   └── removal_sandbox/          # Isolated FS/registry simulation for removal tests
├── docs/
│   ├── architecture.md
│   ├── rule-format.md
│   ├── adding-collectors.md
│   ├── threat-model.md
│   ├── removal-policy.md
│   └── contributing-rules.md
├── install.sh                    # Linux/macOS installer with checksum verification
├── install.ps1                   # Windows installer with checksum verification
└── .github/
    ├── workflows/
    │   ├── ci.yml                # fmt + clippy + test + audit + deny
    │   ├── release.yml           # Build + sign + publish
    │   └── rules-validate.yml    # Validate rules on PR
    ├── ISSUE_TEMPLATE/
    │   ├── false-positive.yml
    │   └── missing-signature.yml
    └── PULL_REQUEST_TEMPLATE.md
```

---

## 3. Data Model (`crates/core`)

```rust
/// Central finding produced by the scoring engine
pub struct Finding {
    pub id: String,                    // e.g., "STK-WIN-0042-spyrix-1"
    pub rule_id: String,               // e.g., "STK-WIN-0042"
    pub name: String,                  // e.g., "Spyrix Keylogger"
    pub category: Category,
    pub severity: Severity,            // Critical | High | Medium | Low | Info
    pub confidence: Confidence,        // 0.0–1.0 with label (High/Medium/Low)
    pub evidence: Vec<Evidence>,
    pub is_legitimate_likely: bool,
    pub removal_policy: RemovalPolicy,
    pub removal_steps: RemovalSteps,
    pub explanation: Explanation,       // What, Why, Legitimacy, Recommendations
    pub references: Vec<String>,
}

pub enum Category {
    KeyboardCapture,
    ScreenCapture,
    RemoteAccess,
    OrganizationManaged,
    SuspiciousPersistence,
    NetworkActivity,
    ProcessWatcher,
}

pub enum Severity { Critical, High, Medium, Low, Info }

pub struct Confidence {
    pub score: f32,       // 0.0–1.0
    pub label: String,    // "High" | "Medium" | "Low"
}

pub enum RemovalPolicy {
    SafeAuto,
    ManualReview,
    DoNotRemove,
}

pub struct Evidence {
    pub evidence_type: EvidenceType,   // Process, RegistryKey, File, Service, etc.
    pub description: String,
    pub technical_detail: String,      // For expandable section in report
    pub source_collector: String,
}

pub struct Explanation {
    pub what_is_it: LocalizedString,
    pub why_flagged: LocalizedString,
    pub legitimacy_note: LocalizedString,
    pub recommendation: LocalizedString,
}

pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub platform: PlatformInfo,
    pub scan_duration: Duration,
    pub skipped_checks: Vec<SkippedCheck>,
    pub overall_verdict: Verdict,      // Clean | ReviewRecommended | SurveillanceLikely
}

pub struct SkippedCheck {
    pub name: String,
    pub reason: SkipReason,            // InsufficientPrivileges | UnsupportedPlatform | Timeout
}
```

---

## 4. Collector Architecture (`crates/collectors`)

```rust
/// Trait all collectors implement
pub trait Collector: Send + Sync {
    /// Human-readable name
    fn name(&self) -> &str;
    
    /// Required privilege level
    fn required_privilege(&self) -> PrivilegeLevel;
    
    /// Execute collection with timeout
    fn collect(&self, ctx: &CollectorContext) -> CollectorResult;
}

pub struct CollectorContext {
    pub privilege_level: PrivilegeLevel,
    pub timeout: Duration,
    pub platform: PlatformInfo,
}

pub enum CollectorResult {
    /// Successfully collected evidence
    Ok(Vec<RawEvidence>),
    /// Skipped due to privilege or platform
    Skipped(SkipReason),
    /// Failed with error
    Error(String),
}

pub struct RawEvidence {
    pub evidence_type: EvidenceType,
    pub collector_name: String,
    pub data: EvidenceData,            // Process info, registry entry, file path, etc.
    pub timestamp: SystemTime,
}
```

**Collector Registry** (compile-time, per-OS):
```rust
pub fn create_collectors() -> Vec<Box<dyn Collector>> {
    let mut collectors: Vec<Box<dyn Collector>> = vec![
        // Cross-platform
        Box::new(common::ProcessCollector),
        Box::new(common::NetworkCollector),
    ];
    
    #[cfg(target_os = "windows")]
    {
        collectors.push(Box::new(windows::PersistenceCollector));
        collectors.push(Box::new(windows::InputApiCollector));
        collectors.push(Box::new(windows::ConsentStoreCollector));
        collectors.push(Box::new(windows::DriverCollector));
        collectors.push(Box::new(windows::SignatureCollector));
        collectors.push(Box::new(windows::CertificateCollector));
        collectors.push(Box::new(windows::InstalledSoftwareCollector));
        collectors.push(Box::new(windows::WatcherCollector));
    }
    
    #[cfg(target_os = "linux")]
    {
        collectors.push(Box::new(linux::PersistenceCollector));
        collectors.push(Box::new(linux::InputCollector));
        collectors.push(Box::new(linux::PackageCollector));
        collectors.push(Box::new(linux::WatcherCollector));
    }
    
    #[cfg(target_os = "macos")]
    {
        collectors.push(Box::new(macos::PersistenceCollector));
        collectors.push(Box::new(macos::TccCollector));
        collectors.push(Box::new(macos::EventTapCollector));
        collectors.push(Box::new(macos::SignatureCollector));
        collectors.push(Box::new(macos::ProfileCollector));
        collectors.push(Box::new(macos::WatcherCollector));
    }
    
    collectors
}
```

**Parallel execution** with per-collector timeout:
```rust
pub fn run_scan(collectors: &[Box<dyn Collector>], ctx: &CollectorContext) -> Vec<CollectorResult> {
    collectors.par_iter().map(|c| {
        if ctx.privilege_level < c.required_privilege() {
            return CollectorResult::Skipped(SkipReason::InsufficientPrivileges);
        }
        // Run with timeout
        match timeout(ctx.timeout, || c.collect(ctx)) {
            Some(result) => result,
            None => CollectorResult::Error("Timeout".into()),
        }
    }).collect()
}
```

---

## 5. Rule Engine (`crates/rules`)

### 5.1 YAML Schema (see RESEARCH.md §6 for full example)

Key design decisions:
- **Multi-modal**: registry + processes + services + paths + network + file patterns in one rule
- **Condition language**: `any_of` / `all_of` / `count` — simple, no Turing-complete scripting
- **Removal embedded**: each rule carries `removal_policy` + OS-specific removal steps
- **Versioned**: `version` field; loader validates against JSON Schema
- **Community-friendly**: one YAML file per software family, PR-friendly

### 5.2 Matching Pipeline

```
 Collected Evidence
        │
        ▼
 ┌─────────────────┐
 │ Fast Filter      │  Name/path/hash exact match against rule index
 │ (HashMap lookup) │  Reject 95%+ of rules instantly
 └────────┬────────┘
          │ Candidate rules
          ▼
 ┌─────────────────┐
 │ Full Evaluation  │  Check all detection criteria in rule
 │ (condition tree) │  registry, services, tasks, patterns
 └────────┬────────┘
          │ Matched rules
          ▼
 ┌─────────────────┐
 │ Scoring Engine   │  Combine evidence count, confidence
 │ (crates/scoring) │  Apply allowlist, generate explanation
 └────────┬────────┘
          │
          ▼
      Findings[]
```

---

## 6. Scoring Engine (`crates/scoring`)

### Confidence Scoring Algorithm

```
base_score = 0.0

For each matched evidence:
  if evidence is exact_process_name_match:  +0.25
  if evidence is exact_registry_key_match:  +0.25
  if evidence is known_installation_path:   +0.20
  if evidence is known_service_name:        +0.20
  if evidence is known_network_domain:      +0.30
  if evidence is file_hash_match:           +0.40
  if evidence is suspicious_api_import:     +0.10
  if evidence is unsigned_binary:           +0.10
  if evidence is signed_by_known_vendor:    +0.15

Adjustments:
  if binary is validly signed by OS vendor: score *= 0.3  (likely legitimate)
  if binary is part of OS package manager:  score *= 0.3
  if rule.is_legitimate_likely:             score *= 0.5
  
confidence = clamp(base_score, 0.0, 1.0)
label = if confidence >= 0.7 { "High" }
        else if confidence >= 0.4 { "Medium" }
        else { "Low" }
```

**Allowlist**: Known legitimate software (OBS, Zoom, Teams, etc.) that uses keyboard/screen APIs is matched and explained but **not suppressed** — shown with `severity: Info` and clear "This is likely legitimate" note.

---

## 7. Removal Module (`crates/removal`)

### 7.1 Architecture

```
sentinel quarantine <id>
  │
  ├── Check removal_policy (reject do_not_remove)
  ├── Check corporate device indicators → warn if detected
  ├── Identify watchdog processes → neutralize FIRST
  ├── Disable persistence (rename/mask, don't delete)
  ├── Move executables to ~/.sentinel/quarantine/<id>/
  ├── Save quarantine-manifest.json
  └── Log to ~/.sentinel/removal-log.json

sentinel restore <id>
  │
  ├── Read quarantine-manifest.json
  ├── Restore executables to original locations
  ├── Re-enable persistence (rename back/unmask)
  └── Log to removal-log.json

sentinel remove <id> [--yes]
  │
  ├── Check removal_policy (reject do_not_remove)
  ├── Display exact list of files/keys/services to be deleted
  ├── Require interactive "yes" or --yes flag
  ├── Create restore point (SRSetRestorePointW / config backup)
  ├── Neutralize watchdog
  ├── Stop services/processes
  ├── Use UninstallString when available
  ├── Delete files/registry/tasks/units/plists
  ├── Post-removal verification scan
  └── Log everything to removal-log.json

sentinel remove --all-safe [--yes]
  │
  ├── Filter findings where removal_policy == safe_auto
  ├── If corporate device detected → extra confirmation
  ├── If --personal-safety-mode → REFUSE, show help resources
  ├── Create restore point
  ├── For each: remove (same as single remove)
  └── Post-removal verification scan
```

### 7.2 Corporate Device Detection

Check before any `remove --all-safe`:
- **Windows**: `(Get-WmiObject Win32_ComputerSystem).PartOfDomain`, Intune enrollment registry, Azure AD join status
- **macOS**: `profiles status -type enrollment`, MDM configuration profiles present
- **Linux**: SSSD/Winbind domain membership, managed `/etc` configs

### 7.3 Personal Safety Mode (`--personal-safety-mode`)

When activated:
- Auto-removal (`--all-safe`) is **completely disabled**
- Report includes expanded safety resources section
- Prominent warning: "Removing surveillance software may alert the person monitoring you"
- Links: Coalition Against Stalkerware, NNEDV, hotlines (US: 1-800-799-7233, EU: lila.help, DE: 116 006)
- Advice: "Plan safety steps BEFORE removing anything. Use a separate, unmonitored device to research."

---

## 8. HTML Report (`crates/report`)

### Design Principles
- **One self-contained HTML file** — embedded CSS/JS, zero external requests
- **Works offline** — no CDN, no fonts loaded externally
- **Clean, calm, trustworthy** — not alarmist; professional medical-report aesthetic
- **WCAG AA** — full keyboard navigation, sufficient contrast, semantic HTML
- **i18n** — Russian and English, switchable in-report
- **Dark/Light theme** — respects `prefers-color-scheme`, toggle button
- **Print-friendly** — `@media print` styles
- **Responsive** — mobile-friendly layout

### Report Structure

```
┌──────────────────────────────────────────────────────┐
│ HEADER                                                │
│ Overall Verdict: 🟢 Clean / 🟡 Review / 🔴 Likely    │
│ Plain-language explanation                            │
│ Scan metadata: OS, time, privileges, skipped checks   │
├──────────────────────────────────────────────────────┤
│ FILTERS: [Severity ▾] [Category ▾] [Search 🔍]       │
├──────────────────────────────────────────────────────┤
│ SECTION: Перехват клавиатуры / Keyboard Capture       │
│ ┌─ Finding Card ──────────────────────────────────┐  │
│ │ 🔴 Spyrix Keylogger          [HIGH] [95% conf]  │  │
│ │                                                  │  │
│ │ ▸ What is this?                                  │  │
│ │   Commercial keylogger that records all...       │  │
│ │ ▸ Why flagged (3 evidence items)                 │  │
│ │   • Registry: HKLM\SOFTWARE\Spyrix              │  │
│ │   • Process: spx.exe (PID 1234)                  │  │
│ │   • Service: spxsvc (running)                    │  │
│ │   ▸ Technical details...                         │  │
│ │ ▸ Is this legitimate?                            │  │
│ │   Unlikely. Marketed for covert monitoring.      │  │
│ │                                                  │  │
│ │ ┌─ How to Remove ──────────────────────────────┐│  │
│ │ │ [🛡️ Quarantine] [🗑️ Remove] (commands shown) ││  │
│ │ │ ▸ Manual removal steps (expandable)           ││  │
│ │ │   1. Open Settings → Apps...                  ││  │
│ │ └───────────────────────────────────────────────┘│  │
│ └──────────────────────────────────────────────────┘  │
│                                                       │
│ SECTION: Мониторинг организации / Org-Managed         │
│ ┌─ Finding Card ──────────────────────────────────┐  │
│ │ ℹ️ CrowdStrike Falcon         [INFO]             │  │
│ │ ⚙️ Managed by your organization                  │  │
│ │ Auto-removal not available for this category     │  │
│ │ Contact your IT department for questions          │  │
│ └──────────────────────────────────────────────────┘  │
├──────────────────────────────────────────────────────┤
│ FOOTER                                                │
│ ⚠️ Limitations: rootkits, firmware, hardware...       │
│ 🔒 Privacy: nothing left your computer                │
│ 📤 Export JSON                                        │
│ 🛡️ If you suspect personal surveillance...            │
│    DO NOT auto-remove without a safety plan.          │
│    Resources: stopstalkerware.org, 1-800-799-7233    │
└──────────────────────────────────────────────────────┘
```

---

## 9. CLI Design (`crates/cli`)

```
sentinel scan [OPTIONS]
    --elevated           Request admin/root privileges for deeper scan
    --lang <LANG>        Language: en | ru  [default: en]
    --out <DIR>          Output directory  [default: .]
    --json               Output JSON report only (no HTML)
    --no-open            Don't auto-open HTML report
    --online-lookups     Enable optional hash reputation checks
    --personal-safety-mode  Disable auto-removal, show safety resources

sentinel quarantine <ID>
    Quarantine a finding (reversible)

sentinel restore <ID>
    Restore a quarantined finding

sentinel remove <ID> [--yes]
    Permanently remove a finding

sentinel remove --all-safe [--yes] [--no-restore-point]
    Remove all safe_auto findings

sentinel explain <ID>
    Show detailed explanation of a finding

sentinel rules update
    Update rules from GitHub Releases (signature-verified)

sentinel rules validate <PATH>
    Validate a rule YAML file against schema
```

### Terminal Output

```
$ sentinel scan

  🔍 Sentinel v0.1.0 — Scanning for surveillance software...
  
  Platform: Windows 11 23H2 (x64)
  Privileges: Standard user
  ⚠ 3 checks skipped (admin required): keyboard filter drivers, service DLLs, WMI subscriptions
  
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  
  🔴 HIGH: Spyrix Keylogger — Keyboard Capture
     3 evidence items | Confidence: 95% | Policy: safe_auto
     → sentinel explain STK-WIN-0042-1
     → sentinel quarantine STK-WIN-0042-1
  
  🟡 MEDIUM: TeamViewer — Remote Access
     2 evidence items | Confidence: 60% | Policy: manual_review
     Likely legitimate if you installed it yourself
  
  ℹ️ INFO: CrowdStrike Falcon — Organization-Managed
     Managed by your organization | Policy: do_not_remove
  
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  
  Found: 3 items (1 high, 1 medium, 1 info)
  Report: ./sentinel-report-2026-10-04.html
  JSON:   ./sentinel-report-2026-10-04.json
```

---

## 10. Internationalization (i18n)

Compile-time string tables using a simple macro system:

```rust
// crates/core/src/i18n.rs
pub enum Lang { En, Ru }

macro_rules! localized {
    ($name:ident, $en:expr, $ru:expr) => {
        pub fn $name(lang: Lang) -> &'static str {
            match lang {
                Lang::En => $en,
                Lang::Ru => $ru,
            }
        }
    };
}

localized!(verdict_clean, "No surveillance software detected", "Следящее ПО не обнаружено");
localized!(verdict_review, "Review recommended", "Рекомендуется проверка");
localized!(verdict_surveillance, "Surveillance software likely detected", "Вероятно обнаружено следящее ПО");
localized!(skipped_admin, "Skipped (admin required)", "Пропущено (нужны права администратора)");
// ... hundreds more entries
```

---

## 11. Threat Model

### What Sentinel Protects Against
- **User-mode stalkerware/keyloggers/screen recorders** installed by someone with temporary physical access
- **Commercial monitoring software** (Teramind, ActivTrak, etc.) installed by employer/partner
- **Remote access tools** (TeamViewer, AnyDesk, VNC) that may be installed without user's knowledge
- **Process watchers / watchdog agents** that protect other surveillance software from removal
- **Abuser without specialized technical skills** — Sentinel minimizes scan footprint to avoid alerting a non-technical stalker who checks installed apps or recent files

### What Sentinel Does NOT Protect Against
- **Kernel rootkits** — cannot reliably detect from user-mode on a compromised system
- **Firmware/hardware keyloggers** — physical USB devices, modified keyboard firmware
- **Corporate EDR/SIEM** — will see Sentinel's process execution; we do NOT attempt to evade this
- **Advanced persistent threats** — nation-state implants with kernel/hypervisor access
- **Already-compromised OS** — scan results unreliable; recommend scan from trusted boot media

### Scan Footprint Minimization
- No persistent artifacts (no services, no registry keys, no autostart)
- Report written only to user-specified directory (default: CWD)
- No network connections by default
- Process exits after scan completes (no background daemon)
- Does NOT delete/modify system event logs
- Does NOT self-delete or clean up after itself (that's anti-forensics territory)

---

## 12. Milestone Plan

| # | Milestone | Deliverables | Est. Effort |
|---|-----------|-------------|-------------|
| **M1** | Skeleton | Cargo workspace, CI, core data model, YAML rule loader, JSON report, CLI `scan` stub | Foundation |
| **M2** | Process & Persistence | Cross-platform process collector, Windows persistence (Run/Services/Tasks/WMI/IFEO/Winlogon), Linux (systemd/cron/XDG/rc/LD_PRELOAD), macOS (LaunchAgents/Daemons/BTM), signature verification | Major |
| **M3** | Input/Screen Capture | Windows PE import analysis, Linux /dev/input + X11 + PipeWire, macOS CGGetEventTapList + TCC | Major |
| **M4** | Network | TCP/UDP→PID mapping, remote access port detection, proxy/cert/hosts checks | Medium |
| **M5** | Process Watchers | Windows (debug privs, handle enum, WMI watchers), Linux (ptrace, eBPF, auditd), macOS (ESF, MDM, Screen Time) | Medium |
| **M6** | Scoring & Allowlist | Scoring engine, allowlist, explanation generator, i18n strings | Medium |
| **M7** | Removal Module | Quarantine, restore, remove, restore points, watchdog neutralization, verification scan, removal log | Major |
| **M8** | HTML Report | Self-contained HTML with all UX requirements, terminal summary | Major |
| **M9** | Rule Database v1 | ≥60 rules with removal_policy + steps, JSON Schema, validator, contribution guide | Medium |
| **M10** | Packaging & Release | Installers, CI/CD release workflow, cosign, SBOM, winget/homebrew manifests, full docs | Medium |

---

## 13. CI / CD

### CI Matrix (`.github/workflows/ci.yml`)

```yaml
strategy:
  matrix:
    os: [windows-latest, ubuntu-latest, macos-latest]
    rust: [stable]
steps:
  - cargo fmt --all -- --check
  - cargo clippy --all-targets --all-features -- -D warnings
  - cargo test --all
  - cargo audit
  - cargo deny check
```

### Release Pipeline (`.github/workflows/release.yml`)

Triggered on tag `v*`:
1. Build release binaries: `x86_64-pc-windows-msvc`, `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`
2. Generate `SHA256SUMS`
3. Sign with cosign/sigstore
4. Generate SBOM (`cargo-sbom`)
5. Create GitHub Release with attached artifacts
6. Update `install.sh` / `install.ps1` checksums

---

## 14. License Decision

- **Code**: Apache-2.0 — explicit patent grant, corporate-friendly, no copyleft friction
- **Rule database** (`rules/`): CC-BY-4.0 — appropriate for data/IoC feeds, community-friendly, requires attribution
- **Dual-license header** in each source file

---

## 15. Non-Goals Reminder

Sentinel will **NEVER** implement:
- ❌ Keylogging, screen capture, input hooks, DLL injection, or any offensive capability
- ❌ Telemetry or phone-home behavior
- ❌ Anti-forensics (log deletion, self-destruction, EDR evasion)
- ❌ Auto-removal of `do_not_remove` software
- ❌ Background daemon or persistent service mode
- ❌ Any code that would trigger its own detection rules

---

> **Next step**: Awaiting your approval of this plan before proceeding to Phase 2 (implementation).  
> If you'd like changes to any section — architecture, data model, UX, milestones — let me know.
