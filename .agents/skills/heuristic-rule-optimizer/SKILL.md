---
name: heuristic-rule-optimizer
description: >-
  Procedures and guidelines for calibrating Sentinel detection heuristics, tuning confidence scores,
  verifying multi-modal rule conditions, and suppressing false positives against legitimate software.
---

# Heuristic Rule Optimizer Skill

This skill defines workflows for profiling, calibrating, and benchmarking Sentinel surveillance detection rules to maximize true positives while maintaining a zero false-positive rate on standard user workstations.

## 1. Multi-Modal Rule Design Principles
To prevent accidental alerts on similarly named legitimate utilities:
- **Avoid Single Process-Name Triggers**:
  Never author a rule that matches solely on a generic executable name (e.g. `client.exe`, `monitor.exe`, `service.exe`).
- **Enforce Corroborating Evidence (`condition.min_matches`)**:
  When a binary name might conflict with other software, set `min_matches: 2` and require at least two distinct modalities:
  1. Process Execution + Autostart Registry Key (`Run` / `RunOnce`).
  2. Process Execution + Outbound C2 Domain or Port.
  3. Process Execution + Matching File Path in AppData/ProgramData.
- **Strict Command-Line Regular Expressions (`cmdline_regex`)**:
  Use `cmdline_regex` to match persistent background daemon flags (e.g. `--hidden`, `-silent`, `--autostart`, `/nogui`).

## 2. Confidence Calibration Scale
- **0.90 – 1.0 (Critical / High Certainty)**:
  - Matched known Stalkerware C2 domain in DNS cache or active socket.
  - Critical Windows system process masquerading (`svchost.exe` or `lsass.exe` running from `AppData` or `Temp`).
  - Active process correlated with dedicated surveillance registry persistence and known file hashes.
- **0.75 – 0.85 (Medium Certainty / Dual-Use Review)**:
  - Legitimate remote administration tools (TeamViewer, AnyDesk, RustDesk, VNC) running in user session.
  - Corporate time-tracking agents (Hubstaff, Time Doctor) with active UI.
- **0.50 – 0.70 (Low Certainty / Heuristic Suspicion)**:
  - Isolated file artifact on disk without active execution or persistence.
  - Background process capturing screen without matching known C2 or persistence.

## 3. Benign Application Safeguards
Always benchmark rules against standard benign workstation profiles:
- **Streaming & Screen Recording**: OBS Studio (`obs64.exe`), NVIDIA ShadowPlay (`nvspcaps64.exe`).
- **Gaming Overlays**: Discord Game Overlay (`discord.exe`), Steam Overlay (`gameoverlayui.exe`), RivaTuner (`RTSS.exe`).
- **Accessibility & Screen Readers**: NVDA (`nvda.exe`), Windows Narrator (`narrator.exe`).
- **Developer IDEs & Terminals**: VS Code (`code.exe`), Visual Studio (`devenv.exe`), JetBrains IDEs.

## 4. Benchmark Validation Workflow
Run the workspace test suite to verify that rule updates do not break benchmark expectations:
```bash
cargo test --test mock_tests
sentinel rules validate --dir ./rules
```
