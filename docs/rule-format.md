# Sentinel Detection Rule Format Specification

Sentinel rules are declarative YAML files stored under the `rules/` directory.

---

## Example Rule

```yaml
id: "STK-WIN-0042"
name: "Spyrix Personal Monitor"
version: 1
category: "KeyboardCapture"
severity: "High"
base_confidence: 0.85
removal_policy: "SafeAuto"
platforms:
  - "windows"
  - "macos"
vendor: "Spyrix Software"
description: "Commercial keylogger recording keystrokes and taking screenshots."
is_legitimate_use_likely: false

detection:
  processes:
    - name: "spx.exe"
    - name: "spm.exe"
  registry_keys:
    - hive: "HKLM"
      path: "SOFTWARE\\Spyrix"
  services:
    - name: "spxsvc"
  paths:
    - "C:\\Program Files (x86)\\Spyrix Personal Monitor\\"
  network_domains:
    - "spyrix.com"

removal:
  services_to_stop:
    - "spxsvc"
  processes_to_kill:
    - "spx.exe"
  paths_to_remove:
    - "C:\\Program Files (x86)\\Spyrix Personal Monitor"
  manual_steps_windows: |
    1. Stop the spxsvc service via `sc stop spxsvc`.
    2. Terminate spx.exe in Task Manager.
    3. Delete the folder C:\Program Files (x86)\Spyrix Personal Monitor.

references:
  - "https://stopstalkerware.org/"
```

---

## Fields Reference

- `id`: Unique identifier formatted as `[CAT]-[OS]-[0000]` (e.g. `STK-WIN-0042`, `COR-ALL-0001`).
- `name`: Display name of the software family.
- `version`: Integer version of the rule format.
- `category`: Primary classification (`KeyboardCapture`, `ScreenCapture`, `RemoteAccess`, `OrganizationManaged`, `SuspiciousPersistence`, `NetworkActivity`, `ProcessWatcher`).
- `severity`: Alert level (`Critical`, `High`, `Medium`, `Low`, `Info`).
- `base_confidence`: Float between 0.0 and 1.0 representing initial detection confidence.
- `removal_policy`: Remediation permission (`SafeAuto`, `ManualReview`, `DoNotRemove`).
- `detection`: Target IoCs and technical patterns:
  - `processes`: Executable names and optional regexes.
  - `registry_keys`: Hive (`HKLM` or `HKCU`), subkey path, and value name.
  - `services`: Windows service or Linux daemon names.
  - `paths`: Installation directories.
  - `network_domains`: Associated C2 or update hostnames.
  - `network_ports`: Default listening ports.
- `removal`: Structured steps for automated remediation and markdown text for manual removal instructions.
