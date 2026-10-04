# Sentinel Removal Policy & Safe Remediation Specification

Sentinel classifies all findings into one of three strict `removal_policy` levels to protect users from breaking their systems or violating workplace agreements:

---

## 1. `SafeAuto` (Safe Automatic Removal Available)

### Criteria
- The detected software is unequivocally dedicated to surveillance, keystroke logging, stealth screen recording, or unauthorized tracking.
- There is no credible dual-use personal productivity role for the binary.
- The uninstallation procedure is well-understood, documented, and capable of clean execution without destabilizing the operating system.

### Examples
- Spyrix Personal Monitor
- Refog Keylogger
- Actual Keylogger
- pcTattletale
- mSpy Desktop Agent
- FlexiSPY

### Operational Flow
- `sentinel quarantine <id>`: Moves executables to `~/.sentinel/quarantine/` and creates a rollback manifest.
- `sentinel remove <id>`: Permanently removes registry autostarts, services, tasks, and files after interactive confirmation.
- `sentinel remove --all-safe`: Remediates all `SafeAuto` items after explicit prompt.

---

## 2. `ManualReview` (Dual-Use Software)

### Criteria
- The software possesses surveillance or remote control capabilities, but is also commonly deployed by legitimate users for remote administration, video streaming, automation, or family safety.
- Examples include remote desktop clients, automated macros, employee time trackers, and legitimate parental controls.

### Examples
- TeamViewer, AnyDesk, RustDesk
- VNC Servers (UltraVNC, TightVNC, RealVNC)
- Time Doctor, Hubstaff, Kickidler
- AutoHotkey
- KidLogger

### Operational Flow
- Automatic bulk removal (`--all-safe`) will **never** touch `ManualReview` software.
- The user must individually review and confirm each item:
  ```bash
  sentinel remove <id>
  ```
- Sentinel provides detailed manual removal guides if the user prefers standard OS uninstallers.

---

## 3. `DoNotRemove` (Organization-Managed Software)

### Criteria
- Software deployed, maintained, and legally owned by an enterprise, university, or corporate IT department.
- Includes enterprise Endpoint Detection & Response (EDR), Mobile Device Management (MDM), and corporate compliance agents.

### Examples
- CrowdStrike Falcon Sensor
- SentinelOne Singularity
- Microsoft Intune Management Extension
- VMware Carbon Black
- Jamf Pro Management Agent
- Mosyle & Kandji MDM Agents
- Teramind & ActivTrak Corporate Agents

### Operational Flow
- **Automated removal is permanently and unconditionally blocked** across all CLI subcommands (`remove`, `quarantine`).
- Reports and CLI output explain:
  1. What the software is and why it was deployed.
  2. That tampering with employer-owned software may violate the Computer Fraud and Abuse Act (CFAA), employment contracts, or corporate acceptable use policies.
  3. Guidance on contacting IT administration for legitimate assistance.
