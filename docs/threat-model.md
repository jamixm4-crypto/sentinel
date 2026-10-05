# Sentinel Threat Model & Security Boundaries

## 1. System Philosophy & Purpose

Sentinel is designed specifically to detect software installed on a desktop workstation or laptop that conducts unauthorized surveillance, keystroke logging, screen capturing, remote control, or process watching. It operates offline-first, with zero telemetry, and is strictly read-only by default.

---

## 2. In-Scope Adversaries & Threats

| Threat Actor | Capabilities & Tools | Defensive Posture |
| :--- | :--- | :--- |
| **Domestic Stalker / Intimate Partner** | Physical or remote desktop access to install commercial stalkerware (Spyrix, mSpy, FlexiSPY, Refog, Actual Keylogger). | **Primary Focus**: Sentinel inspects process tables, autostart extensibility points (ASEP), startup folders, scheduled tasks, and C2 beacons. |
| **Employer / Enterprise Monitoring** | Corporate tracking software (Teramind, ActivTrak, Hubstaff, Kickidler, Veriato) deployed via GPO, script, or installer. | **In Scope**: Sentinel identifies and explains the surveillance capabilities, while classifying them as `DoNotRemove` or `ManualReview` to protect the employee from unintended contractual or disciplinary harm. |
| **Unwanted Remote Access Utilities** | Unattended access backdoors (TeamViewer, AnyDesk, RustDesk, ScreenConnect, NetSupport, VNC). | **In Scope**: Sentinel identifies active listeners, services, and autostart configurations. |
| **Watchdog & Anti-Kill Implants** | Secondary processes or watchdog scripts configured to respawn primary surveillance software if terminated. | **In Scope**: Sentinel correlates process trees and targets watchdogs first before remediating primary components. |
| **Process Masquerading (MITRE T1036.005)** | Stalkerware binaries renamed to `svchost.exe`, `lsass.exe`, `csrss.exe` running from user directories (`AppData`, `Temp`, `Users`). | **In Scope**: Sentinel strictly verifies binary paths against `%SystemRoot%\System32` and flags any unauthorized masquerading with high severity. |

---

## 3. Explicit Non-Goals & Limitations

Sentinel operates in user-mode with optional administrative elevation. As a matter of computer science and operating system security boundaries:

1. **Kernel-Level Rootkits**: If an adversary has installed a custom kernel driver or modified kernel dispatch tables (`ntoskrnl.exe`, Mach kernel, Linux LKM), user-mode code cannot reliably query kernel truth. Sentinel alerts users to inspect drivers, but recommends scanning from trusted offline boot media when rootkits are suspected.
2. **Firmware & Hardware Keyloggers**: Hardware keyloggers (inline USB dongles, compromised keyboard microcontrollers) operate completely below the operating system bus layer. Sentinel explicitly notes this limitation in reports and advises physical cable and port inspection.
3. **Mobile Devices (Android & iOS)**:
   - The majority of modern consumer stalkerware targets mobile smartphones (Android APKs, iOS iCloud synchronization / configuration profiles).
   - Sentinel is a desktop security tool (Windows, Linux, macOS) and **cannot directly inspect internal smartphone storage** without physical connection via ADB (Android Debug Bridge) or extracting an unencrypted iOS backup.
   - For mobile stalkerware triage, we recommend specialized mobile forensics tools such as **Amnesty International's MVT (Mobile Verification Toolkit)** or **TinyCheck**.
   - Sentinel does, however, maintain an embedded database of 280+ mobile stalkerware Command & Control (C2) domains, detecting if a computer's DNS cache or local proxy is communicating with mobile tracking servers.
4. **Enterprise SIEM / EDR Evasion**: Sentinel is a legitimate defensive security tool, **not an anti-EDR malware loader**. Enterprise security operations centers (SOCs) monitoring endpoint process launches will observe `sentinel.exe` running. Sentinel does not attempt to bypass AMSI, unhook NTDLL, or hide from CrowdStrike Falcon.
5. **Anti-Forensics & Log Erasure**: Sentinel **never** deletes Windows Event Logs, clears syslog, or shreds audit files. Such actions are characteristic of offensive tools.

---

## 4. Personal Safety Mode (`--personal-safety-mode`)

In situations involving domestic abuse or stalking:
- Auto-removal or termination of stalkerware can immediately trigger alerts on the abuser's remote portal (e.g. "Device disconnected", "Heartbeat lost").
- This sudden loss of access can precipitate physical confrontation or retaliatory violence.
- When `personal_safety_mode` is enabled:
  1. **Zero Disk Artifacts**: No HTML or JSON report files are saved to the local filesystem (in-memory terminal output only), preventing the abuser from finding report files.
  2. **Browser Suppression**: The default web browser is not launched, leaving no browser history, cache, or tabs.
  3. **Strict Remediation Lockdown**: Automated removal and quarantine are strictly disabled.
  4. **Safety Guidance**: The terminal displays international assistance resources ([Coalition Against Stalkerware](https://stopstalkerware.org), [Lila.help](https://lila.help)).

---

## 5. Residual Traces & Forensic Footprint

Running any binary on an operating system naturally creates secondary forensic traces:
- **Windows**: Prefetch files (`SENTINEL.EXE-*.pf`), BAM (Background Activity Moderator), UserAssist registry keys, and PowerShell console history (`ConsoleHost_history.txt`).
- **Linux / macOS**: Shell history files (`~/.bash_history`, `~/.zsh_history`) and system audit logs.

**Defensive Advice**: If you fear being actively monitored, run Sentinel from an external read-only USB flash drive and review results on an unmonitored secondary device.
