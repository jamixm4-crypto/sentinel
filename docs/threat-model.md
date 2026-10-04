# Sentinel Threat Model & Security Boundaries

## 1. System Philosophy & Purpose

Sentinel is designed specifically to detect software installed on a personal computer that conducts unauthorized surveillance, keystroke logging, screen capturing, remote control, or process watching.

---

## 2. In-Scope Adversaries & Threats

| Threat Actor | Capabilities & Tools | Defensive Posture |
| :--- | :--- | :--- |
| **Domestic Stalker / Abuser** | Physical or remote desktop access to install commercial stalkerware (Spyrix, mSpy, FlexiSPY, Refog, Actual Keylogger). | **Primary Target**: Sentinel detects known process names, registry persistence, startup hooks, and hidden installation directories. |
| **Employer / Enterprise Monitoring** | Corporate tracking software (Teramind, ActivTrak, Hubstaff, Kickidler, Veriato) deployed via GPO, script, or installer. | **In Scope**: Sentinel identifies and explains the surveillance capabilities, while classifying them as `DoNotRemove` or `ManualReview` to protect the employee from unintended contractual or disciplinary harm. |
| **Unwanted Remote Access Utilities** | Unattended access backdoors (TeamViewer, AnyDesk, RustDesk, ScreenConnect, NetSupport, VNC). | **In Scope**: Sentinel identifies active listeners, services, and autostart configurations. |
| **Watchdog & Anti-Kill Implants** | Secondary processes or drivers configured to restart primary surveillance software if terminated. | **In Scope**: Sentinel correlates and targets watchdogs first before remediating primary components. |

---

## 3. Explicit Non-Goals & Limitations

Sentinel operates in user-mode with optional administrative elevation. As a matter of computer science and operating system security principles:

1. **Kernel-Level Rootkits**: If an adversary has installed a custom kernel driver or modified the kernel Dispatch tables (`ntoskrnl.exe`, Mach kernel, Linux LKM), user-mode code cannot reliably query kernel truth. Sentinel alerts users to inspect drivers, but recommends scanning from trusted offline boot media when rootkits are suspected.
2. **Firmware & Hardware Keyloggers**: Hardware keyloggers (inline USB dongles, compromised keyboard microcontrollers) operate completely below the operating system bus layer. Sentinel explicitly notes this limitation in reports and advises physical cable inspection.
3. **Enterprise SIEM / EDR Evasion**: Sentinel is a legitimate defensive security tool, **not an anti-EDR malware loader**. Enterprise security operations centers (SOCs) monitoring endpoint process launches will observe `sentinel.exe` running. Sentinel does not attempt to bypass AMSI, unhook NTDLL, or hide from CrowdStrike Falcon.
4. **Anti-Forensics & Log Erasure**: Sentinel **never** deletes Windows Event Logs, clears syslog, or shreds audit files. Such actions are characteristic of offensive tools.

---

## 4. Personal Safety Mode (`--personal-safety-mode`)

In situations involving domestic abuse or stalking:
- Auto-removal of stalkerware can immediately trigger alerts on the abuser's remote portal (e.g. "Device disconnected").
- This sudden loss of access can precipitate physical confrontation or danger.
- When `personal_safety_mode` is enabled:
  1. Automated removal is strictly prohibited.
  2. The report presents emergency hotlines ([Coalition Against Stalkerware](https://stopstalkerware.org), [Lila.help](https://lila.help), National DV Hotline).
  3. Guidance is provided to seek advice from an unmonitored device before disabling any software.
