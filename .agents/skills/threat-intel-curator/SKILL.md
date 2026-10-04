---
name: threat-intel-curator
description: >-
  Workflows, procedures, and validation steps for curating, normalizing, and verifying
  stalkerware and surveillance Indicators of Compromise (IOCs) from open threat feeds
  (Coalition Against Stalkerware, AssoEchap, Citizen Lab, TinyCheck) into Sentinel YAML rules.
---

# Threat Intelligence Curator Skill for Sentinel

This skill guides the collection, verification, and transformation of external threat intelligence into production Sentinel detection rules.

## 1. Upstream Threat Intelligence Sources
- **AssoEchap / stalkerware-indicators**:
  - URL: `https://github.com/AssoEchap/stalkerware-indicators`
  - Formats: `ioc.yaml`, `generated/hosts`, `generated/hosts_full`
  - Indicators: C2 domains, server IPs, Android certificates, package names.
- **Kaspersky TinyCheck IoC Feeds**:
  - Network indicators and beacon patterns for mobile and desktop spyware.
- **Citizen Lab Research**:
  - Commercial spyware forensics (Pegasus, Predator, FinFisher, Cytrox).
- **MITRE ATT&CK Matrix for Enterprise**:
  - T1056.001 (Input Capture: Keylogging)
  - T1113 (Screen Capture)
  - T1125 (Video Capture)
  - T1123 (Audio Capture)
  - T1020 (Automated Exfiltration)
  - T1562.001 (Impair Defenses: Disable or Evade Tools)

## 2. IOC Normalization Pipeline
When ingesting indicators for a newly discovered surveillance family:

1. **Category Assignment**:
   - `stalkerware`: Covert consumer monitoring without notification.
   - `corporate`: Employee activity trackers, screenshots, productivity monitors.
   - `remote_access`: Dual-use remote administration tools.
   - `edr_mdm`: Enterprise security agents.
2. **Policy Mapping**:
   - Covert spyware/keyloggers -> `removal_policy: safe_auto`
   - Dual-use remote access -> `removal_policy: manual_review`
   - Corporate infrastructure -> `removal_policy: do_not_remove`
3. **Multi-Modal Verification**:
   - Ensure rules do not rely on binary names alone. Require at least two orthogonal modalities:
     - Process name + Autostart registry key / LaunchAgent
     - File path glob + SHA-256 / Certificate Signer
     - Network C2 domain / Port + Process signature

## 3. Automated Validation Rule
Run validation before committing any new rule:
```bash
sentinel rules validate --dir ./rules
cargo test --workspace
```
