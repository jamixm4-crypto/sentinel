---
name: surveillance-incident-response
description: >-
  Standard operating procedures and triage protocols for responding to suspected intimate partner
  surveillance, employee monitoring, and corporate EDR inquiries safely and ethically.
---

# Surveillance Incident Response Skill

This skill provides step-by-step triage procedures for responders handling surveillance detections.

## 1. Safety-First Triage for Domestic Violence / Stalking
When a user suspects stalking by an intimate partner:

1. **Do NOT Immediately Remove**:
   - Immediate removal triggers offline alerts to the abuser's dashboard.
   - Escalation risk: Abusers may turn to physical confrontation or intensify monitoring.
2. **Safe Communication**:
   - Establish communication exclusively from an uncompromised secondary device (burner phone, library terminal).
3. **Forensic Evidence Preservation**:
   - Generate static cryptographic evidence reports:
     ```bash
     sentinel scan --format json --output evidence.json
     sentinel scan --format html --output evidence.html
     ```
   - Store reports on an encrypted external drive.
   - Record system timestamp, OS serial, and network interface MAC addresses.
4. **Crisis Hotlines**:
   - Coalition Against Stalkerware: `https://stopstalkerware.org`
   - Lila.help International Directory: `https://lila.help`
   - National DV Hotline: 1-800-799-7233 (SMS: START to 88788)
   - Russian Helplines: 8-800-7000-600, Центр «Насилию.нет» (+7 495 916-30-00)

## 2. Enterprise & Workplace Triage
When detections occur on enterprise-managed assets:

1. **Verify `removal_policy: do_not_remove`**:
   - Never attempt deletion of EDR/MDM agents (CrowdStrike, SentinelOne, Intune, Jamf).
   - Tamper protection triggers automated host isolation.
2. **Distinguish Security Telemetry from Employee Activity Monitoring (EAM)**:
   - Security EDR: Process telemetry, network sockets, file modifications.
   - EAM: Keylogging, periodic screen recording, webcam snapshots (StaffCop, Kickidler, Hubstaff).
3. **Report to Infosec**:
   - Provide the JSON audit report to the internal IT/Security team for resolution.
