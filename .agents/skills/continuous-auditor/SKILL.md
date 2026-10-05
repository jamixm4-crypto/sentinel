---
name: continuous-auditor
description: >-
  Workflows and configuration templates for scheduling non-intrusive background surveillance audits
  with Sentinel using scheduled automations, Windows Task Scheduler, or systemd timers.
---

# Continuous Auditor Skill for Sentinel

This skill provides step-by-step guidance on establishing persistent, low-overhead surveillance audits so that users are automatically notified if new stalkerware, remote access tools, or process masquerading appear on their system.

## 1. Antigravity Scheduled Automation (`sidecar.json`)
Sentinel can be invoked on a cadence (e.g. daily at 9:00 AM or hourly) via the Antigravity automation framework:

```json
{
  "builtin": "schedule",
  "args": [
    "0 9 * * *",
    "agentapi",
    "new-conversation",
    "--",
    "Run 'sentinel scan --output json' to audit the local system for surveillance software. If any High or Critical findings are discovered, present an immediate incident report."
  ],
  "restart_policy": "always",
  "display_name": "Daily Sentinel Surveillance Audit",
  "description": "Performs an automated daily read-only audit of background processes, autostart persistence, and network beacons.",
  "agent_permissions": {
    "access_grants": [
      "command(sentinel scan)"
    ]
  }
}
```

## 2. Native Windows Scheduled Task Setup
To run Sentinel automatically on Windows logon or daily at 10:00 without opening terminal windows:
```powershell
$Action = New-ScheduledTaskAction -Execute "sentinel.exe" -Argument "scan --output json"
$Trigger = New-ScheduledTaskTrigger -Daily -At 10:00AM
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName "SentinelDailyAudit" -Action $Action -Trigger $Trigger -Settings $Settings -Description "Sentinel Read-Only Surveillance Audit"
```

## 3. Native Linux systemd User Timer
Create a lightweight user service `~/.config/systemd/user/sentinel-audit.service`:
```ini
[Unit]
Description=Sentinel Surveillance Audit
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/sentinel scan --output json
```

And companion timer `~/.config/systemd/user/sentinel-audit.timer`:
```ini
[Unit]
Description=Run Sentinel Audit Daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```
Enable with:
```bash
systemctl --user enable --now sentinel-audit.timer
```

## 4. Triage on Audit Triggers
When an automated audit flags a finding:
1. Verify if the finding is `safe_auto` (covert stalkerware) vs `manual_review` (dual-use remote desktop tool like AnyDesk).
2. Generate an HTML or Markdown incident summary for review.
3. Consult `surveillance-incident-response` before attempting automatic removal if intimate partner violence or workplace surveillance is suspected.
