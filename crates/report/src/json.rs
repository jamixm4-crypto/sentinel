use sentinel_core::{Category, ScanResult, Severity};
use serde_json::json;
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub fn export_json_report(result: &ScanResult, path: &Path) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(result)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

/// Convert Sentinel scan findings into Elastic Common Schema (ECS v8.11.0) compatible alerts
pub fn generate_ecs_events(result: &ScanResult) -> Vec<serde_json::Value> {
    result
        .findings
        .iter()
        .map(|f| {
            let severity_num = match f.severity {
                Severity::Info => 10,
                Severity::Low => 30,
                Severity::Medium => 60,
                Severity::High => 80,
                Severity::Critical => 100,
            };

            let (tactic_id, tactic_name, tech_id, tech_name) = match f.category {
                Category::KeyboardCapture => ("TA0009", "Collection", "T1056.001", "Keylogging"),
                Category::ScreenCapture => ("TA0009", "Collection", "T1113", "Screen Capture"),
                Category::RemoteAccess => ("TA0011", "Command and Control", "T1219", "Remote Access Software"),
                Category::OrganizationManaged => ("TA0007", "Discovery", "T1082", "System Information Discovery"),
                Category::SuspiciousPersistence => ("TA0003", "Persistence", "T1547", "Boot or Logon Autostart Execution"),
                Category::NetworkActivity => ("TA0011", "Command and Control", "T1071", "Application Layer Protocol"),
                Category::ProcessWatcher => ("TA0005", "Defense Evasion", "T1562", "Impair Defenses"),
            };

            json!({
                "@timestamp": result.timestamp,
                "ecs": {
                    "version": "8.11.0"
                },
                "event": {
                    "kind": "alert",
                    "category": ["intrusion_detection", "malware"],
                    "type": ["indicator"],
                    "severity": severity_num,
                    "risk_score": (f.confidence.score * 100.0).round() as u32,
                    "provider": "Sentinel",
                    "action": format!("{:?}", f.removal_policy)
                },
                "rule": {
                    "id": f.rule_id,
                    "name": f.name,
                    "category": f.category.name_en(),
                    "description": f.explanation.what_is_it,
                    "reference": f.references
                },
                "threat": {
                    "framework": "MITRE ATT&CK",
                    "tactic": {
                        "id": tactic_id,
                        "name": tactic_name
                    },
                    "technique": {
                        "id": tech_id,
                        "name": tech_name
                    }
                },
                "host": {
                    "os": {
                        "name": &result.platform.os_name,
                        "family": &result.platform.os_name
                    },
                    "hostname": &result.platform.hostname
                },
                "message": format!("{}: {}", f.name, f.explanation.why_flagged),
                "sentinel": {
                    "finding_id": f.id,
                    "confidence_label": f.confidence.label,
                    "confidence_score": f.confidence.score,
                    "is_legitimate_likely": f.is_legitimate_likely,
                    "vendor": f.vendor.as_deref().unwrap_or("Unknown")
                }
            })
        })
        .collect()
}

/// Export scan findings as newline-delimited ECS JSON (NDJSON) string
pub fn export_ecs_ndjson(result: &ScanResult) -> String {
    let events = generate_ecs_events(result);
    let mut out = String::new();
    for ev in events {
        if let Ok(line) = serde_json::to_string(&ev) {
            out.push_str(&line);
            out.push('\n');
        }
    }
    out
}

/// Export scan findings to an ECS formatted JSON file
pub fn export_ecs_report(result: &ScanResult, path: &Path) -> std::io::Result<()> {
    let ndjson = export_ecs_ndjson(result);
    let mut file = File::create(path)?;
    file.write_all(ndjson.as_bytes())?;
    Ok(())
}
