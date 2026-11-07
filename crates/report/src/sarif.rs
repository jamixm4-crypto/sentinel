use sentinel_core::{ScanResult, Severity};
use serde_json::json;
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub fn generate_sarif_report(result: &ScanResult) -> serde_json::Value {
    let rules: Vec<serde_json::Value> = result
        .findings
        .iter()
        .map(|f| {
            json!({
                "id": f.rule_id,
                "name": f.name,
                "shortDescription": {
                    "text": f.name
                },
                "fullDescription": {
                    "text": f.explanation.what_is_it
                },
                "help": {
                    "text": format!("{}\nRecommendation: {}", f.explanation.why_flagged, f.explanation.recommendation)
                },
                "properties": {
                    "category": format!("{:?}", f.category),
                    "confidence": f.confidence.score,
                    "mitre_attack": f.mitre_attack
                }
            })
        })
        .collect();

    let results: Vec<serde_json::Value> = result
        .findings
        .iter()
        .map(|f| {
            let level = match f.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low | Severity::Info => "note",
            };

            let message = format!("{}: {}", f.name, f.explanation.why_flagged);

            json!({
                "ruleId": f.rule_id,
                "level": level,
                "message": {
                    "text": message
                },
                "properties": {
                    "findingId": f.id,
                    "evidenceCount": f.evidence.len(),
                    "removalPolicy": format!("{:?}", f.removal_policy)
                }
            })
        })
        .collect();

    json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Sentinel",
                        "version": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://github.com/jamixm4-crypto/sentinel",
                        "rules": rules
                    }
                },
                "results": results
            }
        ]
    })
}

pub fn export_sarif_report(result: &ScanResult, path: &Path) -> std::io::Result<()> {
    let sarif = generate_sarif_report(result);
    let json = serde_json::to_string_pretty(&sarif)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}
