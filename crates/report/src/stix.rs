use sentinel_core::ScanResult;
use serde_json::json;
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub fn generate_stix_report(result: &ScanResult) -> serde_json::Value {
    let objects: Vec<serde_json::Value> = result
        .findings
        .iter()
        .map(|f| {
            let indicator_id = format!("indicator--{}", f.id);
            let confidence_val = (f.confidence.score * 100.0).round() as u32;

            json!({
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": result.timestamp,
                "modified": result.timestamp,
                "name": f.name,
                "description": format!("{}\nRecommendation: {}", f.explanation.why_flagged, f.explanation.recommendation),
                "indicator_types": ["malicious-activity", "surveillance-software"],
                "pattern": format!("[process:name = '{}']", f.rule_id),
                "pattern_type": "stix",
                "confidence": confidence_val,
                "external_references": f.references.iter().map(|r| {
                    json!({
                        "source_name": "sentinel-rule",
                        "url": r
                    })
                }).collect::<Vec<_>>()
            })
        })
        .collect();

    json!({
        "type": "bundle",
        "id": format!("bundle--sentinel-{}", result.timestamp.replace([':', '-', '.'], "")),
        "objects": objects
    })
}

pub fn export_stix_report(result: &ScanResult, path: &Path) -> std::io::Result<()> {
    let stix = generate_stix_report(result);
    let json = serde_json::to_string_pretty(&stix)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}
