use sentinel_core::ScanResult;
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub fn generate_csv_report(result: &ScanResult) -> String {
    let mut out = String::from("id,rule_id,name,vendor,category,severity,confidence,is_legitimate_likely,removal_policy,evidence_count\n");
    for f in &result.findings {
        let clean_name = f.name.replace('"', "\"\"");
        let clean_vendor = f.vendor.as_deref().unwrap_or("").replace('"', "\"\"");
        out.push_str(&format!(
            "\"{}\",\"{}\",\"{}\",\"{}\",\"{:?}\",\"{:?}\",{:.2},{},\"{:?}\",{}\n",
            f.id,
            f.rule_id,
            clean_name,
            clean_vendor,
            f.category,
            f.severity,
            f.confidence.score,
            f.is_legitimate_likely,
            f.removal_policy,
            f.evidence.len()
        ));
    }
    out
}

pub fn export_csv_report(result: &ScanResult, path: &Path) -> std::io::Result<()> {
    let csv = generate_csv_report(result);
    let mut file = File::create(path)?;
    file.write_all(csv.as_bytes())?;
    Ok(())
}
