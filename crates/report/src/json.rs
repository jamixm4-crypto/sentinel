use sentinel_core::ScanResult;
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub fn export_json_report(result: &ScanResult, path: &Path) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(result)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}
