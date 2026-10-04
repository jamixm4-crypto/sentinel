use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationLogEntry {
    pub timestamp: String,
    pub operation: String, // "quarantine", "restore", "remove"
    pub finding_id: String,
    pub target_name: String,
    pub success: bool,
    pub details: Vec<String>,
}

pub fn get_sentinel_data_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".sentinel")
}

pub fn log_operation(
    operation: &str,
    finding_id: &str,
    target_name: &str,
    success: bool,
    details: Vec<String>,
) -> std::io::Result<()> {
    let dir = get_sentinel_data_dir();
    create_dir_all(&dir)?;

    let log_file = dir.join("removal-log.json");
    let entry = OperationLogEntry {
        timestamp: Utc::now().to_rfc3339(),
        operation: operation.to_string(),
        finding_id: finding_id.to_string(),
        target_name: target_name.to_string(),
        success,
        details,
    };

    let serialized = serde_json::to_string(&entry)? + "\n";
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)?;
    file.write_all(serialized.as_bytes())?;
    Ok(())
}
