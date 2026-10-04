use std::fs::{read_to_string, rename};
use std::path::{Path, PathBuf};
use thiserror::Error;

use sentinel_core::QuarantineManifest;
use crate::log::{get_sentinel_data_dir, log_operation};

#[derive(Error, Debug)]
pub enum RestoreError {
    #[error("Manifest for quarantine ID '{0}' not found.")]
    ManifestNotFound(String),
    #[error("Filesystem IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

pub struct RestoreManager {
    quarantine_root: PathBuf,
}

impl Default for RestoreManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RestoreManager {
    pub fn new() -> Self {
        let root = get_sentinel_data_dir().join("quarantine");
        Self { quarantine_root: root }
    }

    pub fn restore(&self, id: &str) -> Result<QuarantineManifest, RestoreError> {
        let target_dir = self.quarantine_root.join(id);
        let manifest_path = target_dir.join("quarantine-manifest.json");

        if !manifest_path.exists() {
            return Err(RestoreError::ManifestNotFound(id.to_string()));
        }

        let content = read_to_string(&manifest_path)?;
        let manifest: QuarantineManifest = serde_json::from_str(&content)?;
        let mut details = Vec::new();

        // 1. Move quarantined files back to original locations
        for file in &manifest.original_files {
            let q_path = Path::new(&file.quarantined_path);
            let orig_path = Path::new(&file.original_path);

            if q_path.exists() {
                if let Some(parent) = orig_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if rename(q_path, orig_path).is_ok() {
                    details.push(format!("Restored {} -> {}", q_path.display(), orig_path.display()));
                }
            }
        }

        // 2. Re-enable services
        for s in &manifest.disabled_services {
            #[cfg(target_os = "windows")]
            {
                let _ = std::process::Command::new("sc")
                    .args(["config", s, "start=", "auto"])
                    .output();
                details.push(format!("Re-enabled service {}", s));
            }
        }

        // Log operation
        let _ = log_operation("restore", &manifest.id, &manifest.name, true, details);

        // Delete manifest and directory
        let _ = std::fs::remove_file(manifest_path);
        let _ = std::fs::remove_dir_all(target_dir);

        Ok(manifest)
    }
}
