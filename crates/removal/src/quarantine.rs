use chrono::Utc;
use sha2::{Digest, Sha256};
use std::fs::{create_dir_all, rename, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

use sentinel_core::{Finding, QuarantineManifest, QuarantinedFileEntry, RemovalPolicy};

use crate::log::{get_sentinel_data_dir, log_operation};

#[derive(Error, Debug)]
pub enum QuarantineError {
    #[error("Action blocked: this software is managed by your organization and cannot be quarantined.")]
    PolicyBlocked,
    #[error("Quarantine aborted by safety policy: Personal Safety Mode is active to prevent alerting monitors.")]
    PersonalSafetyModeActive,
    #[error("Target finding {0} has no removable paths or components.")]
    NoRemovableComponents(String),
    #[error("Filesystem IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

fn is_process_currently_running(name: &str) -> bool {
    let mut sys = sysinfo::System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All);
    let target_lower = name.to_lowercase();
    let target_trimmed = target_lower.trim_end_matches(".exe");
    for (_pid, proc) in sys.processes() {
        let p_name = proc.name().to_string_lossy().to_lowercase();
        let p_trimmed = p_name.trim_end_matches(".exe");
        if p_name == target_lower || p_trimmed == target_trimmed {
            return true;
        }
    }
    false
}

fn is_service_currently_installed(name: &str) -> bool {
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let path = format!(r"SYSTEM\CurrentControlSet\Services\{}", name);
        hklm.open_subkey(&path).is_ok()
    }
    #[cfg(target_os = "linux")]
    {
        Path::new(&format!("/etc/systemd/system/{}", name)).exists()
            || Path::new(&format!("/lib/systemd/system/{}", name)).exists()
            || Path::new(&format!("/etc/systemd/system/{}.service", name)).exists()
            || Path::new(&format!("/lib/systemd/system/{}.service", name)).exists()
    }
    #[cfg(target_os = "macos")]
    {
        Path::new(&format!("/Library/LaunchDaemons/{}.plist", name)).exists()
            || Path::new(&format!("/Library/LaunchAgents/{}.plist", name)).exists()
    }
}

pub struct QuarantineManager {
    quarantine_root: PathBuf,
    personal_safety_mode: bool,
}

impl Default for QuarantineManager {
    fn default() -> Self {
        Self::new(false)
    }
}

impl QuarantineManager {
    pub fn new(personal_safety_mode: bool) -> Self {
        let root = get_sentinel_data_dir().join("quarantine");
        Self {
            quarantine_root: root,
            personal_safety_mode,
        }
    }

    /// Dry run: simulate quarantine without terminating processes or moving files
    pub fn dry_run(&self, finding: &Finding) -> Result<Vec<String>, QuarantineError> {
        if self.personal_safety_mode {
            return Err(QuarantineError::PersonalSafetyModeActive);
        }
        if finding.removal_policy == RemovalPolicy::DoNotRemove {
            return Err(QuarantineError::PolicyBlocked);
        }

        let mut actions = Vec::new();
        let mut active_count = 0;

        for step in &finding.removal_steps.steps {
            match &step.action {
                sentinel_core::RemovalAction::TerminateProcess { name } => {
                    if is_process_currently_running(name) {
                        actions.push(format!("Would terminate active process '{}' (currently running)", name));
                        active_count += 1;
                    }
                }
                sentinel_core::RemovalAction::StopService { name } => {
                    if is_service_currently_installed(name) {
                        actions.push(format!("Would stop service '{}' (currently installed in OS)", name));
                        active_count += 1;
                    }
                }
                sentinel_core::RemovalAction::DeleteService { name } => {
                    if is_service_currently_installed(name) {
                        actions.push(format!("Would delete service registration '{}'", name));
                        active_count += 1;
                    }
                }
                sentinel_core::RemovalAction::QuarantineFile { source_path } => {
                    let p = Path::new(source_path);
                    if p.exists() {
                        actions.push(format!("Would move file '{}' to quarantine vault (verified on disk)", source_path));
                        active_count += 1;
                    }
                }
                sentinel_core::RemovalAction::DeleteRegistryValue { hive, path, value } => {
                    actions.push(format!("Would delete registry entry {}\\{}->{}", hive, path, value));
                    active_count += 1;
                }
                _ => {
                    actions.push(format!("Would execute action: {}", step.description));
                    active_count += 1;
                }
            }
        }

        if active_count == 0 {
            actions.push("No active processes, registered services, or target files exist on your system for this finding (system is clean).".to_string());
        }

        Ok(actions)
    }

    /// Quarantine a finding safely and reversibly
    pub fn quarantine(&self, finding: &Finding) -> Result<QuarantineManifest, QuarantineError> {
        if self.personal_safety_mode {
            return Err(QuarantineError::PersonalSafetyModeActive);
        }

        if finding.removal_policy == RemovalPolicy::DoNotRemove {
            return Err(QuarantineError::PolicyBlocked);
        }

        let target_dir = self.quarantine_root.join(&finding.id);
        create_dir_all(&target_dir)?;

        let mut quarantined_files = Vec::new();
        let mut details = Vec::new();

        // 1. Terminate running processes
        for step in &finding.removal_steps.steps {
            if let sentinel_core::RemovalAction::TerminateProcess { name } = &step.action {
                if is_process_currently_running(name) {
                    #[cfg(target_os = "windows")]
                    {
                        let _ = std::process::Command::new("taskkill")
                            .args(["/F", "/IM", name])
                            .output();
                        details.push(format!("Terminated process {}", name));
                    }
                    #[cfg(not(target_os = "windows"))]
                    {
                        let _ = std::process::Command::new("killall")
                            .args(["-9", name])
                            .output();
                        details.push(format!("Terminated process {}", name));
                    }
                }
            }
        }

        // 2. Stop and disable services
        for step in &finding.removal_steps.steps {
            if let sentinel_core::RemovalAction::StopService { name } = &step.action {
                if is_service_currently_installed(name) {
                    #[cfg(target_os = "windows")]
                    {
                        let _ = std::process::Command::new("sc")
                            .args(["stop", name])
                            .output();
                        let _ = std::process::Command::new("sc")
                            .args(["config", name, "start=", "disabled"])
                            .output();
                        details.push(format!("Disabled service {}", name));
                    }
                }
            }
        }

        // 3. Move files to quarantine directory
        for step in &finding.removal_steps.steps {
            if let sentinel_core::RemovalAction::QuarantineFile { source_path } = &step.action {
                let p = Path::new(source_path);
                if p.exists() {
                    let file_name = p.file_name().unwrap_or_default();
                    let dest_path = target_dir.join(file_name);

                    // Compute sha256 before moving
                    let (sha256, size) = compute_file_sha256(p).unwrap_or_default();

                    if rename(p, &dest_path).is_ok() {
                        quarantined_files.push(QuarantinedFileEntry {
                            original_path: source_path.clone(),
                            quarantined_path: dest_path.display().to_string(),
                            sha256,
                            file_size: size,
                        });
                        details.push(format!("Moved {} to quarantine", source_path));
                    }
                }
            }
        }

        let manifest = QuarantineManifest {
            id: finding.id.clone(),
            finding_id: finding.id.clone(),
            rule_id: finding.rule_id.clone(),
            name: finding.name.clone(),
            timestamp: Utc::now().to_rfc3339(),
            original_files: quarantined_files,
            disabled_registry_values: Vec::new(),
            disabled_services: Vec::new(),
            disabled_tasks: Vec::new(),
            notes: format!("Quarantined by Sentinel: {}", finding.name),
        };

        // Save manifest in target directory
        let manifest_path = target_dir.join("quarantine-manifest.json");
        let manifest_json = serde_json::to_string_pretty(&manifest)?;
        let mut file = File::create(manifest_path)?;
        file.write_all(manifest_json.as_bytes())?;

        // Log operation
        let _ = log_operation("quarantine", &finding.id, &finding.name, true, details);

        Ok(manifest)
    }
}

fn compute_file_sha256(path: &Path) -> std::io::Result<(String, u64)> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    let mut total_size = 0u64;

    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        total_size += count as u64;
    }

    Ok((hex::encode(hasher.finalize()), total_size))
}
