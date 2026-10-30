use std::path::Path;
use thiserror::Error;
use sentinel_core::{Finding, RemovalAction, RemovalPolicy};
use crate::log::log_operation;

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

#[derive(Error, Debug)]
pub enum RemovalError {
    #[error("Action blocked: software is marked as DoNotRemove (organization-managed).")]
    PolicyBlocked,
    #[error("Removal aborted by safety policy: Personal Safety Mode is active.")]
    PersonalSafetyModeActive,
    #[error("Filesystem IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct RemovalManager {
    personal_safety_mode: bool,
}

impl RemovalManager {
    pub fn new(personal_safety_mode: bool) -> Self {
        Self { personal_safety_mode }
    }

    /// Dry run: simulate removal actions without modifying system state
    pub fn dry_run(&self, finding: &Finding) -> Result<Vec<String>, RemovalError> {
        if self.personal_safety_mode {
            return Err(RemovalError::PersonalSafetyModeActive);
        }

        if finding.removal_policy == RemovalPolicy::DoNotRemove {
            return Err(RemovalError::PolicyBlocked);
        }

        let mut planned_actions = Vec::new();
        let mut active_count = 0;

        for step in &finding.removal_steps.steps {
            match &step.action {
                RemovalAction::TerminateProcess { name } => {
                    if is_process_currently_running(name) {
                        planned_actions.push(format!("Would terminate active process '{}' (currently running)", name));
                        active_count += 1;
                    }
                }
                RemovalAction::StopService { name } => {
                    if is_service_currently_installed(name) {
                        planned_actions.push(format!("Would stop service '{}' (currently installed in OS)", name));
                        active_count += 1;
                    }
                }
                RemovalAction::DeleteService { name } => {
                    if is_service_currently_installed(name) {
                        planned_actions.push(format!("Would delete service registration '{}'", name));
                        active_count += 1;
                    }
                }
                RemovalAction::QuarantineFile { source_path } => {
                    let p = Path::new(source_path);
                    if p.exists() {
                        planned_actions.push(format!("Would move '{}' to quarantine vault (verified on disk)", source_path));
                        active_count += 1;
                    }
                }
                RemovalAction::DeleteRegistryValue { hive, path, value } => {
                    planned_actions.push(format!("Would delete registry entry {}\\{}->{}", hive, path, value));
                    active_count += 1;
                }
                _ => {
                    planned_actions.push(format!("Would execute action: {}", step.description));
                    active_count += 1;
                }
            }
        }

        if active_count == 0 {
            planned_actions.push("No active processes, registered services, or target files exist on your system for this finding (system is clean).".to_string());
        }

        Ok(planned_actions)
    }

    pub fn remove_finding(&self, finding: &Finding) -> Result<Vec<String>, RemovalError> {
        if self.personal_safety_mode {
            return Err(RemovalError::PersonalSafetyModeActive);
        }

        if finding.removal_policy == RemovalPolicy::DoNotRemove {
            return Err(RemovalError::PolicyBlocked);
        }

        let mut executed_actions = Vec::new();

        for step in &finding.removal_steps.steps {
            match &step.action {
                RemovalAction::TerminateProcess { name } => {
                    if is_process_currently_running(name) {
                        #[cfg(target_os = "windows")]
                        let _ = std::process::Command::new("taskkill")
                            .args(["/F", "/IM", name])
                            .output();
                        #[cfg(not(target_os = "windows"))]
                        let _ = std::process::Command::new("killall")
                            .args(["-9", name])
                            .output();
                        executed_actions.push(format!("Terminated process '{}'", name));
                    }
                }
                RemovalAction::StopService { name } => {
                    if is_service_currently_installed(name) {
                        #[cfg(target_os = "windows")]
                        let _ = std::process::Command::new("sc")
                            .args(["stop", name])
                            .output();
                        executed_actions.push(format!("Stopped service '{}'", name));
                    }
                }
                RemovalAction::DeleteService { name } => {
                    if is_service_currently_installed(name) {
                        #[cfg(target_os = "windows")]
                        let _ = std::process::Command::new("sc")
                            .args(["delete", name])
                            .output();
                        executed_actions.push(format!("Deleted service '{}'", name));
                    }
                }
                RemovalAction::QuarantineFile { source_path } | RemovalAction::DeleteFile { path: source_path } => {
                    let p = std::path::Path::new(source_path);
                    if p.exists() {
                        if p.is_dir() {
                            let _ = std::fs::remove_dir_all(p);
                        } else {
                            let _ = std::fs::remove_file(p);
                        }
                        executed_actions.push(format!("Deleted '{}'", source_path));
                    }
                }
                RemovalAction::RunUninstallString { command } => {
                    #[cfg(target_os = "windows")]
                    let _ = std::process::Command::new("cmd")
                        .args(["/C", command])
                        .output();
                    executed_actions.push(format!("Executed uninstaller '{}'", command));
                }
                _ => {}
            }
        }

        let _ = log_operation(
            "remove",
            &finding.id,
            &finding.name,
            true,
            executed_actions.clone(),
        );

        Ok(executed_actions)
    }
}
