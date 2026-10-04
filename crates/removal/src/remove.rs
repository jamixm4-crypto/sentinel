use thiserror::Error;
use sentinel_core::{Finding, RemovalAction, RemovalPolicy};
use crate::log::log_operation;

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
                RemovalAction::StopService { name } => {
                    #[cfg(target_os = "windows")]
                    let _ = std::process::Command::new("sc")
                        .args(["stop", name])
                        .output();
                    executed_actions.push(format!("Stopped service '{}'", name));
                }
                RemovalAction::DeleteService { name } => {
                    #[cfg(target_os = "windows")]
                    let _ = std::process::Command::new("sc")
                        .args(["delete", name])
                        .output();
                    executed_actions.push(format!("Deleted service '{}'", name));
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
