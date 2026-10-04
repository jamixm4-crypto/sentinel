use serde::{Deserialize, Serialize};

/// Privilege level under which Sentinel is executing
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PrivilegeLevel {
    /// Standard non-administrative user
    StandardUser,
    /// Elevated administrator on Windows, root on Linux/macOS
    ElevatedAdmin,
}

impl PrivilegeLevel {
    pub fn is_elevated(&self) -> bool {
        matches!(self, Self::ElevatedAdmin)
    }

    pub fn detect() -> Self {
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            let output = Command::new("net")
                .arg("session")
                .output();
            if let Ok(out) = output {
                if out.status.success() {
                    return Self::ElevatedAdmin;
                }
            }
            Self::StandardUser
        }
        #[cfg(not(target_os = "windows"))]
        {
            unsafe {
                if libc::geteuid() == 0 {
                    Self::ElevatedAdmin
                } else {
                    Self::StandardUser
                }
            }
        }
    }
}

/// Information about the current operating system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformInfo {
    pub os_name: String,
    pub os_version: String,
    pub architecture: String,
    pub hostname: String,
    pub privilege_level: PrivilegeLevel,
    pub is_domain_joined: bool,
    pub has_mdm_profile: bool,
}

impl PlatformInfo {
    pub fn current() -> Self {
        let privilege_level = PrivilegeLevel::detect();
        let os_name = std::env::consts::OS.to_string();
        let architecture = std::env::consts::ARCH.to_string();
        
        let hostname = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "localhost".to_string());

        let os_version = if cfg!(target_os = "windows") {
            "Windows 10/11".to_string()
        } else if cfg!(target_os = "linux") {
            "Linux".to_string()
        } else if cfg!(target_os = "macos") {
            "macOS".to_string()
        } else {
            "Unknown".to_string()
        };

        Self {
            os_name,
            os_version,
            architecture,
            hostname,
            privilege_level,
            is_domain_joined: false,
            has_mdm_profile: false,
        }
    }
}

/// Reason a detection check was skipped
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SkipReason {
    InsufficientPrivileges { required: String },
    UnsupportedOperatingSystem { os: String },
    TimeoutReached { duration_secs: u64 },
    SubsystemUnavailable { reason: String },
}

/// Record of an omitted or skipped check for transparency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedCheck {
    pub collector: String,
    pub description: String,
    pub reason: SkipReason,
}
