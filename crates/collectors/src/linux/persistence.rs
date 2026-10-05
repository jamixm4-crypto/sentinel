use sentinel_core::{Evidence, EvidenceData, EvidenceType};
use std::path::Path;

use crate::{Collector, CollectorContext};

pub struct LinuxPersistenceCollector;

impl Collector for LinuxPersistenceCollector {
    fn name(&self) -> &'static str {
        "LinuxPersistenceCollector"
    }

    fn collect(&self, _ctx: &CollectorContext) -> Result<Vec<Evidence>, String> {
        let mut evidence = Vec::new();

        // 1. Check /etc/ld.so.preload
        let preload_path = Path::new("/etc/ld.so.preload");
        if preload_path.exists() {
            if let Ok(content) = std::fs::read_to_string(preload_path) {
                if !content.trim().is_empty() {
                    evidence.push(Evidence::new(
                        EvidenceType::KnownFileArtifact,
                        self.name(),
                        format!("Active /etc/ld.so.preload entries detected: {}", content.trim()),
                        content,
                    ));
                }
            }
        }

        // 2. Check XDG autostart (.desktop files)
        if let Some(home) = dirs::home_dir() {
            let autostart_dir = home.join(".config/autostart");
            if autostart_dir.exists() {
                if let Ok(entries) = std::fs::read_dir(autostart_dir) {
                    for entry in entries.filter_map(Result::ok) {
                        let path = entry.path();
                        if path.extension().and_then(|s| s.to_str()) == Some("desktop") {
                            evidence.push(Evidence::new(
                                EvidenceType::StartupFolderItem,
                                self.name(),
                                format!("User XDG autostart desktop entry: {}", path.display()),
                                std::fs::read_to_string(&path).unwrap_or_default(),
                            ));
                        }
                    }
                }
            }
        }

        // 3. Check systemd user services
        if let Some(home) = dirs::home_dir() {
            let systemd_user = home.join(".config/systemd/user");
            if systemd_user.exists() {
                if let Ok(entries) = std::fs::read_dir(systemd_user) {
                    for entry in entries.filter_map(Result::ok) {
                        let path = entry.path();
                        let unit_name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                        evidence.push(Evidence::new(
                            EvidenceType::SystemDaemonService,
                            self.name(),
                            format!("User systemd unit: {}", path.display()),
                            std::fs::read_to_string(&path).unwrap_or_default(),
                        ).with_data(EvidenceData::Service {
                            name: unit_name.trim_end_matches(".service").to_string(),
                            display_name: Some(unit_name),
                            binary_path: Some(path.display().to_string()),
                            start_type: Some("systemd-user".to_string()),
                        }));
                    }
                }
            }
        }

        // 4. Check system-wide systemd units
        let systemd_system = Path::new("/etc/systemd/system");
        if systemd_system.exists() {
            if let Ok(entries) = std::fs::read_dir(systemd_system) {
                for entry in entries.filter_map(Result::ok) {
                    let path = entry.path();
                    let unit_name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                    if unit_name.ends_with(".service") {
                        evidence.push(Evidence::new(
                            EvidenceType::SystemDaemonService,
                            self.name(),
                            format!("System-wide systemd service: {}", path.display()),
                            std::fs::read_to_string(&path).unwrap_or_default(),
                        ).with_data(EvidenceData::Service {
                            name: unit_name.trim_end_matches(".service").to_string(),
                            display_name: Some(unit_name),
                            binary_path: Some(path.display().to_string()),
                            start_type: Some("systemd-system".to_string()),
                        }));
                    }
                }
            }
        }

        Ok(evidence)
    }
}
