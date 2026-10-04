use sentinel_core::{Evidence, EvidenceData, EvidenceType};
use std::process::Command;
use winreg::enums::*;
use winreg::RegKey;

use crate::{Collector, CollectorContext};

pub struct WindowsPersistenceCollector;

impl Collector for WindowsPersistenceCollector {
    fn name(&self) -> &'static str {
        "WindowsPersistenceCollector"
    }

    fn collect(&self, _ctx: &CollectorContext) -> Result<Vec<Evidence>, String> {
        let mut evidence = Vec::new();

        // 1. Scan Registry Run and RunOnce keys
        let run_hives = [
            (HKEY_LOCAL_MACHINE, "HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (HKEY_LOCAL_MACHINE, "HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (HKEY_LOCAL_MACHINE, "HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
            (HKEY_CURRENT_USER, "HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (HKEY_CURRENT_USER, "HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ];

        for (hive, hive_name, path) in run_hives {
            let root = RegKey::predef(hive);
            if let Ok(key) = root.open_subkey_with_flags(path, KEY_READ) {
                for (name, value) in key.enum_values().filter_map(Result::ok) {
                    let val_str = value.to_string();
                    let desc = format!("Registry Run key: {}\\{} -> {}", hive_name, name, val_str);
                    let tech = format!("Hive: {}\nPath: {}\nValue: {}\nCommand: {}", hive_name, path, name, val_str);

                    evidence.push(
                        Evidence::new(EvidenceType::RegistryRunKey, self.name(), desc, tech)
                            .with_data(EvidenceData::Registry {
                                hive: hive_name.to_string(),
                                path: path.to_string(),
                                value_name: Some(name),
                                value_data: Some(val_str),
                            }),
                    );
                }
            }
        }

        // 2. Scan Startup Folder
        if let Some(appdata) = dirs::config_dir() {
            let startup_dir = appdata.join(r"Microsoft\Windows\Start Menu\Programs\Startup");
            if startup_dir.exists() {
                if let Ok(entries) = std::fs::read_dir(startup_dir) {
                    for entry in entries.filter_map(Result::ok) {
                        let path = entry.path();
                        if path.is_file() {
                            let file_name = path.file_name().unwrap_or_default().to_string_lossy();
                            let desc = format!("Startup folder item: {}", file_name);
                            let tech = format!("Path: {}", path.display());

                            evidence.push(Evidence::new(
                                EvidenceType::StartupFolderItem,
                                self.name(),
                                desc,
                                tech,
                            ).with_data(EvidenceData::File {
                                path: path.display().to_string(),
                                sha256: None,
                                is_signed: None,
                            }));
                        }
                    }
                }
            }
        }

        // 3. Scan Scheduled Tasks
        if let Ok(output) = Command::new("schtasks").args(["/query", "/fo", "CSV", "/nh"]).output() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let parts: Vec<&str> = line.split(',').collect();
                if let Some(task_name) = parts.first() {
                    let cleaned = task_name.trim_matches('"');
                    if !cleaned.starts_with(r"\Microsoft") && !cleaned.is_empty() {
                        let desc = format!("User scheduled task: {}", cleaned);
                        evidence.push(Evidence::new(
                            EvidenceType::ScheduledTask,
                            self.name(),
                            desc,
                            line.to_string(),
                        ));
                    }
                }
            }
        }

        Ok(evidence)
    }
}
