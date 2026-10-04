use sentinel_core::{Evidence, EvidenceData, EvidenceType};
use winreg::enums::*;
use winreg::RegKey;

use crate::{Collector, CollectorContext};

pub struct WindowsInstalledSoftwareCollector;

impl Collector for WindowsInstalledSoftwareCollector {
    fn name(&self) -> &'static str {
        "WindowsInstalledSoftwareCollector"
    }

    fn collect(&self, _ctx: &CollectorContext) -> Result<Vec<Evidence>, String> {
        let mut evidence = Vec::new();
        let uninstall_paths = [
            (HKEY_LOCAL_MACHINE, "HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (HKEY_LOCAL_MACHINE, "HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (HKEY_CURRENT_USER, "HKCU", r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        ];

        for (hive, hive_name, path) in uninstall_paths {
            let root = RegKey::predef(hive);
            if let Ok(key) = root.open_subkey_with_flags(path, KEY_READ) {
                for app_key_name in key.enum_keys().filter_map(Result::ok) {
                    if let Ok(app_key) = key.open_subkey_with_flags(&app_key_name, KEY_READ) {
                        let display_name: String = app_key.get_value("DisplayName").unwrap_or_default();
                        let uninstall_string: String = app_key.get_value("UninstallString").unwrap_or_default();
                        let system_component: u32 = app_key.get_value("SystemComponent").unwrap_or(0);
                        let install_location: String = app_key.get_value("InstallLocation").unwrap_or_default();

                        if !display_name.is_empty() {
                            let is_hidden = system_component == 1;
                            let desc = if is_hidden {
                                format!("Installed software (HIDDEN from Settings): {}", display_name)
                            } else {
                                format!("Installed software: {}", display_name)
                            };

                            let tech = format!(
                                "Key: {}\\{}\\{}\nDisplayName: {}\nUninstallString: {}\nSystemComponent: {}\nLocation: {}",
                                hive_name, path, app_key_name, display_name, uninstall_string, system_component, install_location
                            );

                            evidence.push(
                                Evidence::new(EvidenceType::KnownFileArtifact, self.name(), desc, tech)
                                    .with_data(EvidenceData::Generic {
                                        key: "InstalledSoftware".to_string(),
                                        value: format!("{}:{}", display_name, uninstall_string),
                                    }),
                            );
                        }
                    }
                }
            }
        }

        Ok(evidence)
    }
}
