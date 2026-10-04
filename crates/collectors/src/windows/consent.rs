use sentinel_core::{Evidence, EvidenceData, EvidenceType};
use winreg::enums::*;
use winreg::RegKey;

use crate::{Collector, CollectorContext};

pub struct WindowsConsentStoreCollector;

impl Collector for WindowsConsentStoreCollector {
    fn name(&self) -> &'static str {
        "WindowsConsentStoreCollector"
    }

    fn collect(&self, _ctx: &CollectorContext) -> Result<Vec<Evidence>, String> {
        let mut evidence = Vec::new();
        let capabilities = ["webcam", "microphone", "graphicsCaptureProgrammatic"];

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);

        for cap in &capabilities {
            let path = format!(
                r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\{}\NonPackaged",
                cap
            );

            if let Ok(key) = hkcu.open_subkey_with_flags(&path, KEY_READ) {
                for app_key_name in key.enum_keys().filter_map(Result::ok) {
                    if let Ok(app_sub) = key.open_subkey_with_flags(&app_key_name, KEY_READ) {
                        let original_path = app_key_name.replace('#', "\\");
                        let start_time: u64 = app_sub.get_value("LastUsedTimeStart").unwrap_or(0);
                        let stop_time: u64 = app_sub.get_value("LastUsedTimeStop").unwrap_or(0);

                        let is_currently_active = start_time > 0 && (stop_time == 0 || start_time > stop_time);

                        if is_currently_active {
                            let desc = format!(
                                "ACTIVE hardware sensor access: '{}' is currently using {}",
                                original_path, cap
                            );
                            let tech = format!(
                                "Capability: {}\nApplication: {}\nStart FILETIME: {}\nStop FILETIME: {}",
                                cap, original_path, start_time, stop_time
                            );

                            evidence.push(
                                Evidence::new(EvidenceType::ScreenCaptureApi, self.name(), desc, tech)
                                    .with_data(EvidenceData::Generic {
                                        key: "ConsentStoreActive".to_string(),
                                        value: format!("{}:{}", cap, original_path),
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
