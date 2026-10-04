use sentinel_core::{Evidence, EvidenceData, EvidenceType};
use winreg::enums::*;
use winreg::RegKey;

use crate::{Collector, CollectorContext};

pub struct WindowsDriversCollector;

impl Collector for WindowsDriversCollector {
    fn name(&self) -> &'static str {
        "WindowsDriversCollector"
    }

    fn collect(&self, _ctx: &CollectorContext) -> Result<Vec<Evidence>, String> {
        let mut evidence = Vec::new();
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let keyboard_class_path = r"SYSTEM\CurrentControlSet\Control\Class\{4D36E96B-E325-11CE-BFC1-08002BE10318}";

        if let Ok(key) = hklm.open_subkey_with_flags(keyboard_class_path, KEY_READ) {
            // Read UpperFilters
            if let Ok(upper_filters) = key.get_value::<Vec<String>, _>("UpperFilters") {
                for filter in &upper_filters {
                    let lower = filter.to_lowercase();
                    // kbdclass is the standard Windows keyboard driver. vmmouse is VMware.
                    if lower != "kbdclass" && lower != "vmmouse" && !lower.is_empty() {
                        let desc = format!("Anomalous keyboard UpperFilter driver installed: '{}'", filter);
                        let tech = format!(
                            "Class GUID: {{4D36E96B-E325-11CE-BFC1-08002BE10318}}\nUpperFilters: {:?}",
                            upper_filters
                        );

                        evidence.push(
                            Evidence::new(
                                EvidenceType::KeyboardFilterDriver,
                                self.name(),
                                desc,
                                tech,
                            )
                            .with_data(EvidenceData::Generic {
                                key: "KeyboardUpperFilter".to_string(),
                                value: filter.clone(),
                            }),
                        );
                    }
                }
            }

            // Read LowerFilters
            if let Ok(lower_filters) = key.get_value::<Vec<String>, _>("LowerFilters") {
                for filter in &lower_filters {
                    if !filter.is_empty() {
                        let desc = format!("Suspicious keyboard LowerFilter driver installed: '{}'", filter);
                        evidence.push(
                            Evidence::new(
                                EvidenceType::KeyboardFilterDriver,
                                self.name(),
                                desc,
                                format!("LowerFilters: {:?}", lower_filters),
                            )
                            .with_data(EvidenceData::Generic {
                                key: "KeyboardLowerFilter".to_string(),
                                value: filter.clone(),
                            }),
                        );
                    }
                }
            }
        }

        Ok(evidence)
    }
}
