use sentinel_core::{Evidence, EvidenceData, EvidenceType};
use std::collections::HashSet;
use winreg::enums::*;
use winreg::RegKey;

use crate::{Collector, CollectorContext};

pub struct WindowsUsbHidCollector;

impl Collector for WindowsUsbHidCollector {
    fn name(&self) -> &'static str {
        "WindowsUsbHidCollector"
    }

    fn collect(&self, _ctx: &CollectorContext) -> Result<Vec<Evidence>, String> {
        let mut evidence = Vec::new();
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let hid_enum_path = r"SYSTEM\CurrentControlSet\Enum\HID";

        let hid_key = match hklm.open_subkey_with_flags(hid_enum_path, KEY_READ) {
            Ok(k) => k,
            Err(_) => return Ok(evidence),
        };

        // Known hardware keyloggers, BadUSB boards, and keystroke injection microcontroller VIDs
        let suspicious_vids = [
            ("16c0", "Teensy / PJRC Microcontroller HID Device (Potential BadUSB / Keylogger)"),
            ("05df", "Digispark ATtiny85 Virtual USB Keyboard (Potential Keystroke Injector)"),
            ("1d50", "OpenMoko / Hak5 Key Croc / Rubber Ducky Hardware Keylogger"),
            ("2341", "Arduino Leonardo/Micro Emulating USB Keyboard"),
            ("1b4f", "SparkFun Pro Micro Emulating USB Keyboard"),
            ("2e8a", "Raspberry Pi Pico (RP2040) Emulating HID Keyboard"),
            ("cafe", "Raspberry Pi / CircuitPython Emulating HID Keyboard"),
        ];

        let mut keyboard_devices = HashSet::new();

        for dev_name in hid_key.enum_keys().filter_map(Result::ok) {
            let dev_lower = dev_name.to_lowercase();
            if let Ok(dev_key) = hid_key.open_subkey_with_flags(&dev_name, KEY_READ) {
                for instance_name in dev_key.enum_keys().filter_map(Result::ok) {
                    if let Ok(inst_key) = dev_key.open_subkey_with_flags(&instance_name, KEY_READ) {
                        let class_guid: String = inst_key.get_value("ClassGUID").unwrap_or_default();
                        let service: String = inst_key.get_value("Service").unwrap_or_default();
                        let desc: String = inst_key.get_value("DeviceDesc").unwrap_or_else(|_| "HID Device".to_string());
                        let hw_id: String = inst_key.get_value::<Vec<String>, _>("HardwareID")
                            .map(|v| v.join(", "))
                            .unwrap_or_default();

                        // Check if device is configured as a Keyboard ({4D36E96B-E325-11CE-BFC1-08002BE10318})
                        let is_keyboard = class_guid.to_lowercase() == "{4d36e96b-e325-11ce-bfc1-08002be10318}"
                            || service.to_lowercase() == "kbdhid";

                        if is_keyboard {
                            keyboard_devices.insert(dev_name.clone());

                            // Check against suspicious hardware VID signatures
                            for (vid, threat_name) in &suspicious_vids {
                                if dev_lower.contains(&format!("vid_{}", vid)) {
                                    evidence.push(
                                        Evidence::new(
                                            EvidenceType::HardwareKeylogger,
                                            self.name(),
                                            format!("Suspicious hardware keyboard device detected: {} ({})", threat_name, dev_name),
                                            format!("DeviceDesc: {}\nHardwareID: {}\nInstance: {}\\{}", desc, hw_id, dev_name, instance_name),
                                        ).with_data(EvidenceData::HardwareDevice {
                                            device_name: desc.clone(),
                                            hardware_id: hw_id.clone(),
                                            device_type: "USB HID Keyboard".to_string(),
                                            is_suspicious: true,
                                        })
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        // Anomaly heuristic: excessive number of physical keyboards attached concurrently
        if keyboard_devices.len() >= 3 {
            evidence.push(
                Evidence::new(
                    EvidenceType::HardwareKeylogger,
                    self.name(),
                    format!("Anomalous count of active keyboard interfaces detected ({} physical keyboards)", keyboard_devices.len()),
                    format!("Connected keyboard device classes: {:?}", keyboard_devices),
                ).with_data(EvidenceData::Generic {
                    key: "MultipleKeyboardsAnomaly".to_string(),
                    value: format!("Active keyboards count: {}", keyboard_devices.len()),
                })
            );
        }

        Ok(evidence)
    }
}
