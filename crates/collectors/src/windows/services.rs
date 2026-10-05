use sentinel_core::{Evidence, EvidenceData, EvidenceType};
use winreg::enums::*;
use winreg::RegKey;

use crate::{Collector, CollectorContext};

pub struct WindowsServicesCollector;

impl Collector for WindowsServicesCollector {
    fn name(&self) -> &'static str {
        "WindowsServicesCollector"
    }

    fn collect(&self, _ctx: &CollectorContext) -> Result<Vec<Evidence>, String> {
        let mut evidence = Vec::new();
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let services_path = r"SYSTEM\CurrentControlSet\Services";

        if let Ok(services_root) = hklm.open_subkey_with_flags(services_path, KEY_READ) {
            for service_name in services_root.enum_keys().filter_map(Result::ok) {
                if let Ok(svc_key) = services_root.open_subkey_with_flags(&service_name, KEY_READ) {
                    let image_path: String = svc_key.get_value("ImagePath").unwrap_or_default();
                    let display_name: String = svc_key.get_value("DisplayName").unwrap_or_default();
                    let description: String = svc_key.get_value("Description").unwrap_or_default();
                    let start_val: u32 = svc_key.get_value("Start").unwrap_or(3);
                    let svc_type: u32 = svc_key.get_value("Type").unwrap_or(0);

                    // Skip standard kernel drivers (*.sys in system32\drivers) unless specifically named
                    let img_lower = image_path.to_lowercase();
                    let is_standard_sys_driver = (svc_type == 1 || svc_type == 2)
                        && (img_lower.ends_with(".sys") || img_lower.contains(r"system32\drivers\"));

                    if is_standard_sys_driver && !img_lower.contains("spy") && !img_lower.contains("mon") {
                        continue;
                    }

                    // Extract binary path from ImagePath (strip arguments, quotes, prefix)
                    let clean_bin = extract_binary_path(&image_path);

                    let start_str = match start_val {
                        0 => "Boot",
                        1 => "System",
                        2 => "Automatic",
                        3 => "Manual",
                        4 => "Disabled",
                        _ => "Unknown",
                    };

                    let title = if !display_name.is_empty() {
                        &display_name
                    } else {
                        &service_name
                    };

                    let desc = format!("Windows Service: '{}' ({}) [Start: {}]", title, service_name, start_str);
                    let tech = format!(
                        "ServiceName: {}\nDisplayName: {}\nImagePath: {}\nBinaryPath: {}\nStart: {} ({})\nDescription: {}",
                        service_name, display_name, image_path, clean_bin, start_val, start_str, description
                    );

                    evidence.push(
                        Evidence::new(EvidenceType::SystemDaemonService, self.name(), desc, tech)
                            .with_data(EvidenceData::Service {
                                name: service_name.clone(),
                                display_name: if display_name.is_empty() { None } else { Some(display_name) },
                                binary_path: if clean_bin.is_empty() { None } else { Some(clean_bin) },
                                start_type: Some(start_str.to_string()),
                            }),
                    );
                }
            }
        }

        Ok(evidence)
    }
}

/// Helper to parse the executable file path from ImagePath string
fn extract_binary_path(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    // Expand %SystemRoot% and %windir%
    let expanded = trimmed
        .replace("%SystemRoot%", "C:\\Windows")
        .replace("%systemroot%", "C:\\Windows")
        .replace("%windir%", "C:\\Windows")
        .replace("%WINDIR%", "C:\\Windows")
        .replace("%ProgramFiles%", "C:\\Program Files")
        .replace("%ProgramFiles(x86)%", "C:\\Program Files (x86)")
        .replace("%ProgramData%", "C:\\ProgramData")
        .replace("\\??\\", "");

    if expanded.starts_with('"') {
        if let Some(end_quote) = expanded[1..].find('"') {
            return expanded[1..=end_quote].to_string();
        }
    }

    // Otherwise split by space or .exe
    if let Some(exe_idx) = expanded.to_lowercase().find(".exe") {
        return expanded[..exe_idx + 4].to_string();
    }

    expanded.split_whitespace().next().unwrap_or("").to_string()
}
