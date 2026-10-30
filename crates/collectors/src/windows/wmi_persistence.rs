use sentinel_core::{Evidence, EvidenceData, EvidenceType};
use std::process::Command;

use crate::{Collector, CollectorContext};

pub struct WindowsWmiPersistenceCollector;

impl Collector for WindowsWmiPersistenceCollector {
    fn name(&self) -> &'static str {
        "WindowsWmiPersistenceCollector"
    }

    fn collect(&self, _ctx: &CollectorContext) -> Result<Vec<Evidence>, String> {
        let mut evidence = Vec::new();

        // Query WMI Event Consumers via PowerShell without creating visible windows
        let ps_cmd = "Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue | Select-Object Name, CommandLineTemplate, ExecutablePath | ConvertTo-Json -Compress";

        if let Ok(output) = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd])
            .output()
        {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !text.is_empty() && text != "null" {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
                        let consumers = if let Some(arr) = val.as_array() {
                            arr.clone()
                        } else {
                            vec![val]
                        };

                        for c in consumers {
                            let c_name = c["Name"].as_str().unwrap_or("Unnamed WMI Consumer").to_string();
                            let cmd_tmpl = c["CommandLineTemplate"].as_str().unwrap_or("").to_string();
                            let exe_path = c["ExecutablePath"].as_str().unwrap_or("").to_string();

                            // Filter out standard benign SCCM / SCOM agents if applicable
                            if c_name.contains("SCX") || c_name.contains("BdeAfd") {
                                continue;
                            }

                            let desc = format!("WMI Event Consumer persistence detected: '{}'", c_name);
                            let tech = format!(
                                "Namespace: root/subscription\nClass: CommandLineEventConsumer\nName: {}\nCommand: {}\nExecutable: {}",
                                c_name, cmd_tmpl, exe_path
                            );

                            evidence.push(
                                Evidence::new(
                                    EvidenceType::WmiSubscription,
                                    self.name(),
                                    desc,
                                    tech,
                                )
                                .with_data(EvidenceData::Generic {
                                    key: "WmiEventConsumer".to_string(),
                                    value: format!("{} | {}", c_name, cmd_tmpl),
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
