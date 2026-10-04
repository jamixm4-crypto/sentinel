use sentinel_core::{Evidence, EvidenceData, EvidenceType};
use std::process::Command;

use crate::{Collector, CollectorContext};

pub struct NetworkCollector;

impl Collector for NetworkCollector {
    fn name(&self) -> &'static str {
        "NetworkCollector"
    }

    fn collect(&self, _ctx: &CollectorContext) -> Result<Vec<Evidence>, String> {
        let mut evidence = Vec::new();

        #[cfg(target_os = "windows")]
        {
            if let Ok(output) = Command::new("netstat").args(["-ano"]).output() {
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines().skip(4) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        let proto = parts[0];
                        let local = parts[1];
                        let remote = parts.get(2).copied();
                        let pid_str = parts.last().unwrap_or(&"0");
                        let pid = pid_str.parse::<u32>().ok();

                        if local.contains(":5900")
                            || local.contains(":5901")
                            || local.contains(":3389")
                            || local.contains(":7070")
                            || local.contains(":7906")
                        {
                            let desc = format!("Suspicious remote desktop port listening: {}", local);
                            let tech = format!("Protocol: {}, Local: {}, PID: {:?}", proto, local, pid);
                            evidence.push(
                                Evidence::new(
                                    EvidenceType::NetworkSocketListener,
                                    self.name(),
                                    desc,
                                    tech,
                                )
                                .with_data(EvidenceData::Network {
                                    protocol: proto.to_string(),
                                    local_address: local.to_string(),
                                    remote_address: remote.map(|s| s.to_string()),
                                    pid,
                                }),
                            );
                        }
                    }
                }
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            // On Linux / macOS, run ss or netstat
            if let Ok(output) = Command::new("ss").args(["-tulnp"]).output() {
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 5 {
                        let local = parts[4];
                        if local.ends_with(":5900") || local.ends_with(":3389") || local.ends_with(":7906") {
                            evidence.push(Evidence::new(
                                EvidenceType::NetworkSocketListener,
                                self.name(),
                                format!("Remote access listener on {}", local),
                                line.to_string(),
                            ));
                        }
                    }
                }
            }
        }

        Ok(evidence)
    }
}
