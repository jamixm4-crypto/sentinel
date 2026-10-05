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

                        let is_suspicious_port = local.ends_with(":10050")  // Zabbix Agent
                            || local.ends_with(":10051")  // Zabbix Trapper
                            || local.ends_with(":9100")   // Prometheus node_exporter
                            || local.ends_with(":9182")   // Prometheus windows_exporter
                            || local.ends_with(":5666")   // Nagios NRPE
                            || local.ends_with(":5693")   // Nagios NCPA
                            || local.ends_with(":6556")   // Checkmk Agent
                            || local.ends_with(":19999")  // Netdata
                            || local.ends_with(":8089")   // Splunk
                            || local.ends_with(":5001")   // Datadog Agent
                            || local.ends_with(":1514")   // Wazuh
                            || local.ends_with(":1515")   // Wazuh
                            || local.ends_with(":5900")   // VNC
                            || local.ends_with(":5901")   // VNC
                            || local.ends_with(":5902")   // VNC
                            || local.ends_with(":3389")   // RDP
                            || local.ends_with(":7070")   // AnyDesk
                            || local.ends_with(":7906")   // Remcos / RAT
                            || local.ends_with(":21115")  // RustDesk
                            || local.ends_with(":21116")  // RustDesk
                            || local.ends_with(":21117"); // RustDesk

                        let is_remote_established = remote.map(|r| {
                            !r.starts_with("127.0.0.1:")
                                && !r.starts_with("0.0.0.0:")
                                && !r.starts_with("[::")
                                && !r.starts_with("*:")
                        }).unwrap_or(false);

                        if is_suspicious_port || is_remote_established {
                            let desc = if is_suspicious_port {
                                format!("Remote desktop or control port listening: {}", local)
                            } else {
                                format!("Active outbound network connection: {} -> {}", local, remote.unwrap_or(""))
                            };
                            let tech = format!("Protocol: {}, Local: {}, Remote: {:?}, PID: {:?}", proto, local, remote, pid);
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

            // Inspect Windows DNS Client Cache for recently resolved hostnames
            if let Ok(output) = Command::new("ipconfig").arg("/displaydns").output() {
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("Record Name") {
                        if let Some(domain_part) = trimmed.split(':').nth(1) {
                            let domain = domain_part.trim().to_lowercase();
                            if !domain.is_empty() && !domain.ends_with(".local") {
                                evidence.push(
                                    Evidence::new(
                                        EvidenceType::NetworkSocketListener,
                                        self.name(),
                                        format!("DNS Client Cache resolved host: {}", domain),
                                        format!("Queried domain in DNS cache: {}", domain),
                                    )
                                    .with_data(EvidenceData::Generic {
                                        key: "DnsCacheRecord".to_string(),
                                        value: domain,
                                    }),
                                );
                            }
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
