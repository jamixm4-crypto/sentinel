use sentinel_core::{Evidence, EvidenceData, EvidenceType};
use std::fs::read_to_string;
use std::process::Command;
use winreg::enums::*;
use winreg::RegKey;

use crate::{Collector, CollectorContext};

pub struct WindowsCertificatesCollector;

impl Collector for WindowsCertificatesCollector {
    fn name(&self) -> &'static str {
        "WindowsCertificatesCollector"
    }

    fn collect(&self, _ctx: &CollectorContext) -> Result<Vec<Evidence>, String> {
        let mut evidence = Vec::new();

        // 1. Check WinINet Proxy Settings
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        if let Ok(key) = hkcu.open_subkey_with_flags(
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            KEY_READ,
        ) {
            let proxy_enable: u32 = key.get_value("ProxyEnable").unwrap_or(0);
            let proxy_server: String = key.get_value("ProxyServer").unwrap_or_default();
            let autoconfig_url: String = key.get_value("AutoConfigURL").unwrap_or_default();

            if proxy_enable == 1 && !proxy_server.is_empty() {
                evidence.push(
                    Evidence::new(
                        EvidenceType::SystemProxySetting,
                        self.name(),
                        format!("Active system proxy redirect configured: {}", proxy_server),
                        format!("ProxyServer: {}\nProxyEnable: 1", proxy_server),
                    )
                    .with_data(EvidenceData::Generic {
                        key: "ProxyServer".to_string(),
                        value: proxy_server,
                    }),
                );
            }

            if !autoconfig_url.is_empty() {
                evidence.push(Evidence::new(
                    EvidenceType::SystemProxySetting,
                    self.name(),
                    format!("Proxy Auto-Config (PAC) script configured: {}", autoconfig_url),
                    format!("AutoConfigURL: {}", autoconfig_url),
                ));
            }
        }

        // 2. Check Hosts File
        let hosts_path = r"C:\Windows\System32\drivers\etc\hosts";
        if let Ok(content) = read_to_string(hosts_path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if !trimmed.starts_with('#') && !trimmed.is_empty() {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let ip = parts[0];
                        let domain = parts[1];
                        if (ip == "127.0.0.1" || ip == "0.0.0.0")
                            && (domain.contains("microsoft")
                                || domain.contains("virustotal")
                                || domain.contains("kaspersky")
                                || domain.contains("avast"))
                        {
                            evidence.push(Evidence::new(
                                EvidenceType::HostsFileTampering,
                                self.name(),
                                format!("Security domain sinkholed in hosts file: {} -> {}", domain, ip),
                                line.to_string(),
                            ));
                        }
                    }
                }
            }
        }

        // 3. Check for Suspicious Root Certificates via certutil
        if let Ok(output) = Command::new("certutil").args(["-store", "root"]).output() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let lower = line.to_lowercase();
                if lower.contains("subject:") && (lower.contains("teramind") || lower.contains("activtrak") || lower.contains("fiddler") || lower.contains("charles")) {
                    evidence.push(Evidence::new(
                        EvidenceType::UntrustedRootCertificate,
                        self.name(),
                        format!("Suspicious SSL MITM Root Certificate detected in store: {}", line.trim()),
                        text.to_string(),
                    ));
                }
            }
        }

        Ok(evidence)
    }
}
