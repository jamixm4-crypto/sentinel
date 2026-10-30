use chrono::Utc;
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, Write};
use std::path::Path;

use sentinel_core::{Evidence, EvidenceData, EvidenceType, Lang};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemSnapshot {
    pub timestamp: String,
    pub os: String,
    pub processes: Vec<SnapshotProcess>,
    pub services: Vec<SnapshotService>,
    pub autostart: Vec<SnapshotAutostart>,
    pub listening_ports: Vec<SnapshotPort>,
    pub browser_extensions: Vec<SnapshotExtension>,
    pub root_certificates: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SnapshotProcess {
    pub name: String,
    pub exe_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SnapshotService {
    pub name: String,
    pub display_name: Option<String>,
    pub binary_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SnapshotAutostart {
    pub location: String,
    pub name: String,
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SnapshotPort {
    pub protocol: String,
    pub port: u16,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SnapshotExtension {
    pub browser: String,
    pub id: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotDiffResult {
    pub baseline_timestamp: String,
    pub current_timestamp: String,
    pub new_processes: Vec<SnapshotProcess>,
    pub new_services: Vec<SnapshotService>,
    pub removed_services: Vec<SnapshotService>,
    pub new_autostart: Vec<SnapshotAutostart>,
    pub new_listening_ports: Vec<SnapshotPort>,
    pub new_extensions: Vec<SnapshotExtension>,
    pub new_root_certificates: Vec<String>,
}

impl SnapshotDiffResult {
    pub fn has_differences(&self) -> bool {
        !self.new_processes.is_empty()
            || !self.new_services.is_empty()
            || !self.removed_services.is_empty()
            || !self.new_autostart.is_empty()
            || !self.new_listening_ports.is_empty()
            || !self.new_extensions.is_empty()
            || !self.new_root_certificates.is_empty()
    }
}

pub fn create_snapshot(evidence: &[Evidence]) -> SystemSnapshot {
    let mut processes = HashSet::new();
    let mut services = HashSet::new();
    let mut autostart = HashSet::new();
    let mut listening_ports = HashSet::new();
    let mut browser_extensions = HashSet::new();
    let mut root_certificates = HashSet::new();

    for ev in evidence {
        match &ev.data {
            Some(EvidenceData::Process { name, exe_path, .. }) => {
                processes.insert(SnapshotProcess {
                    name: name.clone(),
                    exe_path: exe_path.clone(),
                });
            }
            Some(EvidenceData::Service { name, display_name, binary_path, .. }) => {
                services.insert(SnapshotService {
                    name: name.clone(),
                    display_name: display_name.clone(),
                    binary_path: binary_path.clone(),
                });
            }
            Some(EvidenceData::Registry { hive, path, value_name, value_data }) => {
                if ev.evidence_type == EvidenceType::RegistryRunKey {
                    autostart.insert(SnapshotAutostart {
                        location: format!(r"{}\{}", hive, path),
                        name: value_name.clone().unwrap_or_default(),
                        command: value_data.clone().unwrap_or_default(),
                    });
                }
            }
            Some(EvidenceData::Network { protocol, local_address, .. }) => {
                if let Some(pos) = local_address.rfind(':') {
                    if let Ok(port) = local_address[pos + 1..].parse::<u16>() {
                        listening_ports.insert(SnapshotPort {
                            protocol: protocol.clone(),
                            port,
                            address: local_address.clone(),
                        });
                    }
                }
            }
            Some(EvidenceData::BrowserExtension { browser, id, name, version, .. }) => {
                browser_extensions.insert(SnapshotExtension {
                    browser: browser.clone(),
                    id: id.clone(),
                    name: name.clone(),
                    version: version.clone(),
                });
            }
            _ => {
                if ev.evidence_type == EvidenceType::UntrustedRootCertificate {
                    root_certificates.insert(ev.description.clone());
                }
            }
        }
    }

    SystemSnapshot {
        timestamp: Utc::now().to_rfc3339(),
        os: std::env::consts::OS.to_string(),
        processes: processes.into_iter().collect(),
        services: services.into_iter().collect(),
        autostart: autostart.into_iter().collect(),
        listening_ports: listening_ports.into_iter().collect(),
        browser_extensions: browser_extensions.into_iter().collect(),
        root_certificates: root_certificates.into_iter().collect(),
    }
}

pub fn save_snapshot(snapshot: &SystemSnapshot, path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = File::create(path)?;
    let json = serde_json::to_string_pretty(snapshot)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

pub fn load_snapshot(path: &Path) -> std::io::Result<SystemSnapshot> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let snapshot = serde_json::from_reader(reader)?;
    Ok(snapshot)
}

pub fn compute_diff(baseline: &SystemSnapshot, current: &SystemSnapshot) -> SnapshotDiffResult {
    let base_proc: HashSet<_> = baseline.processes.iter().cloned().collect();
    let curr_proc: HashSet<_> = current.processes.iter().cloned().collect();
    let new_processes = curr_proc.difference(&base_proc).cloned().collect();

    let base_serv: HashSet<_> = baseline.services.iter().cloned().collect();
    let curr_serv: HashSet<_> = current.services.iter().cloned().collect();
    let new_services = curr_serv.difference(&base_serv).cloned().collect();
    let removed_services = base_serv.difference(&curr_serv).cloned().collect();

    let base_auto: HashSet<_> = baseline.autostart.iter().cloned().collect();
    let curr_auto: HashSet<_> = current.autostart.iter().cloned().collect();
    let new_autostart = curr_auto.difference(&base_auto).cloned().collect();

    let base_ports: HashSet<_> = baseline.listening_ports.iter().cloned().collect();
    let curr_ports: HashSet<_> = current.listening_ports.iter().cloned().collect();
    let new_listening_ports = curr_ports.difference(&base_ports).cloned().collect();

    let base_ext: HashSet<_> = baseline.browser_extensions.iter().cloned().collect();
    let curr_ext: HashSet<_> = current.browser_extensions.iter().cloned().collect();
    let new_extensions = curr_ext.difference(&base_ext).cloned().collect();

    let base_certs: HashSet<_> = baseline.root_certificates.iter().cloned().collect();
    let curr_certs: HashSet<_> = current.root_certificates.iter().cloned().collect();
    let new_root_certificates = curr_certs.difference(&base_certs).cloned().collect();

    SnapshotDiffResult {
        baseline_timestamp: baseline.timestamp.clone(),
        current_timestamp: current.timestamp.clone(),
        new_processes,
        new_services,
        removed_services,
        new_autostart,
        new_listening_ports,
        new_extensions,
        new_root_certificates,
    }
}

pub fn print_diff_summary(diff: &SnapshotDiffResult, lang: Lang) {
    println!();
    match lang {
        Lang::Ru => {
            println!("{}", "📊 РЕЗУЛЬТАТ ДИФФЕРЕНЦИАЛЬНОГО АУДИТА СИСТЕМЫ (SNAPSHOT DIFF)".bold().cyan());
            println!("Базовый снимок:   {}", diff.baseline_timestamp.dimmed());
            println!("Текущее состояние: {}", diff.current_timestamp.dimmed());
            println!("{}", "─".repeat(70).dimmed());

            if !diff.has_differences() {
                println!("{}", "✔ Изменений не обнаружено! Система полностью идентична базовому снимку.".bold().green());
                return;
            }

            if !diff.new_processes.is_empty() {
                println!("\n{} ({}):", "➕ Новые активные процессы".bold().yellow(), diff.new_processes.len());
                for p in &diff.new_processes {
                    println!("  • {} ({})", p.name.bold(), p.exe_path.as_deref().unwrap_or("неизвестный путь").dimmed());
                }
            }

            if !diff.new_services.is_empty() {
                println!("\n{} ({}):", "➕ Новые системные службы".bold().red(), diff.new_services.len());
                for s in &diff.new_services {
                    println!("  • {} [{}] ({})", s.name.bold(), s.display_name.as_deref().unwrap_or("").cyan(), s.binary_path.as_deref().unwrap_or("").dimmed());
                }
            }

            if !diff.removed_services.is_empty() {
                println!("\n{} ({}):", "➖ Удалённые/остановленные службы".bold().magenta(), diff.removed_services.len());
                for s in &diff.removed_services {
                    println!("  • {} ({})", s.name.bold(), s.display_name.as_deref().unwrap_or("").dimmed());
                }
            }

            if !diff.new_autostart.is_empty() {
                println!("\n{} ({}):", "➕ Новые точки автозагрузки (Run/Startup)".bold().red(), diff.new_autostart.len());
                for a in &diff.new_autostart {
                    println!("  • {} = {}", a.name.bold(), a.command.dimmed());
                }
            }

            if !diff.new_listening_ports.is_empty() {
                println!("\n{} ({}):", "➕ Новые открытые порты / сокеты".bold().yellow(), diff.new_listening_ports.len());
                for lp in &diff.new_listening_ports {
                    println!("  • {} {}", lp.protocol.cyan(), lp.address.bold());
                }
            }

            if !diff.new_extensions.is_empty() {
                println!("\n{} ({}):", "➕ Новые браузерные расширения".bold().yellow(), diff.new_extensions.len());
                for ext in &diff.new_extensions {
                    println!("  • [{}] {} (ID: {})", ext.browser.cyan(), ext.name.bold(), ext.id.dimmed());
                }
            }

            if !diff.new_root_certificates.is_empty() {
                println!("\n{} ({}):", "🚨 НОВЫЕ КОРНЕВЫЕ СЕРТИФИКАТЫ В ХРАНИЛИЩЕ ROOT".bold().red(), diff.new_root_certificates.len());
                for cert in &diff.new_root_certificates {
                    println!("  • {}", cert.bold().red());
                }
            }
        }
        Lang::En => {
            println!("{}", "📊 SYSTEM DIFFERENTIAL AUDIT REPORT (SNAPSHOT DIFF)".bold().cyan());
            println!("Baseline Snapshot: {}", diff.baseline_timestamp.dimmed());
            println!("Current State:     {}", diff.current_timestamp.dimmed());
            println!("{}", "─".repeat(70).dimmed());

            if !diff.has_differences() {
                println!("{}", "✔ No differences detected! System is identical to the baseline snapshot.".bold().green());
                return;
            }

            if !diff.new_processes.is_empty() {
                println!("\n{} ({}):", "➕ New Active Processes".bold().yellow(), diff.new_processes.len());
                for p in &diff.new_processes {
                    println!("  • {} ({})", p.name.bold(), p.exe_path.as_deref().unwrap_or("unknown path").dimmed());
                }
            }

            if !diff.new_services.is_empty() {
                println!("\n{} ({}):", "➕ New System Services".bold().red(), diff.new_services.len());
                for s in &diff.new_services {
                    println!("  • {} [{}] ({})", s.name.bold(), s.display_name.as_deref().unwrap_or("").cyan(), s.binary_path.as_deref().unwrap_or("").dimmed());
                }
            }

            if !diff.removed_services.is_empty() {
                println!("\n{} ({}):", "➖ Removed/Stopped Services".bold().magenta(), diff.removed_services.len());
                for s in &diff.removed_services {
                    println!("  • {} ({})", s.name.bold(), s.display_name.as_deref().unwrap_or("").dimmed());
                }
            }

            if !diff.new_autostart.is_empty() {
                println!("\n{} ({}):", "➕ New Autostart Persistence Entries".bold().red(), diff.new_autostart.len());
                for a in &diff.new_autostart {
                    println!("  • {} = {}", a.name.bold(), a.command.dimmed());
                }
            }

            if !diff.new_listening_ports.is_empty() {
                println!("\n{} ({}):", "➕ New Listening Ports / Sockets".bold().yellow(), diff.new_listening_ports.len());
                for lp in &diff.new_listening_ports {
                    println!("  • {} {}", lp.protocol.cyan(), lp.address.bold());
                }
            }

            if !diff.new_extensions.is_empty() {
                println!("\n{} ({}):", "➕ New Browser Extensions".bold().yellow(), diff.new_extensions.len());
                for ext in &diff.new_extensions {
                    println!("  • [{}] {} (ID: {})", ext.browser.cyan(), ext.name.bold(), ext.id.dimmed());
                }
            }

            if !diff.new_root_certificates.is_empty() {
                println!("\n{} ({}):", "🚨 NEW ROOT CERTIFICATES DETECTED IN ROOT STORE".bold().red(), diff.new_root_certificates.len());
                for cert in &diff.new_root_certificates {
                    println!("  • {}", cert.bold().red());
                }
            }
        }
    }
    println!();
}
