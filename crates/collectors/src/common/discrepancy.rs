use sentinel_core::{Evidence, EvidenceData, EvidenceType};
use std::collections::HashSet;
use sysinfo::System;

use crate::{Collector, CollectorContext};

pub struct ProcessDiscrepancyCollector;

impl Collector for ProcessDiscrepancyCollector {
    fn name(&self) -> &'static str {
        "ProcessDiscrepancyCollector"
    }

    fn collect(&self, _ctx: &CollectorContext) -> Result<Vec<Evidence>, String> {
        let mut evidence = Vec::new();

        // 1. Gather primary processes using sysinfo (NtQuerySystemInformation / sysfs)
        let mut sys = System::new_all();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All);

        let sys_pids: HashSet<u32> = sys.processes().keys().map(|p| p.as_u32()).collect();

        // 2. Gather secondary processes using native OS tools (tasklist on Windows, ps on Unix)
        let secondary_pids = get_secondary_process_pids();

        if secondary_pids.is_empty() {
            return Ok(evidence);
        }

        // Compare: processes visible in secondary API but missing from primary API (Hidden from NtQuery/sysinfo)
        for &pid in &secondary_pids {
            // Ignore system idle / zero PID and secure system PIDs
            if pid <= 4 {
                continue;
            }

            if !sys_pids.contains(&pid) {
                evidence.push(
                    Evidence::new(
                        EvidenceType::HiddenProcessDiscrepancy,
                        self.name(),
                        format!("Process discrepancy detected: PID {} exists in system API but was omitted from primary process table", pid),
                        format!("PID: {}\nDiscrepancy: Visible in secondary query, hidden in NtQuery/sysinfo.\nPotential Rootkit or DKOM process hiding.", pid),
                    ).with_data(EvidenceData::ProcessDiscrepancy {
                        pid,
                        detected_in: "PSAPI / Tasklist".to_string(),
                        missing_from: "NtQuerySystemInformation / Sysinfo".to_string(),
                        details: format!("Process with PID {} appears unlinked from standard process enumeration", pid),
                    })
                );
            }
        }

        Ok(evidence)
    }
}

fn get_secondary_process_pids() -> HashSet<u32> {
    let mut pids = HashSet::new();

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("tasklist")
            .args(["/fo", "csv", "/nh"])
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                // CSV line format: "Image Name","PID","Session Name","Session#","Mem Usage"
                let parts: Vec<&str> = line.split(',').collect();
                if parts.len() >= 2 {
                    let pid_str = parts[1].trim_matches('"').trim();
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        pids.insert(pid);
                    }
                }
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        // On Linux / macOS, read /proc entries or ps -A -o pid=
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.filter_map(Result::ok) {
                if let Ok(file_name) = entry.file_name().into_string() {
                    if let Ok(pid) = file_name.parse::<u32>() {
                        pids.insert(pid);
                    }
                }
            }
        } else if let Ok(output) = std::process::Command::new("ps").args(["-A", "-o", "pid="]).output() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                if let Ok(pid) = line.trim().parse::<u32>() {
                    pids.insert(pid);
                }
            }
        }
    }

    pids
}
