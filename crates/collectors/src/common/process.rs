use sysinfo::System;
use sentinel_core::{Evidence, EvidenceData, EvidenceType};

use crate::{Collector, CollectorContext};

pub struct ProcessCollector;

impl Collector for ProcessCollector {
    fn name(&self) -> &'static str {
        "ProcessCollector"
    }

    fn collect(&self, _ctx: &CollectorContext) -> Result<Vec<Evidence>, String> {
        let mut sys = System::new_all();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All);

        let mut evidence = Vec::new();

        for (pid, proc) in sys.processes() {
            let name = proc.name().to_string_lossy().to_string();
            let exe_path = proc.exe().map(|p| p.display().to_string());
            let cmdline = Some(
                proc.cmd()
                    .iter()
                    .map(|s| s.to_string_lossy().to_string())
                    .collect::<Vec<_>>()
                    .join(" "),
            );

            let desc = format!("Active process: {} (PID: {})", name, pid.as_u32());
            let tech = format!(
                "Path: {}\nCommandLine: {}",
                exe_path.as_deref().unwrap_or("N/A"),
                cmdline.as_deref().unwrap_or("N/A")
            );

            evidence.push(
                Evidence::new(EvidenceType::ActiveProcess, self.name(), desc, tech).with_data(
                    EvidenceData::Process {
                        pid: pid.as_u32(),
                        name,
                        exe_path,
                        command_line: cmdline,
                    },
                ),
            );
        }

        Ok(evidence)
    }
}
