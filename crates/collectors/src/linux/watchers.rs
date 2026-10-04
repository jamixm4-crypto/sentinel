use sentinel_core::{Evidence, EvidenceData, EvidenceType};
use std::fs::read_to_string;

use crate::{Collector, CollectorContext};

pub struct LinuxWatcherCollector;

impl Collector for LinuxWatcherCollector {
    fn name(&self) -> &'static str {
        "LinuxWatcherCollector"
    }

    fn collect(&self, _ctx: &CollectorContext) -> Result<Vec<Evidence>, String> {
        let mut evidence = Vec::new();

        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.filter_map(Result::ok) {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.chars().all(|c| c.is_ascii_digit()) {
                    let status_path = entry.path().join("status");
                    if let Ok(status) = read_to_string(status_path) {
                        for line in status.lines() {
                            if line.starts_with("TracerPid:") {
                                let parts: Vec<&str> = line.split_whitespace().collect();
                                if let Some(tracer_str) = parts.get(1) {
                                    if let Ok(tracer_pid) = tracer_str.parse::<u32>() {
                                        if tracer_pid > 0 {
                                            evidence.push(Evidence::new(
                                                EvidenceType::ProcessTracerPtrace,
                                                self.name(),
                                                format!(
                                                    "Process {} is actively being traced by PID {}",
                                                    name_str, tracer_pid
                                                ),
                                                line.to_string(),
                                            ).with_data(EvidenceData::Generic {
                                                key: "TracerPid".to_string(),
                                                value: tracer_str.to_string(),
                                            }));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(evidence)
    }
}
