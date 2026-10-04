use sentinel_core::{Evidence, EvidenceType};
use std::process::Command;

use crate::{Collector, CollectorContext};

pub struct LinuxInputCollector;

impl Collector for LinuxInputCollector {
    fn name(&self) -> &'static str {
        "LinuxInputCollector"
    }

    fn collect(&self, _ctx: &CollectorContext) -> Result<Vec<Evidence>, String> {
        let mut evidence = Vec::new();

        // Check PipeWire active screen capture streams via pw-dump
        if let Ok(output) = Command::new("pw-dump").output() {
            let text = String::from_utf8_lossy(&output.stdout);
            if text.contains("Stream/Input/Video") {
                evidence.push(Evidence::new(
                    EvidenceType::ScreenCaptureApi,
                    self.name(),
                    "Active Wayland / PipeWire video stream detected (screen recording/sharing)",
                    "PipeWire node media.class is 'Stream/Input/Video'",
                ));
            }
        }

        Ok(evidence)
    }
}
