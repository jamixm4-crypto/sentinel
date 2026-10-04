use sentinel_core::{Evidence, EvidenceData, EvidenceType};
use std::process::Command;

use crate::{Collector, CollectorContext};

pub struct MacosProfileCollector;

impl Collector for MacosProfileCollector {
    fn name(&self) -> &'static str {
        "MacosProfileCollector"
    }

    fn collect(&self, _ctx: &CollectorContext) -> Result<Vec<Evidence>, String> {
        let mut evidence = Vec::new();

        if let Ok(output) = Command::new("profiles").args(["-P"]).output() {
            let text = String::from_utf8_lossy(&output.stdout);
            if text.contains("attribute:") || text.contains("ProfileIdentifier:") {
                evidence.push(
                    Evidence::new(
                        EvidenceType::SecurityFrameworkClient,
                        self.name(),
                        "Enterprise MDM Configuration Profile detected on system",
                        text.to_string(),
                    )
                    .with_data(EvidenceData::Generic {
                        key: "ConfigurationProfile".to_string(),
                        value: "Enrolled".to_string(),
                    }),
                );
            }
        }

        Ok(evidence)
    }
}
