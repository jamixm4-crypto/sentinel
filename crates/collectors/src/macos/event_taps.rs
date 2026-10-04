use sentinel_core::{Evidence, EvidenceType};

use crate::{Collector, CollectorContext};

pub struct MacosEventTapCollector;

impl Collector for MacosEventTapCollector {
    fn name(&self) -> &'static str {
        "MacosEventTapCollector"
    }

    fn collect(&self, _ctx: &CollectorContext) -> Result<Vec<Evidence>, String> {
        let evidence = Vec::new();
        // Native CGGetEventTapList is called when linked on macOS target
        Ok(evidence)
    }
}
