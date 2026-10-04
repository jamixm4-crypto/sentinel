use sentinel_core::{Evidence, EvidenceData, EvidenceType};
use std::path::Path;

use crate::{Collector, CollectorContext};

pub struct MacosPersistenceCollector;

impl Collector for MacosPersistenceCollector {
    fn name(&self) -> &'static str {
        "MacosPersistenceCollector"
    }

    fn collect(&self, _ctx: &CollectorContext) -> Result<Vec<Evidence>, String> {
        let mut evidence = Vec::new();
        let mut launch_paths = vec![
            Path::new("/Library/LaunchDaemons"),
            Path::new("/Library/LaunchAgents"),
        ];

        let home_agents = dirs::home_dir().map(|h| h.join("Library/LaunchAgents"));
        if let Some(ref p) = home_agents {
            launch_paths.push(p.as_path());
        }

        for dir in launch_paths {
            if dir.exists() {
                if let Ok(entries) = std::fs::read_dir(dir) {
                    for entry in entries.filter_map(Result::ok) {
                        let path = entry.path();
                        if path.extension().and_then(|s| s.to_str()) == Some("plist") {
                            let fname = path.file_name().unwrap_or_default().to_string_lossy();
                            let content = std::fs::read_to_string(&path).unwrap_or_default();

                            let is_suspicious = content.contains("<key>KeepAlive</key>")
                                && content.contains("<true/>")
                                && content.contains("<key>RunAtLoad</key>");

                            let desc = if is_suspicious {
                                format!("Aggressive persistent service (KeepAlive+RunAtLoad): {}", fname)
                            } else {
                                format!("Registered launchd service: {}", fname)
                            };

                            evidence.push(
                                Evidence::new(EvidenceType::SystemDaemonService, self.name(), desc, content)
                                    .with_data(EvidenceData::Generic {
                                        key: "LaunchdPlist".to_string(),
                                        value: fname.to_string(),
                                    }),
                            );
                        }
                    }
                }
            }
        }

        Ok(evidence)
    }
}
