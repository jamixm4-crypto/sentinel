use sentinel_core::{Evidence, EvidenceData};
use crate::schema::Rule;

/// Match a set of evidence against a rule
#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule: Rule,
    pub matched_evidence: Vec<Evidence>,
    pub score: f32,
}

pub struct RuleMatcher<'a> {
    rules: &'a [Rule],
}

impl<'a> RuleMatcher<'a> {
    pub fn new(rules: &'a [Rule]) -> Self {
        Self { rules }
    }

    /// Match a collection of evidence against all loaded rules
    pub fn match_evidence(&self, all_evidence: &[Evidence]) -> Vec<RuleMatch> {
        let mut matches = Vec::new();

        for rule in self.rules {
            let mut matched = Vec::new();

            for ev in all_evidence {
                if self.evidence_matches_rule(ev, rule) {
                    matched.push(ev.clone());
                }
            }

            if !matched.is_empty() {
                // Enforce condition min_matches if specified
                if let Some(cond) = &rule.condition {
                    if let Some(min_req) = cond.min_matches {
                        if matched.len() < min_req {
                            continue;
                        }
                    }
                }

                // Calculate match score based on base confidence and evidence count
                let evidence_boost = (matched.len() as f32 * 0.15).min(0.25);
                let score = (rule.base_confidence + evidence_boost).min(1.0);

                matches.push(RuleMatch {
                    rule: rule.clone(),
                    matched_evidence: matched,
                    score,
                });
            }
        }

        matches
    }

    fn evidence_matches_rule(&self, ev: &Evidence, rule: &Rule) -> bool {
        match &ev.data {
            Some(EvidenceData::Process { name, exe_path, command_line, .. }) => {
                let name_lower = name.to_lowercase();
                for proc in &rule.detection.processes {
                    if proc.name.to_lowercase() == name_lower {
                        if let Some(regex_str) = &proc.cmdline_regex {
                            if let Ok(re) = regex::Regex::new(regex_str) {
                                let cmd = command_line.as_deref().unwrap_or("");
                                if !re.is_match(cmd) {
                                    continue;
                                }
                            }
                        }
                        return true;
                    }
                }

                // Correlate process executable path with rule paths
                if let Some(path) = exe_path {
                    let path_lower = path.to_lowercase();
                    for p in &rule.detection.paths {
                        if path_lower.contains(&p.to_lowercase()) {
                            return true;
                        }
                    }
                }
            }
            Some(EvidenceData::Registry { path, value_name, value_data: _, .. }) => {
                let path_lower = path.to_lowercase();
                for reg in &rule.detection.registry_keys {
                    if path_lower.contains(&reg.path.to_lowercase()) {
                        if let (Some(req_val), Some(actual_val)) = (&reg.value_name, value_name) {
                            if actual_val.to_lowercase().contains(&req_val.to_lowercase()) {
                                return true;
                            }
                        } else if reg.value_name.is_none() {
                            return true;
                        }
                    }
                }
            }
            Some(EvidenceData::Service { name, .. }) => {
                let name_lower = name.to_lowercase();
                for s in &rule.detection.services {
                    if s.name.to_lowercase() == name_lower {
                        return true;
                    }
                }
            }
            Some(EvidenceData::File { path, .. }) => {
                let path_lower = path.to_lowercase();
                for p in &rule.detection.paths {
                    if path_lower.contains(&p.to_lowercase()) {
                        return true;
                    }
                }
            }
            Some(EvidenceData::Network { remote_address, local_address, .. }) => {
                for dom in &rule.detection.network_domains {
                    if let Some(remote) = remote_address {
                        if remote.to_lowercase().contains(&dom.to_lowercase()) {
                            return true;
                        }
                    }
                }
                for port in &rule.detection.network_ports {
                    let port_str = format!(":{}", port);
                    if local_address.ends_with(&port_str) {
                        return true;
                    }
                }
            }
            _ => {
                // Generic string matching against description
                let desc_lower = ev.description.to_lowercase();
                for p in &rule.detection.processes {
                    if desc_lower.contains(&p.name.to_lowercase()) {
                        return true;
                    }
                }
                for path in &rule.detection.paths {
                    if desc_lower.contains(&path.to_lowercase()) {
                        return true;
                    }
                }
            }
        }

        false
    }
}
