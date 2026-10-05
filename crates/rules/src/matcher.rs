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
                let name_trimmed = name_lower.trim_end_matches(".exe");
                for proc in &rule.detection.processes {
                    let proc_lower = proc.name.to_lowercase();
                    let proc_trimmed = proc_lower.trim_end_matches(".exe");
                    if name_lower == proc_lower || name_trimmed == proc_trimmed {
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
            Some(EvidenceData::Service { name, display_name, binary_path, .. }) => {
                let name_lower = name.to_lowercase();
                let disp_lower = display_name.as_deref().unwrap_or("").to_lowercase();
                for s in &rule.detection.services {
                    let s_lower = s.name.to_lowercase();
                    if name_lower == s_lower || name_lower.contains(&s_lower) || (!disp_lower.is_empty() && disp_lower.contains(&s_lower)) {
                        return true;
                    }
                }

                // Correlate service binary path with rule processes and paths
                if let Some(bpath) = binary_path {
                    let bpath_lower = bpath.to_lowercase();
                    for proc in &rule.detection.processes {
                        let proc_lower = proc.name.to_lowercase();
                        let proc_trimmed = proc_lower.trim_end_matches(".exe");
                        if bpath_lower.contains(&proc_lower) || bpath_lower.contains(proc_trimmed) {
                            return true;
                        }
                    }
                    for p in &rule.detection.paths {
                        if bpath_lower.contains(&p.to_lowercase()) {
                            return true;
                        }
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
                    if local_address.ends_with(&port_str) || remote_address.as_ref().map_or(false, |r| r.ends_with(&port_str)) {
                        return true;
                    }
                }
            }
            _ => {
                // Generic string matching against description
                let desc_lower = ev.description.to_lowercase();
                for p in &rule.detection.processes {
                    let p_lower = p.name.to_lowercase();
                    let p_trimmed = p_lower.trim_end_matches(".exe");
                    if desc_lower.contains(&p_lower) || desc_lower.contains(p_trimmed) {
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
