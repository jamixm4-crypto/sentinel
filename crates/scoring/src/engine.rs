use sentinel_core::{
    Confidence, Evidence, Finding, Lang, RemovalAction, RemovalStep, RemovalSteps, Severity, Verdict,
};
use sentinel_rules::matcher::RuleMatcher;
use sentinel_rules::schema::Rule;

use crate::allowlist::is_system_allowlisted_process;
use crate::explanation::generate_explanation;

pub struct ScoringEngine<'a> {
    rules: &'a [Rule],
    lang: Lang,
}

impl<'a> ScoringEngine<'a> {
    pub fn new(rules: &'a [Rule], lang: Lang) -> Self {
        Self { rules, lang }
    }

    /// Process all raw evidence and correlate into findings
    pub fn evaluate(&self, all_evidence: &[Evidence]) -> (Verdict, Vec<Finding>) {
        let matcher = RuleMatcher::new(self.rules);
        let matches = matcher.match_evidence(all_evidence);

        let mut findings = Vec::new();
        let mut has_high_severity = false;
        let mut has_medium_severity = false;

        for (idx, rmatch) in matches.into_iter().enumerate() {
            let rule = &rmatch.rule;

            // Check if all matched processes are system allowlisted
            let mut all_allowlisted = true;
            for ev in &rmatch.matched_evidence {
                if let Some(sentinel_core::EvidenceData::Process { name, .. }) = &ev.data {
                    if !is_system_allowlisted_process(name) {
                        all_allowlisted = false;
                        break;
                    }
                } else {
                    all_allowlisted = false;
                    break;
                }
            }

            if all_allowlisted && rule.is_legitimate_use_likely {
                continue; // Suppress false positives on standard OS binaries
            }

            let finding_id = format!("{}-{}", rule.id, idx + 1);
            let confidence = Confidence::new(rmatch.score);
            let explanation = generate_explanation(rule, self.lang);
            let removal_steps = self.build_removal_steps(rule);

            if rule.severity >= Severity::High && !rule.is_legitimate_use_likely {
                has_high_severity = true;
            } else if rule.severity >= Severity::Medium {
                has_medium_severity = true;
            }

            findings.push(Finding {
                id: finding_id,
                rule_id: rule.id.clone(),
                name: rule.name.clone(),
                vendor: rule.vendor.clone(),
                category: rule.category,
                severity: rule.severity,
                confidence,
                is_legitimate_likely: rule.is_legitimate_use_likely,
                removal_policy: rule.removal_policy,
                evidence: rmatch.matched_evidence,
                explanation,
                removal_steps,
                references: rule.references.clone(),
            });
        }

        // Determine system-wide verdict
        let verdict = if has_high_severity {
            Verdict::SurveillanceLikely
        } else if has_medium_severity || !findings.is_empty() {
            Verdict::ReviewRecommended
        } else {
            Verdict::Clean
        };

        (verdict, findings)
    }

    fn build_removal_steps(&self, rule: &Rule) -> RemovalSteps {
        let mut steps = Vec::new();
        let mut order = 1;

        if let Some(rem) = &rule.removal {
            // Neutralize processes first
            for proc in &rem.processes_to_kill {
                steps.push(RemovalStep {
                    order,
                    description: format!("Terminate process '{}'", proc),
                    action: RemovalAction::TerminateProcess { name: proc.clone() },
                    rollback_action: None,
                });
                order += 1;
            }

            // Stop and delete services
            for s in &rem.services_to_stop {
                steps.push(RemovalStep {
                    order,
                    description: format!("Stop system service '{}'", s),
                    action: RemovalAction::StopService { name: s.clone() },
                    rollback_action: None,
                });
                order += 1;
            }

            for s in &rem.services_to_delete {
                steps.push(RemovalStep {
                    order,
                    description: format!("Delete service registration '{}'", s),
                    action: RemovalAction::DeleteService { name: s.clone() },
                    rollback_action: None,
                });
                order += 1;
            }

            // Clean files / paths
            for p in &rem.paths_to_remove {
                steps.push(RemovalStep {
                    order,
                    description: format!("Move file/directory to quarantine '{}'", p),
                    action: RemovalAction::QuarantineFile { source_path: p.clone() },
                    rollback_action: None,
                });
                order += 1;
            }

            RemovalSteps {
                steps,
                manual_guide_windows: rem.manual_steps_windows.clone(),
                manual_guide_linux: rem.manual_steps_linux.clone(),
                manual_guide_macos: rem.manual_steps_macos.clone(),
            }
        } else {
            RemovalSteps::default()
        }
    }
}
