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

        // Check for direct Stalkerware C2 Beaconing in network evidence
        let mut seen_c2 = std::collections::HashSet::new();
        for ev in all_evidence {
            let matched_c2 = match &ev.data {
                Some(sentinel_core::EvidenceData::Network { remote_address: Some(remote), .. }) => {
                    sentinel_rules::matches_known_c2(remote)
                }
                Some(sentinel_core::EvidenceData::Generic { key, value }) if key == "DnsCacheRecord" => {
                    sentinel_rules::matches_known_c2(value)
                }
                _ => None,
            };

            if let Some(c2) = matched_c2 {
                if seen_c2.insert(c2) {
                    has_high_severity = true;
                    let what_is_it = match self.lang {
                        Lang::Ru => format!("Сетевая связь с сервером управления ({}) сталкерского ПО", c2),
                        Lang::En => format!("Network communication with Command & Control server ({}) of stalkerware", c2),
                    };
                    let why_flagged = match self.lang {
                        Lang::Ru => format!("В активных сетевых сокетах или системном DNS-кеше зафиксировано обращение к известному хосту C2: '{}'.", c2),
                        Lang::En => format!("Active socket or DNS client cache record matched known surveillance C2 domain: '{}'.", c2),
                    };
                    let is_legitimate = match self.lang {
                        Lang::Ru => "Маловероятно. Данный домен внесён в международные базы индикаторов сталкерского ПО (AssoEchap / TinyCheck).".to_string(),
                        Lang::En => "Highly unlikely. This domain is cataloged in global stalkerware threat intelligence feeds.".to_string(),
                    };
                    let recommendation = match self.lang {
                        Lang::Ru => "Рекомендуется проверить активные процессы, заблокировать домен на уровне брандмауэра и зафиксировать отчёт перед удалением.".to_string(),
                        Lang::En => "Inspect active network connections, isolate the host or block the domain, and preserve evidence prior to remediation.".to_string(),
                    };

                    findings.push(Finding {
                        id: format!("C2-{}", c2.replace('.', "-")),
                        rule_id: "stalkerware_c2_network_beacon".to_string(),
                        name: format!("Stalkerware C2 Communication ({})", c2),
                        vendor: Some("Threat Intelligence (AssoEchap / TinyCheck)".to_string()),
                        category: sentinel_core::Category::NetworkActivity,
                        severity: Severity::Critical,
                        confidence: Confidence::new(1.0),
                        is_legitimate_likely: false,
                        removal_policy: sentinel_core::RemovalPolicy::SafeAuto,
                        evidence: vec![ev.clone()],
                        explanation: sentinel_core::FindingExplanation {
                            what_is_it,
                            why_flagged,
                            is_legitimate,
                            recommendation,
                        },
                        removal_steps: RemovalSteps {
                            steps: vec![
                                RemovalStep {
                                    order: 1,
                                    description: format!("Block outbound communication to '{}' in hosts file or firewall", c2),
                                    action: RemovalAction::DeleteRegistryValue {
                                        hive: "HKLM".to_string(),
                                        path: r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters".to_string(),
                                        value: "C2Blocked".to_string(),
                                    },
                                    rollback_action: None,
                                },
                            ],
                            manual_guide_windows: Some(format!("Add '0.0.0.0 {}' to C:\\Windows\\System32\\drivers\\etc\\hosts", c2)),
                            manual_guide_linux: Some(format!("Add '0.0.0.0 {}' to /etc/hosts", c2)),
                            manual_guide_macos: Some(format!("Add '0.0.0.0 {}' to /etc/hosts", c2)),
                        },
                        references: vec![
                            "https://github.com/AssoEchap/stalkerware-indicators".to_string(),
                            "https://stopstalkerware.org".to_string(),
                        ],
                    });
                }
            }
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
