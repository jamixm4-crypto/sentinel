use sentinel_core::{
    Confidence, Evidence, Finding, Lang, RemovalAction, RemovalStep, RemovalSteps, Severity, Verdict,
};
use sentinel_rules::matcher::RuleMatcher;
use sentinel_rules::schema::Rule;

use crate::allowlist::{is_known_benign_app, is_masquerading_system_process, is_system_allowlisted_process};
use crate::explanation::generate_explanation;

pub struct ScoringEngine<'a> {
    rules: &'a [Rule],
    lang: Lang,
    user_allowlist: std::collections::HashSet<String>,
    custom_c2: Vec<String>,
}

impl<'a> ScoringEngine<'a> {
    pub fn new(rules: &'a [Rule], lang: Lang) -> Self {
        Self {
            rules,
            lang,
            user_allowlist: std::collections::HashSet::new(),
            custom_c2: Vec::new(),
        }
    }

    /// Attach a user-defined allowlist of rule IDs or binary names to suppress
    pub fn with_allowlist(mut self, allowlist: std::collections::HashSet<String>) -> Self {
        self.user_allowlist = allowlist.into_iter().map(|s| s.to_lowercase()).collect();
        self
    }

    /// Attach offline or custom C2 domains from external threat feeds
    pub fn with_custom_c2(mut self, custom_c2: Vec<String>) -> Self {
        self.custom_c2 = custom_c2;
        self
    }

    /// Process all raw evidence and correlate into findings
    pub fn evaluate(&self, all_evidence: &[Evidence]) -> (Verdict, Vec<Finding>) {
        let matcher = RuleMatcher::new(self.rules);
        let matches = matcher.match_evidence(all_evidence);

        let mut findings = Vec::new();
        let mut has_high_severity = false;
        let mut has_medium_severity = false;

        // 1. Process Masquerading / Impersonation Analysis (MITRE ATT&CK T1036.005)
        for ev in all_evidence {
            if let Some(sentinel_core::EvidenceData::Process { pid, name, exe_path, .. }) = &ev.data {
                if self.user_allowlist.contains(&name.to_lowercase())
                    || self.user_allowlist.contains("t1036_process_masquerading")
                {
                    continue;
                }
                if is_masquerading_system_process(name, exe_path.as_deref()) {
                    has_high_severity = true;
                    let path_str = exe_path.as_deref().unwrap_or("Unknown location");
                    let what_is_it = match self.lang {
                        Lang::Ru => format!("Маскировка под системный процесс Windows ({})", name),
                        Lang::En => format!("System Process Impersonation ({})", name),
                    };
                    let why_flagged = match self.lang {
                        Lang::Ru => format!(
                            "Процесс с именем системного компонента '{}' запущен из каталога '{}'. Настоящие системные процессы Windows никогда не исполняются из пользовательских или временных директорий (техника скрытия MITRE T1036.005).",
                            name, path_str
                        ),
                        Lang::En => format!(
                            "Process mimicking system binary '{}' was launched from '{}'. Genuine Windows system processes never execute from user profiles or temp directories (MITRE ATT&CK T1036.005).",
                            name, path_str
                        ),
                    };
                    let is_legitimate = match self.lang {
                        Lang::Ru => "Крайне маловероятно. Это явная попытка выдать следящее или вредоносное ПО за доверенную службу Windows.".to_string(),
                        Lang::En => "Highly unlikely. This is a known technique to evade detection by posing as a trusted Windows service.".to_string(),
                    };
                    let recommendation = match self.lang {
                        Lang::Ru => "Немедленно завершите процесс, изолируйте файл в карантин и проверьте планировщик задач и реестр.".to_string(),
                        Lang::En => "Immediately terminate the process, quarantine the binary file, and inspect persistence entries.".to_string(),
                    };

                    let mut steps = vec![
                        RemovalStep {
                            order: 1,
                            description: format!("Terminate suspicious impersonating process '{}' (PID {})", name, pid),
                            action: RemovalAction::TerminateProcess { name: name.clone() },
                            rollback_action: None,
                        }
                    ];
                    if let Some(p) = exe_path {
                        steps.push(RemovalStep {
                            order: 2,
                            description: format!("Quarantine binary file '{}'", p),
                            action: RemovalAction::QuarantineFile { source_path: p.clone() },
                            rollback_action: None,
                        });
                    }

                    findings.push(Finding {
                        id: format!("MASQ-{}", pid),
                        rule_id: "t1036_process_masquerading".to_string(),
                        name: format!("Masquerading Process ({})", name),
                        vendor: Some("MITRE ATT&CK T1036.005".to_string()),
                        category: sentinel_core::Category::SuspiciousPersistence,
                        severity: Severity::Critical,
                        confidence: Confidence::new(0.95),
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
                            steps,
                            manual_guide_windows: Some(format!("Inspect folder '{}' and terminate process '{}' via Task Manager", path_str, name)),
                            manual_guide_linux: None,
                            manual_guide_macos: None,
                        },
                        references: vec![
                            "https://attack.mitre.org/techniques/T1036/005/".to_string(),
                        ],
                        mitre_attack: vec!["T1036.005".to_string()],
                    });
                }
            }
        }

        // 2. Rule evaluation with multi-modal confidence boost
        for (idx, rmatch) in matches.into_iter().enumerate() {
            let rule = &rmatch.rule;

            // Check if user allowlisted this rule or process
            if self.user_allowlist.contains(&rule.id.to_lowercase())
                || self.user_allowlist.contains(&rule.name.to_lowercase())
            {
                continue;
            }

            let mut user_suppressed = false;
            for ev in &rmatch.matched_evidence {
                if let Some(sentinel_core::EvidenceData::Process { name, .. }) = &ev.data {
                    if self.user_allowlist.contains(&name.to_lowercase()) {
                        user_suppressed = true;
                        break;
                    }
                }
            }
            if user_suppressed {
                continue;
            }

            // Check if all matched processes are system allowlisted or known benign apps
            let mut all_allowlisted = true;
            for ev in &rmatch.matched_evidence {
                if let Some(sentinel_core::EvidenceData::Process { name, exe_path, .. }) = &ev.data {
                    if !is_system_allowlisted_process(name) && !is_known_benign_app(name, exe_path.as_deref()) {
                        all_allowlisted = false;
                        break;
                    }
                } else {
                    all_allowlisted = false;
                    break;
                }
            }

            if all_allowlisted && rule.is_legitimate_use_likely {
                continue; // Suppress false positives on standard OS binaries and benign software
            }

            let finding_id = format!("{}-{}", rule.id, idx + 1);
            let unique_evidence_types: std::collections::HashSet<_> =
                rmatch.matched_evidence.iter().map(|e| &e.evidence_type).collect();
            let multimodal_boost = if unique_evidence_types.len() >= 2 { 0.15 } else { 0.0 };
            let confidence = Confidence::new((rmatch.score + multimodal_boost).min(1.0));
            let explanation = generate_explanation(rule, self.lang);
            let removal_steps = self.build_removal_steps(rule);

            if rule.severity >= Severity::High && !rule.is_legitimate_use_likely {
                has_high_severity = true;
            } else if rule.severity >= Severity::Medium {
                has_medium_severity = true;
            }

            let mitre_attack = if !rule.mitre_attack.is_empty() {
                rule.mitre_attack.clone()
            } else {
                match rule.category {
                    sentinel_core::Category::KeyboardCapture => vec!["T1056.001".to_string()],
                    sentinel_core::Category::ScreenCapture => vec!["T1113".to_string(), "T1125".to_string()],
                    sentinel_core::Category::RemoteAccess => vec!["T1021.001".to_string(), "T1219".to_string()],
                    sentinel_core::Category::SuspiciousPersistence => vec!["T1547.001".to_string()],
                    sentinel_core::Category::NetworkActivity => vec!["T1071.001".to_string()],
                    sentinel_core::Category::ProcessWatcher => vec!["T1562.001".to_string()],
                    sentinel_core::Category::OrganizationManaged => vec!["T1201".to_string()],
                }
            };

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
                mitre_attack,
            });
        }

        // Check for direct Stalkerware C2 Beaconing in network evidence
        let mut seen_c2 = std::collections::HashSet::new();
        for ev in all_evidence {
            let matched_c2 = match &ev.data {
                Some(sentinel_core::EvidenceData::Network { remote_address: Some(remote), .. }) => {
                    sentinel_rules::matches_c2_with_custom(remote, &self.custom_c2)
                }
                Some(sentinel_core::EvidenceData::Generic { key, value }) if key == "DnsCacheRecord" => {
                    sentinel_rules::matches_c2_with_custom(value, &self.custom_c2)
                }
                _ => None,
            };

            if let Some(c2) = matched_c2 {
                if self.user_allowlist.contains(&c2.to_lowercase()) {
                    continue;
                }
                if seen_c2.insert(c2.clone()) {
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
                        mitre_attack: vec!["T1071.001".to_string(), "T1571".to_string()],
                    });
                }
            }
        }

        // 4. Correlate Active Live Hardware Access (Camera / Microphone)
        for ev in all_evidence {
            if let Some(sentinel_core::EvidenceData::HardwareAccess { device_type, application, is_active }) = &ev.data {
                if *is_active && !is_benign_hardware_user(application) {
                    if self.user_allowlist.contains(&application.to_lowercase()) {
                        continue;
                    }
                    has_high_severity = true;
                    let clean_app = application.replace('\\', "/");
                    let app_name = clean_app.split('/').last().unwrap_or("unknown");
                    let what_is_it = match self.lang {
                        Lang::Ru => format!("Активный негласный перехват датчиков ({}: {})", device_type, app_name),
                        Lang::En => format!("Active Live Hardware Sensor Capture ({}: {})", device_type, app_name),
                    };
                    let why_flagged = match self.lang {
                        Lang::Ru => format!(
                            "Процесс '{}' в настоящий момент напрямую обращается к устройству '{}' без активного окна известного мессенджера или программы видеосвязи.",
                            application, device_type
                        ),
                        Lang::En => format!(
                            "Process '{}' is currently actively capturing the hardware '{}' stream without matching any known video conferencing application.",
                            application, device_type
                        ),
                    };
                    let is_legitimate = match self.lang {
                        Lang::Ru => "Маловероятно, если вы намеренно не запускали запись экрана или звука.".to_string(),
                        Lang::En => "Unlikely unless you intentionally launched a recording application.".to_string(),
                    };
                    let recommendation = match self.lang {
                        Lang::Ru => "Немедленно завершите подозрительный процесс и проверьте права доступа к камере/микрофону в настройках конфиденциальности ОС.".to_string(),
                        Lang::En => "Immediately terminate the process and inspect microphone/camera permissions in OS privacy settings.".to_string(),
                    };

                    let mitre_tech = if device_type.contains("mic") { "T1123" } else { "T1125" };

                    findings.push(Finding {
                        id: format!("ACTIVE-SENSOR-{}", app_name.replace('.', "-")),
                        rule_id: "active_hardware_sensor_capture".to_string(),
                        name: format!("Live Active Sensor Access ({})", app_name),
                        vendor: Some("Hardware ConsentStore Monitor".to_string()),
                        category: if device_type.contains("mic") { sentinel_core::Category::KeyboardCapture } else { sentinel_core::Category::ScreenCapture },
                        severity: Severity::Critical,
                        confidence: Confidence::new(0.95),
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
                                    description: format!("Terminate active recording process '{}'", app_name),
                                    action: RemovalAction::TerminateProcess { name: app_name.to_string() },
                                    rollback_action: None,
                                },
                            ],
                            manual_guide_windows: Some(format!("Terminate '{}' via Task Manager and review Settings > Privacy > Microphone/Camera", app_name)),
                            manual_guide_linux: None,
                            manual_guide_macos: None,
                        },
                        references: vec![
                            "https://attack.mitre.org/techniques/T1125/".to_string(),
                            "https://attack.mitre.org/techniques/T1123/".to_string(),
                        ],
                        mitre_attack: vec![mitre_tech.to_string()],
                    });
                }
            }
        }

        // 5. Correlate Untrusted Root Certificate & SSL MITM Interception
        for ev in all_evidence {
            if ev.evidence_type == sentinel_core::EvidenceType::UntrustedRootCertificate {
                has_high_severity = true;
                let what_is_it = match self.lang {
                    Lang::Ru => "Внедрённый корневой сертификат перехвата SSL/TLS (MITM)".to_string(),
                    Lang::En => "Installed SSL/TLS Interception Root Certificate (MITM)".to_string(),
                };
                let why_flagged = match self.lang {
                    Lang::Ru => format!("В системном хранилище доверенных корневых центров сертификации обнаружен сторонний сертификат: {}.", ev.description),
                    Lang::En => format!("A third-party root certificate was detected in the trusted root CA store: {}.", ev.description),
                };
                let is_legitimate = match self.lang {
                    Lang::Ru => "Используется корпоративными DLP (SearchInform, InfoWatch, Teramind) или отладочными прокси (Fiddler/Charles) для расшифровки всего защищённого трафика.".to_string(),
                    Lang::En => "Commonly installed by corporate DLP software or debugging proxies to decrypt encrypted HTTPS network traffic.".to_string(),
                };
                let recommendation = match self.lang {
                    Lang::Ru => "Если компьютер личный, удалите сертификат из хранилища certmgr.msc (Доверенные корневые центры сертификации).".to_string(),
                    Lang::En => "If this is a personal machine, open certmgr.msc and remove the unauthorized root certificate from Trusted Root Certification Authorities.".to_string(),
                };

                findings.push(Finding {
                    id: "SSL-MITM-ROOT-CERT".to_string(),
                    rule_id: "untrusted_root_certificate_mitm".to_string(),
                    name: "SSL/TLS MITM Interception Root Certificate".to_string(),
                    vendor: Some("Certificate Store Audit".to_string()),
                    category: sentinel_core::Category::NetworkActivity,
                    severity: Severity::High,
                    confidence: Confidence::new(0.95),
                    is_legitimate_likely: false,
                    removal_policy: sentinel_core::RemovalPolicy::ManualReview,
                    evidence: vec![ev.clone()],
                    explanation: sentinel_core::FindingExplanation {
                        what_is_it,
                        why_flagged,
                        is_legitimate,
                        recommendation,
                    },
                    removal_steps: RemovalSteps::default(),
                    references: vec![
                        "https://attack.mitre.org/techniques/T1557/001/".to_string(),
                    ],
                    mitre_attack: vec!["T1557.001".to_string()],
                });
            }
        }

        // 6. Correlate Hosts File Tampering
        for ev in all_evidence {
            if ev.evidence_type == sentinel_core::EvidenceType::HostsFileTampering {
                has_high_severity = true;
                findings.push(Finding {
                    id: "HOSTS-FILE-SINKHOLE".to_string(),
                    rule_id: "hosts_file_security_sinkhole".to_string(),
                    name: "Security Domain Sinkhole in Hosts File".to_string(),
                    vendor: Some("Hosts File Integrity".to_string()),
                    category: sentinel_core::Category::NetworkActivity,
                    severity: Severity::High,
                    confidence: Confidence::new(1.0),
                    is_legitimate_likely: false,
                    removal_policy: sentinel_core::RemovalPolicy::ManualReview,
                    evidence: vec![ev.clone()],
                    explanation: sentinel_core::FindingExplanation {
                        what_is_it: "Модификация файла hosts для блокировки сайтов безопасности".to_string(),
                        why_flagged: ev.description.clone(),
                        is_legitimate: "Крайне маловероятно. Используется вредоносным ПО для изоляции антивирусных ресурсов.".to_string(),
                        recommendation: "Очистите файл C:\\Windows\\System32\\drivers\\etc\\hosts от подозрительных записей.".to_string(),
                    },
                    removal_steps: RemovalSteps::default(),
                    references: vec![
                        "https://attack.mitre.org/techniques/T1565/001/".to_string(),
                    ],
                    mitre_attack: vec!["T1565.001".to_string()],
                });
            }
        }

        // 7. Correlate WMI Persistence Subscriptions
        for ev in all_evidence {
            if ev.evidence_type == sentinel_core::EvidenceType::WmiSubscription {
                has_high_severity = true;
                findings.push(Finding {
                    id: "WMI-PERSISTENCE-SUBSCRIPTION".to_string(),
                    rule_id: "wmi_event_consumer_persistence".to_string(),
                    name: "WMI Event Consumer Hidden Persistence".to_string(),
                    vendor: Some("WMI Persistence Monitor".to_string()),
                    category: sentinel_core::Category::SuspiciousPersistence,
                    severity: Severity::High,
                    confidence: Confidence::new(0.9),
                    is_legitimate_likely: false,
                    removal_policy: sentinel_core::RemovalPolicy::ManualReview,
                    evidence: vec![ev.clone()],
                    explanation: sentinel_core::FindingExplanation {
                        what_is_it: "Скрытый механизм автозапуска через WMI Event Consumer".to_string(),
                        why_flagged: ev.description.clone(),
                        is_legitimate: "Редко используется обычными программами, характерен для APT и скрытого шпионского ПО.".to_string(),
                        recommendation: "Проверьте пространство имён WMI root\\subscription и удалите подозрительный EventConsumer.".to_string(),
                    },
                    removal_steps: RemovalSteps::default(),
                    references: vec![
                        "https://attack.mitre.org/techniques/T1546/003/".to_string(),
                    ],
                    mitre_attack: vec!["T1546.003".to_string()],
                });
            }
        }

        // 8. Correlate Dangerous Browser Extensions
        for ev in all_evidence {
            if let Some(sentinel_core::EvidenceData::BrowserExtension { browser, id, name, permissions, path: _, .. }) = &ev.data {
                let has_debugger = permissions.iter().any(|p| p == "debugger");
                let has_interception = permissions.iter().any(|p| p == "webRequestBlocking")
                    && permissions.iter().any(|p| p.contains("<all_urls>") || p == "*://*/*");

                if has_debugger || has_interception {
                    has_medium_severity = true;
                    findings.push(Finding {
                        id: format!("EXT-{}-{}", browser.to_lowercase(), id),
                        rule_id: "browser_extension_high_privilege".to_string(),
                        name: format!("High-Privilege Browser Extension ({}: {})", browser, name),
                        vendor: Some(browser.clone()),
                        category: sentinel_core::Category::ScreenCapture,
                        severity: Severity::High,
                        confidence: Confidence::new(0.85),
                        is_legitimate_likely: false,
                        removal_policy: sentinel_core::RemovalPolicy::ManualReview,
                        evidence: vec![ev.clone()],
                        explanation: sentinel_core::FindingExplanation {
                            what_is_it: format!("Расширение браузера {} с правами отладки или блокирующего перехвата трафика", browser),
                            why_flagged: format!("Расширение '{}' запрашивает критические разрешения: {}.", name, permissions.join(", ")),
                            is_legitimate: "Такие разрешения могут использоваться легитимными инструментами разработки, но также применяются для негласного перехвата сессий и форм ввода.".to_string(),
                            recommendation: format!("Откройте страницу расширений в {} и удалите '{}', если вы не устанавливали его осознанно.", browser, name),
                        },
                        removal_steps: RemovalSteps {
                            steps: vec![],
                            manual_guide_windows: Some(format!("Open {} > Extensions and remove '{}'", browser, name)),
                            manual_guide_linux: None,
                            manual_guide_macos: None,
                        },
                        references: vec![
                            "https://attack.mitre.org/techniques/T1176/".to_string(),
                            "https://attack.mitre.org/techniques/T1185/".to_string(),
                        ],
                        mitre_attack: vec!["T1176".to_string(), "T1185".to_string()],
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
                    action: RemovalAction::QuarantineFile {
                        source_path: p.clone(),
                    },
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

fn is_benign_hardware_user(app: &str) -> bool {
    let lower = app.to_lowercase();
    lower.contains("zoom.exe")
        || lower.contains("teams.exe")
        || lower.contains("discord.exe")
        || lower.contains("obs64.exe")
        || lower.contains("obs32.exe")
        || lower.contains("chrome.exe")
        || lower.contains("msedge.exe")
        || lower.contains("firefox.exe")
        || lower.contains("skype.exe")
        || lower.contains("slack.exe")
        || lower.contains("telegram.exe")
        || lower.contains("webex.exe")
}

