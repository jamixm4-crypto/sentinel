use sentinel_core::{
    Category, Evidence, EvidenceData, EvidenceType, Lang,
    RemovalPolicy, Severity, Verdict,
};
use sentinel_rules::get_embedded_rules;
use sentinel_scoring::ScoringEngine;

#[test]
fn test_embedded_rules_validity() {
    let rules = get_embedded_rules();
    assert!(!rules.is_empty(), "Embedded rules should not be empty");
    assert!(rules.len() >= 130, "Expected at least 130 embedded rules, got {}", rules.len());

    for r in &rules {
        assert!(!r.id.is_empty(), "Rule ID must not be empty");
        assert!(!r.name.is_empty(), "Rule Name must not be empty");
        assert!(!r.description.is_empty(), "Rule Description must not be empty");
    }
}

#[test]
fn test_clean_system_verdict() {
    let rules = get_embedded_rules();
    let scoring = ScoringEngine::new(&rules, Lang::En);

    // Mock evidence with only benign standard Windows components
    let benign_evidence = vec![
        Evidence::new(
            EvidenceType::ActiveProcess,
            "MockCollector",
            "Active process: explorer.exe (PID: 1000)",
            "Path: C:\\Windows\\explorer.exe",
        )
        .with_data(EvidenceData::Process {
            pid: 1000,
            name: "explorer.exe".to_string(),
            exe_path: Some("C:\\Windows\\explorer.exe".to_string()),
            command_line: None,
        }),
        Evidence::new(
            EvidenceType::ActiveProcess,
            "MockCollector",
            "Active process: svchost.exe (PID: 1004)",
            "Path: C:\\Windows\\System32\\svchost.exe",
        )
        .with_data(EvidenceData::Process {
            pid: 1004,
            name: "svchost.exe".to_string(),
            exe_path: Some("C:\\Windows\\System32\\svchost.exe".to_string()),
            command_line: None,
        }),
    ];

    let (verdict, findings) = scoring.evaluate(&benign_evidence);
    assert_eq!(verdict, Verdict::Clean, "Standard OS processes must yield Clean verdict");
    assert!(findings.is_empty(), "Standard OS processes must produce 0 findings");
}

#[test]
fn test_spyrix_detection_and_severity() {
    let rules = get_embedded_rules();
    let scoring = ScoringEngine::new(&rules, Lang::En);

    // Mock evidence for Spyrix keylogger
    let spyrix_evidence = vec![
        Evidence::new(
            EvidenceType::ActiveProcess,
            "MockCollector",
            "Active process: spx.exe (PID: 4321)",
            "Path: C:\\Program Files (x86)\\Spyrix Personal Monitor\\spx.exe",
        )
        .with_data(EvidenceData::Process {
            pid: 4321,
            name: "spx.exe".to_string(),
            exe_path: Some("C:\\Program Files (x86)\\Spyrix Personal Monitor\\spx.exe".to_string()),
            command_line: None,
        }),
        Evidence::new(
            EvidenceType::RegistryRunKey,
            "MockCollector",
            "Registry Run key: HKLM\\SOFTWARE\\Spyrix",
            "Path: HKLM\\SOFTWARE\\Spyrix",
        )
        .with_data(EvidenceData::Registry {
            hive: "HKLM".to_string(),
            path: "SOFTWARE\\Spyrix".to_string(),
            value_name: None,
            value_data: None,
        }),
    ];

    let (verdict, findings) = scoring.evaluate(&spyrix_evidence);
    assert_eq!(verdict, Verdict::SurveillanceLikely, "Spyrix detection must trigger SurveillanceLikely verdict");
    assert_eq!(findings.len(), 1, "Must find exactly 1 matched rule for Spyrix");
    assert_eq!(findings[0].category, Category::KeyboardCapture);
    assert_eq!(findings[0].removal_policy, RemovalPolicy::SafeAuto);
    assert!(findings[0].confidence.score >= 0.85);
}

#[test]
fn test_do_not_remove_policy_blocking() {
    let rules = get_embedded_rules();
    let scoring = ScoringEngine::new(&rules, Lang::En);

    // Mock evidence for CrowdStrike Falcon EDR
    let cs_evidence = vec![Evidence::new(
        EvidenceType::ActiveProcess,
        "MockCollector",
        "Active process: CSFalconService.exe (PID: 900)",
        "Path: C:\\Program Files\\CrowdStrike\\CSFalconService.exe",
    )
    .with_data(EvidenceData::Process {
        pid: 900,
        name: "CSFalconService.exe".to_string(),
        exe_path: Some("C:\\Program Files\\CrowdStrike\\CSFalconService.exe".to_string()),
        command_line: None,
    })];

    let (_, findings) = scoring.evaluate(&cs_evidence);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].removal_policy, RemovalPolicy::DoNotRemove);

    // Verify removal manager refuses to remove
    let rm = sentinel_removal::RemovalManager::new(false);
    let remove_result = rm.remove_finding(&findings[0]);
    assert!(remove_result.is_err(), "Must reject removing DoNotRemove software");

    // Verify quarantine manager refuses to quarantine
    let qm = sentinel_removal::QuarantineManager::new(false);
    let quarantine_result = qm.quarantine(&findings[0]);
    assert!(quarantine_result.is_err(), "Must reject quarantining DoNotRemove software");
}

#[test]
fn test_personal_safety_mode_blocks_removal() {
    let rules = get_embedded_rules();
    let scoring = ScoringEngine::new(&rules, Lang::En);

    let mspy_evidence = vec![Evidence::new(
        EvidenceType::ActiveProcess,
        "MockCollector",
        "Active process: mspy.exe",
        "Path: C:\\ProgramData\\mspy\\mspy.exe",
    )
    .with_data(EvidenceData::Process {
        pid: 300,
        name: "mspy.exe".to_string(),
        exe_path: Some("C:\\ProgramData\\mspy\\mspy.exe".to_string()),
        command_line: None,
    })];

    let (_, findings) = scoring.evaluate(&mspy_evidence);
    assert!(!findings.is_empty());

    // With personal safety mode active:
    let rm = sentinel_removal::RemovalManager::new(true);
    let res = rm.remove_finding(&findings[0]);
    assert!(res.is_err(), "Personal Safety Mode must forbid removal");
}

#[test]
fn test_personal_safety_mode_blocks_quarantine() {
    let rules = get_embedded_rules();
    let scoring = ScoringEngine::new(&rules, Lang::En);

    let mspy_evidence = vec![Evidence::new(
        EvidenceType::ActiveProcess,
        "MockCollector",
        "Active process: mspy.exe",
        "Path: C:\\ProgramData\\mspy\\mspy.exe",
    )
    .with_data(EvidenceData::Process {
        pid: 300,
        name: "mspy.exe".to_string(),
        exe_path: Some("C:\\ProgramData\\mspy\\mspy.exe".to_string()),
        command_line: None,
    })];

    let (_, findings) = scoring.evaluate(&mspy_evidence);
    assert!(!findings.is_empty());

    let qm = sentinel_removal::QuarantineManager::new(true);
    let res = qm.quarantine(&findings[0]);
    assert!(res.is_err(), "Personal Safety Mode must forbid quarantine");
}

#[test]
fn test_c2_network_beacon_alert() {
    let rules = get_embedded_rules();
    let scoring = ScoringEngine::new(&rules, Lang::En);

    let c2_evidence = vec![
        Evidence::new(
            EvidenceType::NetworkSocketListener,
            "NetworkCollector",
            "Active outbound connection to 198.51.100.1",
            "Remote: api.flexispy.com:443",
        )
        .with_data(EvidenceData::Network {
            protocol: "TCP".to_string(),
            local_address: "192.168.1.50:54321".to_string(),
            remote_address: Some("api.flexispy.com:443".to_string()),
            pid: Some(9999),
        }),
    ];

    let (verdict, findings) = scoring.evaluate(&c2_evidence);
    assert_eq!(verdict, Verdict::SurveillanceLikely);
    assert!(findings.len() >= 1);
    assert!(findings.iter().any(|f| f.rule_id == "stalkerware_c2_network_beacon"));
}

#[test]
fn test_masquerading_system_process_detection() {
    let rules = get_embedded_rules();
    let scoring = ScoringEngine::new(&rules, Lang::En);

    // Malicious stealth keylogger disguising as svchost.exe in AppData
    let fake_svchost = vec![
        Evidence::new(
            EvidenceType::ActiveProcess,
            "ProcessCollector",
            "Active process: svchost.exe (PID: 666)",
            "Path: C:\\Users\\Victim\\AppData\\Roaming\\svchost.exe",
        )
        .with_data(EvidenceData::Process {
            pid: 666,
            name: "svchost.exe".to_string(),
            exe_path: Some("C:\\Users\\Victim\\AppData\\Roaming\\svchost.exe".to_string()),
            command_line: Some("C:\\Users\\Victim\\AppData\\Roaming\\svchost.exe --stealth".to_string()),
        }),
    ];

    let (verdict, findings) = scoring.evaluate(&fake_svchost);
    assert_eq!(verdict, Verdict::SurveillanceLikely, "Masquerading system process must trigger SurveillanceLikely");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "t1036_process_masquerading");
    assert_eq!(findings[0].severity, Severity::Critical);
    assert_eq!(findings[0].confidence.score, 0.95);
    assert!(!findings[0].is_legitimate_likely);
}

#[test]
fn test_benign_app_allowlist_suppression() {
    let rules = get_embedded_rules();
    let scoring = ScoringEngine::new(&rules, Lang::En);

    // Common benign tools: OBS Studio and NVDA screen reader
    let benign_tools = vec![
        Evidence::new(
            EvidenceType::ActiveProcess,
            "ProcessCollector",
            "Active process: obs64.exe (PID: 1200)",
            "Path: C:\\Program Files\\obs-studio\\bin\\64bit\\obs64.exe",
        )
        .with_data(EvidenceData::Process {
            pid: 1200,
            name: "obs64.exe".to_string(),
            exe_path: Some("C:\\Program Files\\obs-studio\\bin\\64bit\\obs64.exe".to_string()),
            command_line: None,
        }),
        Evidence::new(
            EvidenceType::ActiveProcess,
            "ProcessCollector",
            "Active process: nvda.exe (PID: 1300)",
            "Path: C:\\Program Files (x86)\\NVDA\\nvda.exe",
        )
        .with_data(EvidenceData::Process {
            pid: 1300,
            name: "nvda.exe".to_string(),
            exe_path: Some("C:\\Program Files (x86)\\NVDA\\nvda.exe".to_string()),
            command_line: None,
        }),
    ];

    let (verdict, findings) = scoring.evaluate(&benign_tools);
    assert_eq!(verdict, Verdict::Clean, "Benign tools like OBS and NVDA must yield Clean verdict");
    assert!(findings.is_empty(), "Benign tools must not produce false positive findings");
}

#[test]
fn test_cmdline_regex_matching_accuracy() {
    use sentinel_rules::matcher::RuleMatcher;
    use sentinel_rules::schema::{DetectionCriteria, ProcessCriteria, Rule};

    let rule = Rule {
        id: "test_regex_rule".to_string(),
        name: "Test Regex Rule".to_string(),
        version: 1,
        category: Category::SuspiciousPersistence,
        severity: Severity::High,
        base_confidence: 0.8,
        removal_policy: RemovalPolicy::SafeAuto,
        platforms: vec!["windows".to_string()],
        vendor: None,
        description: "Test".to_string(),
        is_legitimate_use_likely: false,
        safety_warning: None,
        detection: DetectionCriteria {
            processes: vec![ProcessCriteria {
                name: "agent.exe".to_string(),
                cmdline_regex: Some(r".*--hidden.*".to_string()),
            }],
            ..Default::default()
        },
        condition: None,
        removal: None,
        references: vec![],
    };

    let rules = vec![rule];
    let matcher = RuleMatcher::new(&rules);

    // 1. Process without matching regex cmdline
    let non_matching_ev = vec![
        Evidence::new(EvidenceType::ActiveProcess, "col", "desc", "tech").with_data(EvidenceData::Process {
            pid: 10,
            name: "agent.exe".to_string(),
            exe_path: None,
            command_line: Some("agent.exe --normal-mode".to_string()),
        })
    ];
    let matches = matcher.match_evidence(&non_matching_ev);
    assert!(matches.is_empty(), "Cmdline without regex match must not match");

    // 2. Process with matching regex cmdline
    let matching_ev = vec![
        Evidence::new(EvidenceType::ActiveProcess, "col", "desc", "tech").with_data(EvidenceData::Process {
            pid: 11,
            name: "agent.exe".to_string(),
            exe_path: None,
            command_line: Some("agent.exe --hidden --port 4444".to_string()),
        })
    ];
    let matches2 = matcher.match_evidence(&matching_ev);
    assert_eq!(matches2.len(), 1, "Cmdline with regex match must match");
}

#[test]
fn test_custom_c2_domain_matching() {
    let rules = get_embedded_rules();
    let scoring = ScoringEngine::new(&rules, Lang::En)
        .with_custom_c2(vec!["evil-stalkerware-tracker.org".to_string()]);

    let evidence = vec![
        Evidence::new(
            EvidenceType::NetworkSocketListener,
            "NetworkCollector",
            "Active TCP connection to evil-stalkerware-tracker.org:443",
            "Socket: 192.168.1.10:54321 -> evil-stalkerware-tracker.org:443",
        )
        .with_data(EvidenceData::Network {
            protocol: "TCP".to_string(),
            local_address: "192.168.1.10:54321".to_string(),
            remote_address: Some("evil-stalkerware-tracker.org:443".to_string()),
            pid: Some(3333),
        }),
    ];

    let (verdict, findings) = scoring.evaluate(&evidence);
    assert_eq!(verdict, Verdict::SurveillanceLikely);
    assert!(findings.iter().any(|f| f.rule_id == "stalkerware_c2_network_beacon"));
    assert!(findings.iter().any(|f| f.name.contains("evil-stalkerware-tracker.org")));
}

#[test]
fn test_ecs_ndjson_export() {
    use sentinel_core::PlatformInfo;
    use std::time::Duration;

    let rules = get_embedded_rules();
    let scoring = ScoringEngine::new(&rules, Lang::En);
    let evidence = vec![
        Evidence::new(
            EvidenceType::ActiveProcess,
            "MockCollector",
            "Active process: spyrix.exe",
            "Path: C:\\Program Files\\Spyrix\\spyrix.exe",
        )
        .with_data(EvidenceData::Process {
            pid: 1234,
            name: "spyrix.exe".to_string(),
            exe_path: Some("C:\\Program Files\\Spyrix\\spyrix.exe".to_string()),
            command_line: None,
        }),
    ];

    let (verdict, findings) = scoring.evaluate(&evidence);
    let scan_result = sentinel_core::ScanResult {
        verdict,
        findings,
        platform: PlatformInfo::current(),
        scan_duration: Duration::from_millis(50),
        timestamp: "2026-10-05T08:00:00Z".to_string(),
        skipped_checks: vec![],
        total_inspected_processes: 1,
        total_inspected_persistence: 0,
    };

    let ecs_events = sentinel_report::generate_ecs_events(&scan_result);
    assert!(!ecs_events.is_empty(), "Should generate at least 1 ECS event");
    let first = &ecs_events[0];
    assert_eq!(first["ecs"]["version"], "8.11.0");
    assert_eq!(first["event"]["kind"], "alert");
    assert_eq!(first["threat"]["framework"], "MITRE ATT&CK");

    let ndjson = sentinel_report::export_ecs_ndjson(&scan_result);
    assert!(ndjson.contains(r#""framework":"MITRE ATT&CK""#));
}

#[test]
fn test_zabbix_agent_service_and_port_detection() {
    let rules = get_embedded_rules();
    let scoring = ScoringEngine::new(&rules, Lang::En);

    // Test 1: Service evidence matching
    let service_evidence = vec![
        Evidence::new(
            EvidenceType::SystemDaemonService,
            "WindowsServicesCollector",
            "Windows Service: 'Zabbix Agent' (Zabbix Agent)",
            "C:\\Program Files\\Zabbix Agent\\zabbix_agentd.exe --config C:\\Program Files\\Zabbix Agent\\zabbix_agentd.conf",
        )
        .with_data(EvidenceData::Service {
            name: "Zabbix Agent".to_string(),
            display_name: Some("Zabbix Agent".to_string()),
            binary_path: Some("C:\\Program Files\\Zabbix Agent\\zabbix_agentd.exe".to_string()),
            start_type: Some("Auto".to_string()),
        }),
    ];

    let (_, findings) = scoring.evaluate(&service_evidence);
    assert!(!findings.is_empty(), "Zabbix service must be detected");
    let zabbix_finding = findings.iter().find(|f| f.rule_id == "CORP-ALL-0017");
    assert!(zabbix_finding.is_some(), "Finding must match Zabbix rule CORP-ALL-0017");
    let zf = zabbix_finding.unwrap();
    assert_eq!(zf.category, Category::OrganizationManaged);
    assert_eq!(zf.removal_policy, RemovalPolicy::ManualReview);

    // Test 2: Network port evidence matching (10050)
    let net_evidence = vec![
        Evidence::new(
            EvidenceType::NetworkSocketListener,
            "NetworkCollector",
            "TCP listening: 0.0.0.0:10050",
            "Port 10050",
        )
        .with_data(EvidenceData::Network {
            protocol: "TCP".to_string(),
            local_address: "0.0.0.0:10050".to_string(),
            remote_address: None,
            pid: Some(4040),
        }),
    ];

    let (_, net_findings) = scoring.evaluate(&net_evidence);
    assert!(net_findings.iter().any(|f| f.rule_id == "CORP-ALL-0017"), "Zabbix port 10050 must trigger rule");

    // Test 3: Process evidence matching (zabbix_agentd.exe)
    let proc_evidence = vec![
        Evidence::new(
            EvidenceType::ActiveProcess,
            "ProcessCollector",
            "Active process: zabbix_agentd.exe (PID: 4040)",
            "Path: C:\\Program Files\\Zabbix Agent\\zabbix_agentd.exe",
        )
        .with_data(EvidenceData::Process {
            pid: 4040,
            name: "zabbix_agentd.exe".to_string(),
            exe_path: Some("C:\\Program Files\\Zabbix Agent\\zabbix_agentd.exe".to_string()),
            command_line: Some("\"C:\\Program Files\\Zabbix Agent\\zabbix_agentd.exe\" -c \"C:\\Program Files\\Zabbix Agent\\zabbix_agentd.conf\"".to_string()),
        }),
    ];

    let (_, proc_findings) = scoring.evaluate(&proc_evidence);
    assert!(proc_findings.iter().any(|f| f.rule_id == "CORP-ALL-0017"), "Zabbix process must trigger rule");
}

#[test]
fn test_rmm_meshcentral_detection() {
    let rules = get_embedded_rules();
    let scoring = ScoringEngine::new(&rules, Lang::En);

    let evidence = vec![
        Evidence::new(
            EvidenceType::ActiveProcess,
            "ProcessCollector",
            "Active process: meshagent.exe",
            "Path: C:\\Program Files\\Mesh Agent\\meshagent.exe",
        )
        .with_data(EvidenceData::Process {
            pid: 5050,
            name: "meshagent.exe".to_string(),
            exe_path: Some("C:\\Program Files\\Mesh Agent\\meshagent.exe".to_string()),
            command_line: None,
        }),
    ];

    let (_, findings) = scoring.evaluate(&evidence);
    assert!(findings.iter().any(|f| f.rule_id == "RAT-ALL-0070"), "MeshCentral must be detected");
}

#[test]
fn test_mipko_personal_monitor_detection() {
    let rules = get_embedded_rules();
    let scoring = ScoringEngine::new(&rules, Lang::En);

    let evidence = vec![
        Evidence::new(
            EvidenceType::ActiveProcess,
            "ProcessCollector",
            "Active process: mpk.exe (PID: 6060)",
            "Path: C:\\Program Files\\Mipko Personal Monitor\\mpk.exe",
        )
        .with_data(EvidenceData::Process {
            pid: 6060,
            name: "mpk.exe".to_string(),
            exe_path: Some("C:\\Program Files\\Mipko Personal Monitor\\mpk.exe".to_string()),
            command_line: None,
        }),
    ];

    let (_, findings) = scoring.evaluate(&evidence);
    assert!(findings.iter().any(|f| f.rule_id == "STK-WIN-0100"), "Mipko must be detected");
    let f = findings.iter().find(|f| f.rule_id == "STK-WIN-0100").unwrap();
    assert_eq!(f.category, Category::KeyboardCapture);
    assert_eq!(f.removal_policy, RemovalPolicy::SafeAuto);
}

#[test]
fn test_searchinform_dlp_detection() {
    let rules = get_embedded_rules();
    let scoring = ScoringEngine::new(&rules, Lang::En);

    let evidence = vec![
        Evidence::new(
            EvidenceType::SystemDaemonService,
            "WindowsServicesCollector",
            "Windows Service: 'SearchInform' (SearchInform)",
            "C:\\Program Files\\SearchInform\\EndpointController.exe",
        )
        .with_data(EvidenceData::Service {
            name: "SearchInform".to_string(),
            display_name: Some("SearchInform Endpoint Controller".to_string()),
            binary_path: Some("C:\\Program Files\\SearchInform\\EndpointController.exe".to_string()),
            start_type: Some("Auto".to_string()),
        }),
    ];

    let (_, findings) = scoring.evaluate(&evidence);
    assert!(findings.iter().any(|f| f.rule_id == "CORP-ALL-0031"), "SearchInform DLP must be detected");
    let f = findings.iter().find(|f| f.rule_id == "CORP-ALL-0031").unwrap();
    assert_eq!(f.category, Category::OrganizationManaged);
    assert_eq!(f.removal_policy, RemovalPolicy::DoNotRemove);
}

