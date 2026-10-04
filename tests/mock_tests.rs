use sentinel_core::{
    Category, Evidence, EvidenceData, EvidenceType, Finding, Lang, PlatformInfo, PrivilegeLevel,
    RemovalPolicy, Severity, Verdict,
};
use sentinel_rules::get_embedded_rules;
use sentinel_scoring::ScoringEngine;

#[test]
fn test_embedded_rules_validity() {
    let rules = get_embedded_rules();
    assert!(!rules.is_empty(), "Embedded rules should not be empty");
    assert!(rules.len() >= 30, "Expected at least 30 embedded rules");

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
            cmdline: None,
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
            cmdline: None,
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
            cmdline: None,
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
        cmdline: None,
    })];

    let (_, findings) = scoring.evaluate(&cs_evidence);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].removal_policy, RemovalPolicy::DoNotRemove);

    // Verify removal manager refuses to remove
    let rm = sentinel_removal::RemovalManager::new(false);
    let remove_result = rm.remove_finding(&findings[0]);
    assert!(remove_result.is_err(), "Must reject removing DoNotRemove software");

    // Verify quarantine manager refuses to quarantine
    let qm = sentinel_removal::QuarantineManager::new();
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
        cmdline: None,
    })];

    let (_, findings) = scoring.evaluate(&mspy_evidence);
    assert!(!findings.is_empty());

    // With personal safety mode active:
    let rm = sentinel_removal::RemovalManager::new(true);
    let res = rm.remove_finding(&findings[0]);
    assert!(res.is_err(), "Personal Safety Mode must forbid removal");
}
