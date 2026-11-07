use colored::*;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

use sentinel_core::Lang;

pub struct MobileAuditFinding {
    pub package_name: String,
    pub threat_name: String,
    pub severity: &'static str,
    pub description: String,
}

pub fn scan_connected_mobile_device(lang: Lang, custom_ios_backup: Option<&Path>) -> Result<(), String> {
    println!();
    match lang {
        Lang::Ru => println!("{}", "📱 ЗАПУСК АУДИТА МОБИЛЬНЫХ УСТРОЙСТВ (ANDROID ADB & IOS BACKUPS)".bold().cyan()),
        Lang::En => println!("{}", "📱 LAUNCHING MOBILE DEVICE AUDIT (ANDROID ADB & IOS BACKUPS)".bold().cyan()),
    }
    println!("{}", "─".repeat(70).dimmed());

    // 1. Audit Android Devices via ADB
    audit_android_devices(lang);

    // 2. Audit iOS Local Backups (iTunes / Finder / MVT style)
    audit_ios_backups(lang, custom_ios_backup);

    Ok(())
}

fn audit_android_devices(lang: Lang) {
    match lang {
        Lang::Ru => println!("\n{}", "🤖 Проверка Android устройств через ADB...".bold()),
        Lang::En => println!("\n{}", "🤖 Auditing Android Devices via ADB...".bold()),
    }

    let adb_check = Command::new("adb").arg("version").output();
    if adb_check.is_err() {
        match lang {
            Lang::Ru => {
                println!("{}", "  ⚠️ Утилита 'adb' (Android Debug Bridge) не найдена в PATH.".yellow());
                println!("    Для проверки Android: установите adb ('winget install Google.PlatformTools' или 'sudo apt install adb')");
                println!("    и включите 'Отладка по USB' в настройках смартфона для разработчиков.");
            }
            Lang::En => {
                println!("{}", "  ⚠️ 'adb' (Android Debug Bridge) was not found in system PATH.".yellow());
                println!("    To audit Android: install adb ('winget install Google.PlatformTools' or 'brew install android-platform-tools')");
                println!("    and enable 'USB Debugging' in Developer Options on your phone.");
            }
        }
        return;
    }

    let devices_output = match Command::new("adb").args(["devices"]).output() {
        Ok(o) => o,
        Err(e) => {
            println!("  {} Failed to execute adb: {}", "✖".red(), e);
            return;
        }
    };

    let devices_str = String::from_utf8_lossy(&devices_output.stdout);
    let mut attached_devices = Vec::new();
    for line in devices_str.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && parts[1] == "device" {
            attached_devices.push(parts[0].to_string());
        }
    }

    if attached_devices.is_empty() {
        match lang {
            Lang::Ru => println!("  ℹ️ Нет авторизованных устройств Android, подключенных по USB кабелю."),
            Lang::En => println!("  ℹ️ No authorized Android devices currently connected via USB."),
        }
        return;
    }

    for dev in &attached_devices {
        println!("  {} {}...", "🔍 Сканирование устройства:".bold(), dev.cyan());

        let mut findings = Vec::new();

        // Check installed packages
        if let Ok(pkg_out) = Command::new("adb").args(["-s", dev, "shell", "pm", "list", "packages", "-u"]).output() {
            let pkg_text = String::from_utf8_lossy(&pkg_out.stdout);
            for line in pkg_text.lines() {
                if let Some(pkg) = line.strip_prefix("package:") {
                    let pkg_lower = pkg.to_lowercase();
                    if pkg_lower.contains("mspy")
                        || pkg_lower.contains("spappmonitoring")
                        || pkg_lower.contains("cerberus")
                        || pkg_lower.contains("snoopza")
                        || pkg_lower.contains("kidsguard")
                        || pkg_lower.contains("clevguard")
                        || pkg_lower.contains("hoverwatch")
                        || pkg_lower.contains("trackview")
                        || pkg_lower.contains("mobiletracker")
                        || pkg_lower.contains("spyhuman")
                        || pkg_lower.contains("ikeymonitor")
                        || pkg_lower.contains("flexispy")
                        || pkg_lower.contains("cocospy")
                        || pkg_lower.contains("spyic")
                        || pkg_lower.contains("thetruthspy")
                        || pkg_lower.contains("highster")
                        || pkg_lower.contains("app.system.service")
                        || pkg_lower.contains("com.android.core.sync")
                    {
                        findings.push(MobileAuditFinding {
                            package_name: pkg.to_string(),
                            threat_name: "Covert Android Stalkerware / Spyware".to_string(),
                            severity: "Critical",
                            description: format!("Known stalkerware signature in package list: {}", pkg),
                        });
                    }
                }
            }
        }

        // Check accessibility services
        if let Ok(access_out) = Command::new("adb").args(["-s", dev, "shell", "settings", "get", "secure", "enabled_accessibility_services"]).output() {
            let access_str = String::from_utf8_lossy(&access_out.stdout);
            if !access_str.is_empty() && access_str.trim() != "null" {
                for service in access_str.split(':') {
                    let s_trimmed = service.trim();
                    if !s_trimmed.is_empty()
                        && !s_trimmed.contains("google")
                        && !s_trimmed.contains("talkback")
                        && !s_trimmed.contains("samsung")
                    {
                        findings.push(MobileAuditFinding {
                            package_name: s_trimmed.to_string(),
                            threat_name: "High-Risk Accessibility Service Active".to_string(),
                            severity: "High",
                            description: format!("Non-system service granted full Accessibility privileges: {}", s_trimmed),
                        });
                    }
                }
            }
        }

        // Check active Device Administrators
        if let Ok(admin_out) = Command::new("adb").args(["-s", dev, "shell", "dpm", "list-active-admins"]).output() {
            let admin_str = String::from_utf8_lossy(&admin_out.stdout);
            for line in admin_str.lines() {
                let l_trim = line.trim();
                if l_trim.contains('/') && !l_trim.contains("google") && !l_trim.contains("samsung") && !l_trim.contains("android") {
                    findings.push(MobileAuditFinding {
                        package_name: l_trim.to_string(),
                        threat_name: "Elevated Device Administrator App Active".to_string(),
                        severity: "High",
                        description: format!("Third-party app holds device administration rights (anti-uninstall/remote wipe): {}", l_trim),
                    });
                }
            }
        }

        // Check notification listeners
        if let Ok(notif_out) = Command::new("adb").args(["-s", dev, "shell", "settings", "get", "secure", "enabled_notification_listeners"]).output() {
            let notif_str = String::from_utf8_lossy(&notif_out.stdout);
            if !notif_str.is_empty() && notif_str.trim() != "null" {
                for listener in notif_str.split(':') {
                    let l_trim = listener.trim();
                    if !l_trim.is_empty() && !l_trim.contains("google") && !l_trim.contains("samsung") && !l_trim.contains("android") {
                        findings.push(MobileAuditFinding {
                            package_name: l_trim.to_string(),
                            threat_name: "Notification Listener Service (SMS/Chat Interception)".to_string(),
                            severity: "Medium",
                            description: format!("App can intercept all incoming notifications and 2FA codes: {}", l_trim),
                        });
                    }
                }
            }
        }

        // Report findings
        if findings.is_empty() {
            match lang {
                Lang::Ru => println!("    ✔ Устройство чисто: известных пакетов stalkerware, скрытых служб accessibility и подозрительных admin-прав не обнаружено."),
                Lang::En => println!("    ✔ Device clean: no known stalkerware packages, covert accessibility services, or rogue device admin rights found."),
            }
        } else {
            for f in &findings {
                println!("    • [{}] {} — {}", f.severity.red().bold(), f.threat_name.bold(), f.package_name.yellow());
                println!("      {}", f.description.dimmed());
            }
        }
    }
}

fn audit_ios_backups(lang: Lang, custom_path: Option<&Path>) {
    match lang {
        Lang::Ru => println!("\n{}", "🍏 Проверка локальных резервных копий iOS (iTunes / Finder)...".bold()),
        Lang::En => println!("\n{}", "🍏 Auditing Local iOS Backups (iTunes / Finder)...".bold()),
    }

    let search_roots = if let Some(p) = custom_path {
        vec![p.to_path_buf()]
    } else {
        get_default_ios_backup_dirs()
    };

    let mut found_backups = 0;

    for root in search_roots {
        if !root.is_dir() {
            continue;
        }

        if let Ok(entries) = std::fs::read_dir(&root) {
            for entry in entries.filter_map(Result::ok) {
                let backup_dir = entry.path();
                if backup_dir.is_dir() {
                    let manifest_file = backup_dir.join("Manifest.plist");
                    let info_file = backup_dir.join("Info.plist");
                    let status_file = backup_dir.join("Status.plist");

                    if manifest_file.exists() || info_file.exists() || status_file.exists() {
                        found_backups += 1;
                        let dir_name = backup_dir.file_name().unwrap_or_default().to_string_lossy();
                        println!("  {} {} ({})", "🔍 Резервная копия iOS:".bold(), dir_name.cyan(), backup_dir.display());

                        let mut ios_findings = Vec::new();

                        // Scan Info.plist / Manifest for known iOS stalkerware bundle IDs
                        let mut content = String::new();
                        if let Ok(c) = std::fs::read_to_string(&info_file) {
                            content.push_str(&c);
                        }
                        if let Ok(c) = std::fs::read_to_string(&manifest_file) {
                            content.push_str(&c);
                        }

                        let content_lower = content.to_lowercase();
                        let known_ios_spyware = [
                            ("com.mspyonline", "mSpy iOS Monitoring Profile"),
                            ("com.ikeymonitor", "iKeyMonitor iOS Stalkerware"),
                            ("com.flexispy", "FlexiSPY iOS Spyware"),
                            ("com.clevguard", "KidsGuard / ClevGuard iOS Tracker"),
                            ("com.hoverwatch", "Hoverwatch iOS Profile"),
                            ("com.spappmonitoring", "SPAPP Monitoring iOS"),
                            ("com.tigersprout", "TigerSprout Spyware"),
                            ("org.cydia", "Cydia Substrate (Jailbreak / Unrestricted Root)"),
                            ("com.saurik.cydia", "Cydia Installer (Jailbreak Environment)"),
                            ("org.coolstar.sileostore", "Sileo Package Manager (Jailbreak Environment)"),
                            ("com.unc0ver", "unc0ver Jailbreak Artifact"),
                        ];

                        for (bundle, name) in &known_ios_spyware {
                            if content_lower.contains(bundle) {
                                ios_findings.push(MobileAuditFinding {
                                    package_name: bundle.to_string(),
                                    threat_name: name.to_string(),
                                    severity: "Critical",
                                    description: format!("Identified stalkerware/jailbreak bundle ID in backup metadata: {}", bundle),
                                });
                            }
                        }

                        if ios_findings.is_empty() {
                            match lang {
                                Lang::Ru => println!("    ✔ В резервной копии не обнаружено признаков джейлбрейка и известных stalkerware-профилей."),
                                Lang::En => println!("    ✔ Backup clean: no jailbreak indicators or known stalkerware profiles identified."),
                            }
                        } else {
                            for f in &ios_findings {
                                println!("    • [{}] {} — {}", f.severity.red().bold(), f.threat_name.bold(), f.package_name.yellow());
                                println!("      {}", f.description.dimmed());
                            }
                        }
                    }
                }
            }
        }
    }

    if found_backups == 0 {
        match lang {
            Lang::Ru => {
                println!("  ℹ️ Локальные резервные копии iOS не найдены в стандартных каталогах.");
                println!("    Для анализа iPhone подключите его к ПК через iTunes/Finder, создайте локальную резервную копию и повторите скан.");
                println!("    Или укажите путь вручную: 'sentinel mobile scan --ios /path/to/backup'.");
            }
            Lang::En => {
                println!("  ℹ️ No local iOS backups detected in standard backup directories.");
                println!("    To audit an iPhone, connect it via USB to iTunes/Finder, create an unencrypted local backup, and rerun scan.");
                println!("    Or specify path manually: 'sentinel mobile scan --ios /path/to/backup'.");
            }
        }
    }

    println!();
}

fn get_default_ios_backup_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    #[cfg(target_os = "windows")]
    {
        if let Some(appdata) = dirs::data_dir() {
            dirs.push(appdata.join("Apple Computer").join("MobileSync").join("Backup"));
            dirs.push(appdata.join("Apple").join("MobileSync").join("Backup"));
        }
        if let Some(user_prof) = dirs::home_dir() {
            dirs.push(user_prof.join("Apple").join("MobileSync").join("Backup"));
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = dirs::home_dir() {
            dirs.push(home.join("Library").join("Application Support").join("MobileSync").join("Backup"));
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(home) = dirs::home_dir() {
            dirs.push(home.join(".local").join("share").join("MobileSync").join("Backup"));
        }
    }

    dirs
}

/// Import and correlate Mobile Verification Toolkit (MVT) audit records
pub fn import_mvt_results(lang: Lang, path: &Path) -> Result<Vec<MobileAuditFinding>, String> {
    if !path.exists() {
        return Err(format!("Specified MVT path does not exist: {}", path.display()));
    }

    match lang {
        Lang::Ru => {
            println!("\n{}", "📱 ИМПОРТ И КОРРЕЛЯЦИЯ РЕЗУЛЬТАТОВ MVT (MOBILE VERIFICATION TOOLKIT)".bold().cyan());
            println!("  Источник: {}", path.display());
            println!("{}", "─".repeat(70).dimmed());
        }
        Lang::En => {
            println!("\n{}", "📱 IMPORTING & CORRELATING MVT (MOBILE VERIFICATION TOOLKIT) RESULTS".bold().cyan());
            println!("  Source: {}", path.display());
            println!("{}", "─".repeat(70).dimmed());
        }
    }

    let mut json_files = Vec::new();
    if path.is_file() {
        json_files.push(path.to_path_buf());
    } else if path.is_dir() {
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.filter_map(Result::ok) {
                let p = entry.path();
                if p.is_file() && p.extension().and_then(|e| e.to_str()) == Some("json") {
                    json_files.push(p);
                }
            }
        }
    }

    if json_files.is_empty() {
        match lang {
            Lang::Ru => return Err("В указанной директории не найдены JSON-отчеты MVT.".to_string()),
            Lang::En => return Err("No MVT JSON report files found in the specified directory.".to_string()),
        }
    }

    let mut findings = Vec::new();
    let mut inspected_files = 0;
    let mut total_records = 0;

    for file_path in &json_files {
        inspected_files += 1;
        let file_name = file_path.file_name().unwrap_or_default().to_string_lossy().to_string();

        let content = match std::fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let json_val: Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => {
                let mut lines_findings = Vec::new();
                for line in content.lines() {
                    if let Ok(item) = serde_json::from_str::<Value>(line) {
                        total_records += 1;
                        check_mvt_record(&item, &file_name, &mut lines_findings);
                    }
                }
                findings.extend(lines_findings);
                continue;
            }
        };

        if let Value::Array(arr) = json_val {
            total_records += arr.len();
            for item in arr {
                check_mvt_record(&item, &file_name, &mut findings);
            }
        } else if let Value::Object(_) = json_val {
            total_records += 1;
            check_mvt_record(&json_val, &file_name, &mut findings);
        }
    }

    match lang {
        Lang::Ru => {
            println!("  ✔ Проанализировано файлов MVT: {}", inspected_files);
            println!("  ✔ Проверено записей (история, пакеты, дампы): {}", total_records);
        }
        Lang::En => {
            println!("  ✔ Inspected MVT files: {}", inspected_files);
            println!("  ✔ Analyzed forensic records: {}", total_records);
        }
    }

    if findings.is_empty() {
        match lang {
            Lang::Ru => println!("\n{}", "  ✔ Корреляция с базой Sentinel: совпадений с известными C2 и сталкерваром не найдено.".green().bold()),
            Lang::En => println!("\n{}", "  ✔ Sentinel correlation clean: no matches with known C2 servers or stalkerware signatures.".green().bold()),
        }
    } else {
        println!();
        match lang {
            Lang::Ru => println!("{}", format!("  ⚠️ ОБНАРУЖЕНО УГРОЗ В ДАМПАХ MVT: {}", findings.len()).red().bold()),
            Lang::En => println!("{}", format!("  ⚠️ THREATS IDENTIFIED IN MVT AUDIT: {}", findings.len()).red().bold()),
        }

        for f in &findings {
            println!("    • [{}] {} — {}", f.severity.red().bold(), f.threat_name.bold(), f.package_name.yellow());
            println!("      {}", f.description.dimmed());
        }
    }
    println!();

    Ok(findings)
}

fn check_mvt_record(item: &Value, source_file: &str, findings: &mut Vec<MobileAuditFinding>) {
    // 1. Direct MVT detections (detected.json)
    if let Some(indicator) = item.get("matched_indicator").or_else(|| item.get("indicator")).and_then(|v| v.as_str()) {
        let threat = item.get("threat_name").or_else(|| item.get("module")).and_then(|v| v.as_str()).unwrap_or("MVT Detected Spyware IOC");
        findings.push(MobileAuditFinding {
            package_name: indicator.to_string(),
            threat_name: format!("MVT Spyware Detection ({})", threat),
            severity: "Critical",
            description: format!("Forensic IOC matched by MVT in '{}': {}", source_file, indicator),
        });
    }

    // 2. URLs and Domains cross-check with Sentinel C2 database
    if let Some(url_str) = item.get("url").or_else(|| item.get("domain")).or_else(|| item.get("host")).and_then(|v| v.as_str()) {
        let domain_candidate = url_str
            .trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or(url_str)
            .split(':')
            .next()
            .unwrap_or(url_str);

        if let Some(matched_c2) = sentinel_rules::matches_known_c2(domain_candidate) {
            findings.push(MobileAuditFinding {
                package_name: url_str.to_string(),
                threat_name: format!("Stalkerware Command & Control Beacon ({})", matched_c2),
                severity: "Critical",
                description: format!("Observed connection to known C2 server in forensic log '{}': {}", source_file, url_str),
            });
        }
    }

    // 3. Android package or iOS bundle ID checks
    if let Some(pkg) = item.get("package_name").or_else(|| item.get("bundle_id")).or_else(|| item.get("package")).and_then(|v| v.as_str()) {
        let pkg_lower = pkg.to_lowercase();
        if pkg_lower.contains("mspy")
            || pkg_lower.contains("flexispy")
            || pkg_lower.contains("ikeymonitor")
            || pkg_lower.contains("spappmonitoring")
            || pkg_lower.contains("hoverwatch")
            || pkg_lower.contains("snoopza")
            || pkg_lower.contains("clevguard")
            || pkg_lower.contains("cerberus")
            || pkg_lower.contains("cocospy")
            || pkg_lower.contains("spyic")
        {
            findings.push(MobileAuditFinding {
                package_name: pkg.to_string(),
                threat_name: "Stalkerware Mobile Package / Bundle".to_string(),
                severity: "Critical",
                description: format!("Forensic record in '{}' identified stalkerware package: {}", source_file, pkg),
            });
        }
    }
}
