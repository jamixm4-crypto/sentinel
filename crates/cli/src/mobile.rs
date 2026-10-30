use colored::*;
use std::process::Command;

use sentinel_core::Lang;

pub struct MobileAuditFinding {
    pub package_name: String,
    pub threat_name: String,
    pub severity: &'static str,
    pub description: String,
}

pub fn scan_connected_mobile_device(lang: Lang) -> Result<(), String> {
    println!();
    match lang {
        Lang::Ru => println!("{}", "📱 ЗАПУСК АУДИТА ПОДКЛЮЧЕННЫХ МОБИЛЬНЫХ УСТРОЙСТВ (ANDROID ADB)".bold().cyan()),
        Lang::En => println!("{}", "📱 LAUNCHING CONNECTED MOBILE DEVICE AUDIT (ANDROID ADB)".bold().cyan()),
    }
    println!("{}", "─".repeat(70).dimmed());

    // 1. Check if adb is installed
    let adb_check = Command::new("adb").arg("version").output();
    if adb_check.is_err() {
        match lang {
            Lang::Ru => {
                println!("{}", "❌ Утилита 'adb' (Android Debug Bridge) не найдена в системном PATH.".yellow());
                println!("\nДля аудита смартфонов Android на stalkerware:");
                println!("  1. Установите adb: 'winget install Google.PlatformTools' (Windows) или 'sudo apt install adb' (Linux)");
                println!("  2. На телефоне откройте: Настройки > О телефоне > Нажмите 7 раз на 'Номер сборки'");
                println!("  3. В меню 'Для разработчиков' включите 'Отладка по USB'");
                println!("  4. Подключите телефон кабелем к ПК, подтвердите доверие на экране телефона и повторите 'sentinel mobile scan'.");
            }
            Lang::En => {
                println!("{}", "❌ 'adb' (Android Debug Bridge) was not found in system PATH.".yellow());
                println!("\nTo audit Android smartphones for stalkerware:");
                println!("  1. Install adb: 'winget install Google.PlatformTools' (Windows) or 'brew install android-platform-tools' (macOS)");
                println!("  2. On your phone: Settings > About Phone > Tap 'Build Number' 7 times");
                println!("  3. Open 'Developer Options' and enable 'USB Debugging'");
                println!("  4. Connect the phone via USB cable, tap 'Allow USB debugging' on screen, and re-run 'sentinel mobile scan'.");
            }
        }
        return Ok(());
    }

    // 2. Query connected devices
    let devices_output = Command::new("adb")
        .args(["devices"])
        .output()
        .map_err(|e| format!("Failed to run adb devices: {}", e))?;

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
            Lang::Ru => {
                println!("{}", "⚠️ Подключенные устройства Android не обнаружены.".yellow());
                println!("Убедитесь, что телефон подключен по USB-кабелю и на экране смартфона нажато 'Разрешить отладку по USB'.");
            }
            Lang::En => {
                println!("{}", "⚠️ No authorized Android devices detected.".yellow());
                println!("Ensure your phone is connected via USB and you accepted the 'Allow USB debugging' prompt on the device screen.");
            }
        }
        return Ok(());
    }

    for dev in &attached_devices {
        println!("\n{} {}...", "🔍 Сканирование устройства:".bold(), dev.cyan());

        // 3. Query installed packages
        let pkg_out = Command::new("adb")
            .args(["-s", dev, "shell", "pm", "list", "packages", "-u"])
            .output()
            .map_err(|e| format!("Failed to query packages on device {}: {}", dev, e))?;

        let pkg_text = String::from_utf8_lossy(&pkg_out.stdout);
        let packages: Vec<&str> = pkg_text
            .lines()
            .filter_map(|l| l.strip_prefix("package:"))
            .collect();

        // 4. Query accessibility services
        let access_out = Command::new("adb")
            .args(["-s", dev, "shell", "settings", "get", "secure", "enabled_accessibility_services"])
            .output()
            .ok();
        let access_str = access_out
            .as_ref()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();

        let mut findings = Vec::new();

        for pkg in &packages {
            let pkg_lower = pkg.to_lowercase();

            // Match against known stalkerware package signatures
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
                    description: format!("Known stalkerware indicator identified in installed packages: {}", pkg),
                });
            }
        }

        // Check if unknown app holds Accessibility permissions
        if !access_str.is_empty() && access_str.trim() != "null" {
            for service in access_str.split(':') {
                let serv_trimmed = service.trim();
                if !serv_trimmed.is_empty()
                    && !serv_trimmed.contains("google")
                    && !serv_trimmed.contains("talkback")
                    && !serv_trimmed.contains("samsung")
                {
                    findings.push(MobileAuditFinding {
                        package_name: serv_trimmed.to_string(),
                        threat_name: "High-Risk Accessibility Service Active".to_string(),
                        severity: "High",
                        description: format!("Non-system app granted full Accessibility Service: {}", serv_trimmed),
                    });
                }
            }
        }

        if findings.is_empty() {
            match lang {
                Lang::Ru => println!("{}", "  ✔ На смартфоне не обнаружено известных пакетов stalkerware и скрытых служб специальных возможностей.".green().bold()),
                Lang::En => println!("{}", "  ✔ No known stalkerware packages or suspicious accessibility services found on smartphone.".green().bold()),
            }
        } else {
            match lang {
                Lang::Ru => {
                    println!("  {} Обнаружено угроз на телефоне: {}", "🚨".red(), findings.len().to_string().bold().red());
                    for f in &findings {
                        println!("    • [{}] {} — {}", f.severity.red().bold(), f.threat_name.bold(), f.package_name.yellow());
                        println!("      Детали: {}", f.description.dimmed());
                    }
                }
                Lang::En => {
                    println!("  {} Threats detected on phone: {}", "🚨".red(), findings.len().to_string().bold().red());
                    for f in &findings {
                        println!("    • [{}] {} — {}", f.severity.red().bold(), f.threat_name.bold(), f.package_name.yellow());
                        println!("      Details: {}", f.description.dimmed());
                    }
                }
            }
        }
    }

    println!();
    Ok(())
}
