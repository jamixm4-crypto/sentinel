use colored::*;
#[cfg(target_os = "macos")]
use std::path::PathBuf;
use std::process::Command;

use sentinel_core::Lang;

pub fn install_schedule(
    _daily: bool,
    hourly: bool,
    on_logon: bool,
    time: &str,
    lang: Lang,
) -> Result<(), String> {
    let current_exe = std::env::current_exe()
        .map_err(|e| format!("Failed to determine current executable path: {}", e))?;
    let exe_str = current_exe.to_string_lossy().to_string();

    #[cfg(target_os = "windows")]
    {
        let sc = if on_logon {
            "ONLOGON"
        } else if hourly {
            "HOURLY"
        } else {
            "DAILY"
        };

        let mut args = vec![
            "/Create",
            "/TN",
            "SentinelSurveillanceAudit",
            "/TR",
        ];
        let task_run = format!("\"{}\" scan --quiet", exe_str);
        args.push(&task_run);
        args.extend(&["/SC", sc]);

        if sc == "DAILY" {
            args.extend(&["/ST", time]);
        }
        args.push("/F");

        let status = Command::new("schtasks")
            .args(&args)
            .status()
            .map_err(|e| format!("Failed to invoke schtasks.exe: {}", e))?;

        if status.success() {
            match lang {
                Lang::Ru => println!(
                    "{} Задача 'SentinelSurveillanceAudit' успешно зарегистрирована в планировщике Windows (Режим: {}, Время: {}).",
                    "✔".green().bold(), sc.cyan(), time.yellow()
                ),
                Lang::En => println!(
                    "{} Task 'SentinelSurveillanceAudit' successfully registered in Windows Task Scheduler (Schedule: {}, Time: {}).",
                    "✔".green().bold(), sc.cyan(), time.yellow()
                ),
            }
            Ok(())
        } else {
            Err(format!("schtasks.exe failed with exit code: {:?}", status.code()))
        }
    }

    #[cfg(target_os = "linux")]
    {
        let user_systemd_dir = dirs::config_dir()
            .ok_or_else(|| "Could not determine user config directory".to_string())?
            .join("systemd/user");
        std::fs::create_dir_all(&user_systemd_dir)
            .map_err(|e| format!("Failed to create systemd user dir: {}", e))?;

        let service_content = format!(
            "[Unit]\nDescription=Sentinel Surveillance Background Audit\n\n[Service]\nType=oneshot\nExecStart=\"{}\" scan --quiet\n",
            exe_str
        );
        std::fs::write(user_systemd_dir.join("sentinel-audit.service"), service_content)
            .map_err(|e| format!("Failed to write service file: {}", e))?;

        let on_calendar = if hourly { "hourly" } else { "daily" };
        let timer_content = format!(
            "[Unit]\nDescription=Run Sentinel Audit Regularly\n\n[Timer]\nOnCalendar={}\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n",
            on_calendar
        );
        std::fs::write(user_systemd_dir.join("sentinel-audit.timer"), timer_content)
            .map_err(|e| format!("Failed to write timer file: {}", e))?;

        let _ = Command::new("systemctl").args(["--user", "daemon-reload"]).status();
        let status = Command::new("systemctl")
            .args(["--user", "enable", "--now", "sentinel-audit.timer"])
            .status()
            .map_err(|e| format!("Failed to enable systemd timer: {}", e))?;

        if status.success() {
            println!("✔ Sentinel systemd user timer successfully activated.");
            Ok(())
        } else {
            Err("Failed to start systemd timer via systemctl".to_string())
        }
    }

    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").map_err(|_| "HOME not set".to_string())?;
        let launch_agents = PathBuf::from(home).join("Library/LaunchAgents");
        std::fs::create_dir_all(&launch_agents).map_err(|e| e.to_string())?;
        let plist_path = launch_agents.join("com.sentinel.audit.plist");

        let plist_content = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.sentinel.audit</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>scan</string>
        <string>--quiet</string>
    </array>
    <key>StartInterval</key>
    <integer>{}</integer>
</dict>
</plist>"#,
            exe_str,
            if hourly { 3600 } else { 86400 }
        );
        std::fs::write(&plist_path, plist_content).map_err(|e| e.to_string())?;
        let _ = Command::new("launchctl").args(["load", &plist_path.to_string_lossy()]).status();
        println!("✔ Sentinel LaunchAgent successfully configured.");
        Ok(())
    }
}

pub fn check_schedule_status(lang: Lang) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let output = Command::new("schtasks")
            .args(["/Query", "/TN", "SentinelSurveillanceAudit", "/FO", "LIST", "/V"])
            .output()
            .map_err(|e| format!("Failed to query schtasks: {}", e))?;

        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            match lang {
                Lang::Ru => println!("{}\n{}", "Статус задачи в планировщике Windows:".bold().cyan(), text),
                Lang::En => println!("{}\n{}", "Windows Task Scheduler status:".bold().cyan(), text),
            }
            Ok(())
        } else {
            match lang {
                Lang::Ru => println!("{}", "Задача 'SentinelSurveillanceAudit' не установлена в планировщике.".yellow()),
                Lang::En => println!("{}", "Task 'SentinelSurveillanceAudit' is not scheduled.".yellow()),
            }
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("systemctl")
            .args(["--user", "status", "sentinel-audit.timer"])
            .output()
            .map_err(|e| format!("Failed to query systemctl: {}", e))?;
        println!("{}", String::from_utf8_lossy(&output.stdout));
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        let output = Command::new("launchctl")
            .args(["list"])
            .output()
            .map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&output.stdout);
        if text.contains("com.sentinel.audit") {
            println!("✔ com.sentinel.audit is actively loaded in launchctl.");
        } else {
            println!("Sentinel LaunchAgent is not currently loaded.");
        }
        Ok(())
    }
}

pub fn remove_schedule(lang: Lang) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let status = Command::new("schtasks")
            .args(["/Delete", "/TN", "SentinelSurveillanceAudit", "/F"])
            .status()
            .map_err(|e| format!("Failed to delete task via schtasks: {}", e))?;

        if status.success() {
            match lang {
                Lang::Ru => println!("{}", "✔ Задача 'SentinelSurveillanceAudit' удалена из планировщика Windows.".green().bold()),
                Lang::En => println!("{}", "✔ Task 'SentinelSurveillanceAudit' deleted from Windows Task Scheduler.".green().bold()),
            }
            Ok(())
        } else {
            Err("Failed to remove task from Windows Task Scheduler (task might not exist)".to_string())
        }
    }

    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("systemctl").args(["--user", "disable", "--now", "sentinel-audit.timer"]).status();
        if let Some(cfg) = dirs::config_dir() {
            let dir = cfg.join("systemd/user");
            let _ = std::fs::remove_file(dir.join("sentinel-audit.service"));
            let _ = std::fs::remove_file(dir.join("sentinel-audit.timer"));
        }
        let _ = Command::new("systemctl").args(["--user", "daemon-reload"]).status();
        println!("✔ Sentinel systemd timer and service removed.");
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            let plist = PathBuf::from(home).join("Library/LaunchAgents/com.sentinel.audit.plist");
            let _ = Command::new("launchctl").args(["unload", &plist.to_string_lossy()]).status();
            let _ = std::fs::remove_file(plist);
        }
        println!("✔ Sentinel LaunchAgent removed.");
        Ok(())
    }
}
