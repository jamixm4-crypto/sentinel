//! Sentinel Scoring - Enhanced Allowlist & Process Impersonation Analysis
//!
//! Provides granular verification for trusted operating system binaries and
//! detects process masquerading (MITRE ATT&CK T1036.005) when malicious tools
//! disguise themselves as svchost.exe, lsass.exe, or csrss.exe.

/// Check if a binary name represents a critical operating system process
pub fn is_system_binary_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    matches!(
        lower.as_str(),
        "explorer.exe"
            | "dwm.exe"
            | "csrss.exe"
            | "smss.exe"
            | "services.exe"
            | "lsass.exe"
            | "svchost.exe"
            | "wininit.exe"
            | "winlogon.exe"
            | "taskhostw.exe"
            | "runtimebroker.exe"
            | "fontdrvhost.exe"
            | "sihost.exe"
            | "ctfmon.exe"
            | "systemd"
            | "init"
            | "kthreadd"
            | "pipewire"
            | "wireplumber"
            | "launchd"
            | "windowserver"
            | "loginwindow"
    )
}

/// Backwards-compatible alias for checking if process name is a system binary
pub fn is_system_allowlisted_process(name: &str) -> bool {
    is_system_binary_name(name)
}

/// Check if a binary path is part of the standard OS directory
pub fn is_trusted_system_path(path: &str) -> bool {
    let lower = path.to_lowercase().replace('/', "\\");
    
    // Windows system locations
    if lower.contains(r"\windows\system32\")
        || lower.contains(r"\windows\syswow64\")
        || lower.ends_with(r"\windows\explorer.exe")
    {
        return true;
    }

    // Unix / macOS system locations
    if lower.starts_with("/system/library/")
        || lower.starts_with("/usr/lib/")
        || lower.starts_with("/usr/bin/")
        || lower.starts_with("/bin/")
        || lower.starts_with("/sbin/")
    {
        return true;
    }

    false
}

/// Detects if an active process is masquerading as a Windows system binary (MITRE T1036.005).
/// If a process names itself `svchost.exe`, `csrss.exe`, `lsass.exe`, etc. but runs from
/// a user directory (%APPDATA%, %TEMP%, %USERPROFILE%, ProgramData), it is anomalous.
pub fn is_masquerading_system_process(name: &str, exe_path: Option<&str>) -> bool {
    let lower_name = name.to_lowercase();

    // Critical Windows system binaries that should NEVER run from user profiles or temp dirs
    let is_critical_win_binary = matches!(
        lower_name.as_str(),
        "svchost.exe"
            | "csrss.exe"
            | "lsass.exe"
            | "services.exe"
            | "smss.exe"
            | "wininit.exe"
            | "winlogon.exe"
            | "taskhostw.exe"
            | "runtimebroker.exe"
            | "fontdrvhost.exe"
            | "sihost.exe"
            | "dwm.exe"
    );

    if !is_critical_win_binary {
        return false;
    }

    if let Some(path) = exe_path {
        let lower_path = path.to_lowercase().replace('/', "\\");

        // If path is inside user profile, temp, downloads or programdata, it's definitely masquerading
        if lower_path.contains(r"\appdata\")
            || lower_path.contains(r"\temp\")
            || lower_path.contains(r"\users\")
            || lower_path.contains(r"\programdata\")
        {
            return true;
        }

        // If it does not belong to Windows system folders at all
        if !lower_path.contains(r"\windows\system32\") && !lower_path.contains(r"\windows\syswow64\") {
            return true;
        }
    }

    false
}

/// Known benign consumer and developer applications that frequently capture screen/input
/// legitimately (e.g. streaming, game overlays, accessibility screen readers).
pub fn is_known_benign_app(name: &str, exe_path: Option<&str>) -> bool {
    let lower_name = name.to_lowercase();
    let is_benign_name = matches!(
        lower_name.as_str(),
        "obs64.exe"
            | "obs32.exe"
            | "obs.exe"
            | "discord.exe"
            | "discordcanary.exe"
            | "discordptb.exe"
            | "steam.exe"
            | "gameoverlayui.exe"
            | "nvspcaps64.exe"
            | "nvcontainer.exe"
            | "rtss.exe"
            | "rivatuner.exe"
            | "nvda.exe"
            | "nvda_slave.exe"
            | "narrator.exe"
            | "code.exe"
            | "devenv.exe"
            | "zoom.exe"
            | "slack.exe"
    );

    if !is_benign_name {
        return false;
    }

    // Verify path if present (must not run out of Temp)
    if let Some(path) = exe_path {
        let lower_path = path.to_lowercase().replace('/', "\\");
        if lower_path.contains(r"\temp\") {
            return false; // Suspicious execution from temp directory
        }
    }

    true
}
