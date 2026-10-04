/// Built-in allowlist of trusted operating system processes
pub fn is_system_allowlisted_process(name: &str) -> bool {
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

/// Check if a binary path is part of the standard OS directory
pub fn is_trusted_system_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    #[cfg(target_os = "windows")]
    {
        lower.starts_with("c:\\windows\\system32\\") || lower.starts_with("c:\\windows\\syswow64\\")
    }
    #[cfg(target_os = "macos")]
    {
        lower.starts_with("/system/library/") || lower.starts_with("/usr/lib/")
    }
    #[cfg(target_os = "linux")]
    {
        lower.starts_with("/usr/bin/") || lower.starts_with("/bin/") || lower.starts_with("/usr/lib/")
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        false
    }
}
