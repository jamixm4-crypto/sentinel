use sentinel_core::{Evidence, EvidenceData, EvidenceType};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::{Collector, CollectorContext};

pub struct BrowserExtensionsCollector;

impl Collector for BrowserExtensionsCollector {
    fn name(&self) -> &'static str {
        "BrowserExtensionsCollector"
    }

    fn collect(&self, _ctx: &CollectorContext) -> Result<Vec<Evidence>, String> {
        let mut evidence = Vec::new();

        let browser_paths = get_browser_user_data_paths();
        for (browser_name, base_path) in browser_paths {
            if !base_path.exists() {
                continue;
            }

            if browser_name == "Firefox" {
                collect_firefox_extensions(&base_path, &mut evidence);
            } else {
                collect_chromium_extensions(&browser_name, &base_path, &mut evidence);
            }
        }

        Ok(evidence)
    }
}

fn get_browser_user_data_paths() -> Vec<(String, PathBuf)> {
    let mut paths = Vec::new();

    #[cfg(target_os = "windows")]
    {
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            let local = PathBuf::from(local_app_data);
            paths.push(("Chrome".to_string(), local.join(r"Google\Chrome\User Data")));
            paths.push(("Edge".to_string(), local.join(r"Microsoft\Edge\User Data")));
            paths.push(("Brave".to_string(), local.join(r"BraveSoftware\Brave-Browser\User Data")));
            paths.push(("Yandex".to_string(), local.join(r"Yandex\YandexBrowser\User Data")));
        }
        if let Ok(app_data) = std::env::var("APPDATA") {
            let roaming = PathBuf::from(app_data);
            paths.push(("Opera".to_string(), roaming.join(r"Opera Software\Opera Stable\Extensions")));
            paths.push(("Firefox".to_string(), roaming.join(r"Mozilla\Firefox\Profiles")));
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(home) = std::env::var("HOME") {
            let h = PathBuf::from(home);
            paths.push(("Chrome".to_string(), h.join(".config/google-chrome")));
            paths.push(("Edge".to_string(), h.join(".config/microsoft-edge")));
            paths.push(("Brave".to_string(), h.join(".config/BraveSoftware/Brave-Browser")));
            paths.push(("Firefox".to_string(), h.join(".mozilla/firefox")));
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            let h = PathBuf::from(home);
            let app_sup = h.join("Library/Application Support");
            paths.push(("Chrome".to_string(), app_sup.join("Google/Chrome")));
            paths.push(("Edge".to_string(), app_sup.join("Microsoft Edge")));
            paths.push(("Brave".to_string(), app_sup.join("BraveSoftware/Brave-Browser")));
            paths.push(("Firefox".to_string(), app_sup.join("Firefox/Profiles")));
        }
    }

    paths
}

fn collect_chromium_extensions(browser: &str, user_data_dir: &Path, evidence: &mut Vec<Evidence>) {
    // If user_data_dir itself ends with Extensions (like Opera)
    let search_roots = if user_data_dir.ends_with("Extensions") {
        vec![user_data_dir.to_path_buf()]
    } else {
        let mut roots = Vec::new();
        if let Ok(entries) = fs::read_dir(user_data_dir) {
            for entry in entries.filter_map(Result::ok) {
                let path = entry.path();
                if path.is_dir() {
                    let dir_name = entry.file_name().to_string_lossy().to_string();
                    if dir_name == "Default" || dir_name.starts_with("Profile ") {
                        let ext_dir = path.join("Extensions");
                        if ext_dir.is_dir() {
                            roots.push(ext_dir);
                        }
                    }
                }
            }
        }
        roots
    };

    for ext_root in search_roots {
        if let Ok(ext_entries) = fs::read_dir(&ext_root) {
            for ext_entry in ext_entries.filter_map(Result::ok) {
                let ext_id_path = ext_entry.path();
                if !ext_id_path.is_dir() {
                    continue;
                }
                let ext_id = ext_entry.file_name().to_string_lossy().to_string();

                // Each extension id directory contains version subdirectories
                if let Ok(ver_entries) = fs::read_dir(&ext_id_path) {
                    for ver_entry in ver_entries.filter_map(Result::ok) {
                        let ver_path = ver_entry.path();
                        if !ver_path.is_dir() {
                            continue;
                        }
                        let manifest_path = ver_path.join("manifest.json");
                        if manifest_path.is_file() {
                            parse_and_record_manifest(browser, &ext_id, &manifest_path, evidence);
                        }
                    }
                }
            }
        }
    }
}

fn parse_and_record_manifest(
    browser: &str,
    ext_id: &str,
    manifest_path: &Path,
    evidence: &mut Vec<Evidence>,
) {
    let content = match fs::read_to_string(manifest_path) {
        Ok(c) => c,
        Err(_) => return,
    };

    let v: Value = match serde_json::from_str(&content) {
        Ok(val) => val,
        Err(_) => return,
    };

    let name = v["name"].as_str().unwrap_or("Unknown Extension").to_string();
    let version = v["version"].as_str().unwrap_or("0.0.0").to_string();

    let mut permissions = Vec::new();
    if let Some(perms) = v["permissions"].as_array() {
        for p in perms {
            if let Some(s) = p.as_str() {
                permissions.push(s.to_string());
            }
        }
    }
    if let Some(host_perms) = v["host_permissions"].as_array() {
        for p in host_perms {
            if let Some(s) = p.as_str() {
                permissions.push(s.to_string());
            }
        }
    }

    let is_dangerous = permissions.iter().any(|p| {
        p == "debugger"
            || p == "webRequestBlocking"
            || p == "nativeMessaging"
            || p.contains("<all_urls>")
            || p == "*://*/*"
            || p == "clipboardRead"
    });

    let desc = if is_dangerous {
        format!(
            "Browser Extension with elevated interception permissions: '{}' ({}) in {}",
            name, ext_id, browser
        )
    } else {
        format!(
            "Installed browser extension: '{}' ({}) in {}",
            name, ext_id, browser
        )
    };

    let tech = format!(
        "Browser: {}\nExtension ID: {}\nName: {}\nVersion: {}\nPermissions: {}\nManifest: {}",
        browser,
        ext_id,
        name,
        version,
        permissions.join(", "),
        manifest_path.display()
    );

    evidence.push(
        Evidence::new(EvidenceType::BrowserExtension, "BrowserExtensionsCollector", desc, tech)
            .with_data(EvidenceData::BrowserExtension {
                browser: browser.to_string(),
                id: ext_id.to_string(),
                name,
                version,
                permissions,
                path: manifest_path.display().to_string(),
                is_sideloaded: false,
            }),
    );
}

fn collect_firefox_extensions(profiles_dir: &Path, evidence: &mut Vec<Evidence>) {
    for entry in WalkDir::new(profiles_dir).max_depth(3).into_iter().filter_map(Result::ok) {
        if entry.file_name() == "extensions.json" {
            let path = entry.path();
            if let Ok(content) = fs::read_to_string(path) {
                if let Ok(v) = serde_json::from_str::<Value>(&content) {
                    if let Some(addons) = v["addons"].as_array() {
                        for addon in addons {
                            let id = addon["id"].as_str().unwrap_or("unknown").to_string();
                            let name = addon["defaultLocale"]["name"]
                                .as_str()
                                .unwrap_or_else(|| addon["name"].as_str().unwrap_or("Unknown Addon"))
                                .to_string();
                            let version = addon["version"].as_str().unwrap_or("0.0.0").to_string();
                            let active = addon["active"].as_bool().unwrap_or(true);

                            if !active {
                                continue;
                            }

                            let mut perms = Vec::new();
                            if let Some(p_arr) = addon["permissions"].as_array() {
                                for p in p_arr {
                                    if let Some(s) = p.as_str() {
                                        perms.push(s.to_string());
                                    }
                                }
                            }

                            let desc = format!("Firefox Addon: '{}' ({})", name, id);
                            let tech = format!(
                                "Browser: Firefox\nExtension ID: {}\nName: {}\nVersion: {}\nPermissions: {}\nPath: {}",
                                id,
                                name,
                                version,
                                perms.join(", "),
                                path.display()
                            );

                            evidence.push(
                                Evidence::new(
                                    EvidenceType::BrowserExtension,
                                    "BrowserExtensionsCollector",
                                    desc,
                                    tech,
                                )
                                .with_data(EvidenceData::BrowserExtension {
                                    browser: "Firefox".to_string(),
                                    id,
                                    name,
                                    version,
                                    permissions: perms,
                                    path: path.display().to_string(),
                                    is_sideloaded: false,
                                }),
                            );
                        }
                    }
                }
            }
        }
    }
}
