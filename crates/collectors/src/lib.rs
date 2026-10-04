//! Sentinel Collectors - Cross-platform and OS-Specific Evidence Collectors

use sentinel_core::{Evidence, PlatformInfo, PrivilegeLevel, SkippedCheck};
use std::time::Duration;

pub mod common;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

/// Context provided to each collector during scan
#[derive(Debug, Clone)]
pub struct CollectorContext {
    pub platform: PlatformInfo,
    pub privilege_level: PrivilegeLevel,
    pub timeout: Duration,
}

/// Common trait implemented by all evidence collectors
pub trait Collector: Send + Sync {
    /// Human-readable name of the collector
    fn name(&self) -> &'static str;

    /// Required privilege level
    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::StandardUser
    }

    /// Run evidence collection
    fn collect(&self, ctx: &CollectorContext) -> Result<Vec<Evidence>, String>;
}

/// Assemble the complete set of collectors for the active OS
pub fn get_all_collectors() -> Vec<Box<dyn Collector>> {
    let mut collectors: Vec<Box<dyn Collector>> = vec![
        Box::new(common::ProcessCollector),
        Box::new(common::NetworkCollector),
    ];

    #[cfg(target_os = "windows")]
    {
        collectors.push(Box::new(windows::WindowsPersistenceCollector));
        collectors.push(Box::new(windows::WindowsConsentStoreCollector));
        collectors.push(Box::new(windows::WindowsDriversCollector));
        collectors.push(Box::new(windows::WindowsInstalledSoftwareCollector));
        collectors.push(Box::new(windows::WindowsCertificatesCollector));
    }

    #[cfg(target_os = "linux")]
    {
        collectors.push(Box::new(linux::LinuxPersistenceCollector));
        collectors.push(Box::new(linux::LinuxInputCollector));
        collectors.push(Box::new(linux::LinuxWatcherCollector));
    }

    #[cfg(target_os = "macos")]
    {
        collectors.push(Box::new(macos::MacosPersistenceCollector));
        collectors.push(Box::new(macos::MacosEventTapCollector));
        collectors.push(Box::new(macos::MacosProfileCollector));
    }

    collectors
}

/// Execute all collectors and gather results alongside skipped checks
pub fn run_collectors(
    collectors: &[Box<dyn Collector>],
    ctx: &CollectorContext,
) -> (Vec<Evidence>, Vec<SkippedCheck>) {
    let mut all_evidence = Vec::new();
    let mut skipped = Vec::new();

    for col in collectors {
        if ctx.privilege_level < col.required_privilege() {
            skipped.push(SkippedCheck {
                collector: col.name().to_string(),
                description: format!("Collector '{}' requires elevated privileges.", col.name()),
                reason: sentinel_core::SkipReason::InsufficientPrivileges {
                    required: "Administrator / Root".to_string(),
                },
            });
            continue;
        }

        match col.collect(ctx) {
            Ok(ev) => all_evidence.extend(ev),
            Err(e) => {
                tracing::warn!("Collector '{}' failed: {}", col.name(), e);
            }
        }
    }

    (all_evidence, skipped)
}
