use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::evidence::Evidence;
use crate::platform::{PlatformInfo, SkippedCheck};
use crate::removal::{RemovalPolicy, RemovalSteps};

/// High-level scan verdict for the entire system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    /// No surveillance software indicators detected
    Clean,
    /// Dual-use software, unknown unsigned binaries, or permissions found - manual review suggested
    ReviewRecommended,
    /// Covert stalkerware, keyloggers, or unauthorized surveillance likely present
    SurveillanceLikely,
}

/// Primary category classification for a finding
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Category {
    /// Programs intercepting or polling keyboard input
    KeyboardCapture,
    /// Programs taking screenshots, recording desktop, or streaming video
    ScreenCapture,
    /// Software enabling remote desktop, VNC, RDP, or remote shell access
    RemoteAccess,
    /// Corporate EDR, MDM, or IT-managed enterprise agents
    OrganizationManaged,
    /// Unorthodox or hidden persistence (hidden tasks, WMI, IFEO, startup hooks)
    SuspiciousPersistence,
    /// Suspicious network listening ports, reverse proxies, or SSL MITM certs
    NetworkActivity,
    /// Programs that monitor, trace, or protect other processes (watchdogs/anti-kill)
    ProcessWatcher,
}

impl Category {
    pub fn name_en(&self) -> &'static str {
        match self {
            Self::KeyboardCapture => "Keyboard Capture",
            Self::ScreenCapture => "Screen Capture & Streaming",
            Self::RemoteAccess => "Remote Access & Control",
            Self::OrganizationManaged => "Organization-Managed Software",
            Self::SuspiciousPersistence => "Suspicious Persistence",
            Self::NetworkActivity => "Network Activity & MITM",
            Self::ProcessWatcher => "Process Watcher / Anti-Kill",
        }
    }

    pub fn name_ru(&self) -> &'static str {
        match self {
            Self::KeyboardCapture => "Перехват клавиатуры",
            Self::ScreenCapture => "Захват и трансляция экрана",
            Self::RemoteAccess => "Удалённое управление",
            Self::OrganizationManaged => "Управляется организацией",
            Self::SuspiciousPersistence => "Подозрительная автозагрузка",
            Self::NetworkActivity => "Сетевая активность и MITM",
            Self::ProcessWatcher => "Слежка за процессами / Watchdog",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            Self::KeyboardCapture => "⌨️",
            Self::ScreenCapture => "🖥️",
            Self::RemoteAccess => "📡",
            Self::OrganizationManaged => "🏢",
            Self::SuspiciousPersistence => "🔄",
            Self::NetworkActivity => "🌐",
            Self::ProcessWatcher => "👁️",
        }
    }
}

/// Severity classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "Info",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }
}

/// Confidence rating with human-readable band
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Confidence {
    /// Normalized score between 0.0 and 1.0
    pub score: f32,
    /// Qualitative label: "High", "Medium", "Low"
    pub label: String,
}

impl Confidence {
    pub fn new(score: f32) -> Self {
        let clamped = score.clamp(0.0, 1.0);
        let label = if clamped >= 0.75 {
            "High".to_string()
        } else if clamped >= 0.45 {
            "Medium".to_string()
        } else {
            "Low".to_string()
        };
        Self {
            score: clamped,
            label,
        }
    }
}

/// Detailed explanation texts for non-technical users
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingExplanation {
    pub what_is_it: String,
    pub why_flagged: String,
    pub is_legitimate: String,
    pub recommendation: String,
}

/// A fully correlated security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub rule_id: String,
    pub name: String,
    pub vendor: Option<String>,
    pub category: Category,
    pub severity: Severity,
    pub confidence: Confidence,
    pub is_legitimate_likely: bool,
    pub removal_policy: RemovalPolicy,
    pub evidence: Vec<Evidence>,
    pub explanation: FindingExplanation,
    pub removal_steps: RemovalSteps,
    pub references: Vec<String>,
}

/// Overall result of a complete scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub verdict: Verdict,
    pub findings: Vec<Finding>,
    pub platform: PlatformInfo,
    pub scan_duration: Duration,
    pub timestamp: String,
    pub skipped_checks: Vec<SkippedCheck>,
    pub total_inspected_processes: usize,
    pub total_inspected_persistence: usize,
}
