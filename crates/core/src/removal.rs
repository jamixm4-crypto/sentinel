use serde::{Deserialize, Serialize};

/// Policy governing how this software may be removed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemovalPolicy {
    /// Clearly undesirable spyware / stalkerware with established uninstaller / cleanup path.
    /// Safe for automated quarantine or removal after explicit single confirmation.
    SafeAuto,
    /// Dual-use software (remote access, legitimate parental control, time trackers).
    /// Requires per-item manual confirmation so the user does not break their own tools.
    ManualReview,
    /// Managed by organization (corporate EDR, MDM, IT agents).
    /// Automatic removal is STRICTLY BLOCKED to prevent breaking employer machines or violating employment agreements.
    DoNotRemove,
}

impl RemovalPolicy {
    pub fn label_en(&self) -> &'static str {
        match self {
            Self::SafeAuto => "Safe Automatic Removal Available",
            Self::ManualReview => "Manual Review Required (Dual-Use)",
            Self::DoNotRemove => "Organization-Managed (Do Not Auto-Remove)",
        }
    }

    pub fn label_ru(&self) -> &'static str {
        match self {
            Self::SafeAuto => "Доступно безопасное автоматическое удаление",
            Self::ManualReview => "Требуется подтверждение (двойное назначение)",
            Self::DoNotRemove => "Управляется организацией (автоудаление заблокировано)",
        }
    }

    pub fn is_auto_allowed(&self) -> bool {
        matches!(self, Self::SafeAuto)
    }

    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::DoNotRemove)
    }
}

/// Action to be taken for removal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RemovalAction {
    TerminateProcess { name: String },
    StopService { name: String },
    DisableService { name: String },
    DeleteService { name: String },
    DisableTask { name: String },
    DeleteTask { name: String },
    DeleteRegistryValue { hive: String, path: String, value: String },
    DeleteRegistryKey { hive: String, path: String },
    SanitizeUpperFilters { class_guid: String, driver_name: String },
    QuarantineFile { source_path: String },
    DeleteFile { path: String },
    RunUninstallString { command: String },
    ResetProxySettings,
    DeleteCertificate { store: String, thumbprint: String },
    LaunchctlBootout { service: String },
    SystemctlDisableMask { service: String },
    TccutilReset { service: String, bundle_id: String },
}

/// Individual step in a removal plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovalStep {
    pub order: u32,
    pub description: String,
    pub action: RemovalAction,
    pub rollback_action: Option<RemovalAction>,
}

/// Structured collection of removal steps and human-readable guides
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemovalSteps {
    pub steps: Vec<RemovalStep>,
    pub manual_guide_windows: Option<String>,
    pub manual_guide_linux: Option<String>,
    pub manual_guide_macos: Option<String>,
}

/// Manifest saved when an item is placed in quarantine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineManifest {
    pub id: String,
    pub finding_id: String,
    pub rule_id: String,
    pub name: String,
    pub timestamp: String,
    pub original_files: Vec<QuarantinedFileEntry>,
    pub disabled_registry_values: Vec<DisabledRegistryEntry>,
    pub disabled_services: Vec<String>,
    pub disabled_tasks: Vec<String>,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantinedFileEntry {
    pub original_path: String,
    pub quarantined_path: String,
    pub sha256: String,
    pub file_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisabledRegistryEntry {
    pub hive: String,
    pub path: String,
    pub original_name: String,
    pub disabled_name: String,
    pub data: String,
}
