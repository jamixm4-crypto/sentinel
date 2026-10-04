//! Sentinel Core - Data Model, Platform Types, and Localization

pub mod evidence;
pub mod finding;
pub mod i18n;
pub mod platform;
pub mod removal;

pub use evidence::{Evidence, EvidenceData, EvidenceType};
pub use finding::{Category, Confidence, Finding, FindingExplanation, ScanResult, Severity, Verdict};
pub use i18n::{t, Lang};
pub use platform::{PlatformInfo, PrivilegeLevel, SkippedCheck, SkipReason};
pub use removal::{
    DisabledRegistryEntry, QuarantineManifest, QuarantinedFileEntry, RemovalAction, RemovalPolicy, RemovalStep,
    RemovalSteps,
};
