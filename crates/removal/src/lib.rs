//! Sentinel Removal - Quarantine, Reversible Restore, and Safe Remediation Engine

pub mod log;
pub mod quarantine;
pub mod remove;
pub mod restore;
pub mod verify;

pub use log::{get_sentinel_data_dir, log_operation, OperationLogEntry};
pub use quarantine::{QuarantineError, QuarantineManager};
pub use remove::{RemovalError, RemovalManager};
pub use restore::{RestoreError, RestoreManager};
pub use verify::{verify_removal, VerificationResult};
