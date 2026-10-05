//! Sentinel Scoring - Evidence Correlation, Allowlisting, and Verdict Engine

pub mod allowlist;
pub mod engine;
pub mod explanation;

pub use allowlist::*;
pub use engine::ScoringEngine;
