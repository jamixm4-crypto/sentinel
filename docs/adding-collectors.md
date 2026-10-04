# Guide: Adding a New Evidence Collector to Sentinel

Sentinel's collector pipeline is designed to be easily extensible. All collectors implement the `Collector` trait in `crates/collectors`.

---

## 1. Implement the `Collector` Trait

Create a new file under `crates/collectors/src/<os>/your_collector.rs`:

```rust
use sentinel_core::{Evidence, EvidenceData, EvidenceType, PrivilegeLevel};
use crate::{Collector, CollectorContext};

pub struct MyCustomCollector;

impl Collector for MyCustomCollector {
    fn name(&self) -> &'static str {
        "MyCustomCollector"
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        // Return ElevatedAdmin if root/administrator is strictly required
        PrivilegeLevel::StandardUser
    }

    fn collect(&self, ctx: &CollectorContext) -> Result<Vec<Evidence>, String> {
        let mut evidence = Vec::new();

        // 1. Gather technical data...
        // 2. Package into Evidence instances...
        evidence.push(
            Evidence::new(
                EvidenceType::KnownFileArtifact,
                self.name(),
                "Found suspicious file artifact",
                "Full file path details...",
            )
        );

        Ok(evidence)
    }
}
```

---

## 2. Register the Collector

Open `crates/collectors/src/lib.rs` and add your collector to `get_all_collectors()`:

```rust
#[cfg(target_os = "windows")]
{
    collectors.push(Box::new(windows::MyCustomCollector));
}
```

---

## 3. Defensive Safety Rules

1. **Read-Only**: Your collector must never modify files, create keys, or kill processes.
2. **Handle Errors Gracefully**: Never panic (`unwrap` / `expect`). Return `Err(String)` or log a warning so other collectors can continue uninterrupted.
3. **Respect Privileges**: If your probe requires administrative privileges, declare `required_privilege()` appropriately so standard user scans report skipped checks transparently rather than failing.
