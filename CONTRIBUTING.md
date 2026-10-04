# Contributing to Sentinel

Thank you for your interest in contributing to Sentinel! As a defensive tool dedicated to protecting individuals from covert surveillance, every contribution directly enhances digital safety.

## Guiding Principles

1. **Defensive Only**: Sentinel will never implement offensive capabilities, keyloggers, screen recording, DLL injection, or weaponized proof-of-concepts. Test suites must use mocked collector data only.
2. **Read-Only by Default**: Scanners must never modify operating system state without explicit user consent.
3. **Zero Telemetry**: Code must not initiate network requests unless explicitly behind an opt-in CLI flag.
4. **Clean-Room Engineering**: Do not copy code from GPL-3.0 or proprietary tools (such as KnockKnock, BlockBlock, LOKI, or Autoruns). Implement logic independently using public system APIs and OS documentation.

---

## Contributing New Detection Rules

Detection rules live in the `rules/` directory as structured YAML files.

### Rule Requirements
- Must follow `rules/schema.json`.
- Must specify `removal_policy`:
  - `SafeAuto` for known spyware / stalkerware with established uninstall paths.
  - `ManualReview` for dual-use utilities (VNC, time trackers, remote desktop).
  - `DoNotRemove` for corporate EDR and MDM software.
- Must provide step-by-step manual removal instructions.
- Must provide reputable references (Coalition Against Stalkerware, MITRE ATT&CK, vendor docs).

### Validating Rules Locally
```bash
sentinel rules validate rules/stalkerware/your_rule.yml
```

---

## Code Style & Testing

Before submitting a Pull Request:
```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

All commits should adhere to [Conventional Commits](https://www.conventionalcommits.org/):
- `feat: add Windows WMI process watcher collector`
- `fix: resolve UpperFilters sanitization edge case`
- `docs: update threat model documentation`
- `rules: add rule for pcTattletale keylogger`
