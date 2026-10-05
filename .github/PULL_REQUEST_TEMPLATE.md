## Description
Please describe your changes and the rationale behind them.

## Type of Change
- [ ] New detection rule (YAML)
- [ ] New evidence collector / forensic capability
- [ ] Bug fix / False positive suppression
- [ ] Performance optimization
- [ ] Documentation improvement

## Verification Checklist
- [ ] `cargo test --workspace` passes cleanly
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` reports zero warnings
- [ ] `cargo fmt --all -- --check` complies with formatting standards
- [ ] If adding rules: verified with `sentinel rules validate <path>`
- [ ] Zero telemetry verified: no external HTTP requests or network calls added
