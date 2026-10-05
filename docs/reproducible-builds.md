# Compiling Sentinel & Reproducible Builds

Sentinel is 100% open-source, written in Rust, and can be independently compiled from source code without any proprietary dependencies.

## 1. Prerequisites

- **Rust Toolchain**: Rust 1.78+ (via [rustup.rs](https://rustup.rs))
- **C Compiler**:
  - **Windows**: MSVC (`cl.exe`) or MinGW GCC
  - **Linux**: `build-essential` / `gcc`
  - **macOS**: Xcode Command Line Tools (`xcode-select --install`)

---

## 2. Standard Source Build

```bash
git clone https://github.com/jamixm4-crypto/sentinel.git
cd sentinel
cargo build --release --bin sentinel
```

The resulting binary will be located at:
- **Windows**: `target/release/sentinel.exe`
- **Linux/macOS**: `target/release/sentinel`

---

## 3. Verifying Official Release Checksums

Every release asset on [GitHub Releases](https://github.com/jamixm4-crypto/sentinel/releases) is published with a corresponding `SHA256SUMS` file.

### On Windows (PowerShell):
```powershell
$releaseHash = (Get-FileHash -Path sentinel-windows-x86_64.zip -Algorithm SHA256).Hash.ToLower()
$expected = (Get-Content SHA256SUMS | Select-String "sentinel-windows-x86_64.zip").Line.Split(" ")[0].ToLower()

if ($releaseHash -eq $expected) {
    Write-Host "✔ SHA-256 Checksum Verified!" -ForegroundColor Green
} else {
    Write-Error "✖ Checksum mismatch! Do not execute this file."
}
```

### On Linux / macOS:
```bash
sha256sum -c SHA256SUMS
# or on macOS:
shasum -a 256 -c SHA256SUMS
```

---

## 4. Supply Chain Security

The Sentinel CI pipeline enforces the following automated security checks on every pull request and commit:
- `cargo fmt -- --check`: Formatting conformance
- `cargo clippy -- -D warnings`: Static analysis and lint enforcement
- `cargo test --workspace`: 100% pass rate on unit and integration test suites
- Dependency vulnerability auditing via `cargo-audit` and RustSec Advisory Database.
