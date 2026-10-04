# Security Policy

## Reporting Security Issues & Stalkerware Responsible Disclosure

The Sentinel project takes security and responsible disclosure seriously. We recognize the sensitive nature of privacy tools and stalkerware detection.

### Scope

- **Vulnerabilities in Sentinel**: Bugs that could lead to local privilege escalation, arbitrary code execution, denial of service, or improper removal of benign system files.
- **New Stalkerware Families & IoCs**: Novel indicators, obfuscation techniques, or persistence mechanisms utilized by commercial or domestic spyware.

### Responsible Disclosure Guidelines for Stalkerware

> [!CAUTION]
> **Do not contact stalkerware vendors directly.**
> Stalkerware vendors operate in bad faith. Advance notice enables them to alter C2 domains, delete victim logs, or harden binary obfuscation against defensive scanners.

Instead, please report new stalkerware indicators to:
1. **Sentinel Security Team**: Open an issue or email security disclosures to `security@sentinel-sec.org`.
2. **Coalition Against Stalkerware**: [stopstalkerware.org/contact](https://stopstalkerware.org/)
3. **AssoEchap / Stalkerware Indicators**: [github.com/AssoEchap/stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators)

### Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

### Reporting a Vulnerability in Sentinel

If you discover a security flaw within Sentinel itself:
1. Please **do not** report security vulnerabilities through public GitHub issues.
2. Submit an advisory through GitHub Security Advisories or email `security@sentinel-sec.org`.
3. Provide reproduction steps, affected operating systems, and proof-of-concept output.
4. We aim to respond within 48 hours and release fixes within 14 days.
