---
name: forensic-artifact-analyzer
description: >-
  Procedures for low-level forensic artifact analysis across Windows, Linux, and macOS:
  detecting Raw Input sinks (RIDEV_INPUTSINK), keyboard hook chains, hidden background processes,
  audio/webcam ConsentStore enumeration, evdev sniffing, and macOS Event Taps.
---

# Forensic Artifact Analyzer Skill

This skill defines runbooks for inspecting stealthy host-level persistence and surveillance artifacts without modifying live system state.

## 1. Windows Low-Level Input & Screen Inspection
- **Raw Input Sink Keyloggers**:
  - API: `RegisterRawInputDevices` with `RIDEV_INPUTSINK` (`0x00000100`).
  - Indicator: Processes with no main window (`WS_VISIBLE == 0`) registering for keyboard usage page (`1`) and usage (`6`).
- **Hook Chains (`SetWindowsHookEx`)**:
  - `WH_KEYBOARD` (`2`) and `WH_KEYBOARD_LL` (`13`).
  - Inspect DLLs injected into target processes via thread hooks.
- **Hardware Capability Access (`ConsentStore`)**:
  - Registry paths:
    - `HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam`
    - `HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone`
  - Values: `LastUsedTimeStop == 0` denotes active live recording.
  - Flag any non-standard executable actively capturing microphone or camera streams in the background.

## 2. Linux Input Sniffing Inspection
- **Direct Event Device Sniffers**:
  - Any user-space process opening `/dev/input/event*` with `O_RDONLY` is reading raw keyboard scancodes.
  - In user sessions, only Xorg/Wayland compositors should hold descriptors to `/dev/input/by-id/*`.
- **eBPF & ptrace Monitoring**:
  - Inspect `/proc/sys/kernel/yama/ptrace_scope` and processes invoking `PTRACE_ATTACH` or `PTRACE_SEIZE`.
  - Check `/etc/ld.so.preload` for injected shared libraries.

## 3. macOS Event Taps & TCC Forensics
- **CoreGraphics Event Taps**:
  - Check `CGEventTapCreate` / `kCGEventTapOptionListenOnly`.
- **TCC Database Queries**:
  - `~/Library/Application Support/com.apple.TCC/TCC.db`
  - Inspect services `kTCCServiceListenEvent`, `kTCCServiceScreenCapture`, `kTCCServiceCamera`, `kTCCServiceMicrophone`.
