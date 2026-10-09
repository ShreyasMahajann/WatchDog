# Changelog

Notable changes to watchDog. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Chipset profile definitions and USB VID/PID lookup for WPA capture adapters.
- Governance files, issue and pull request templates for the Ergane Foundation.

### Changed
- License changed from MIT to Apache-2.0.

### Fixed
- Android SDK setup in the CI and release workflows.

## [0.8.0] - 2026-09-03

### Added
- Desktop app for Windows and Linux, sharing the scan and correlation engine
  through the new `:core` module.
- Desktop WPA Handshake tool and network adapter picker.
- Native desktop installers (`.exe`, `.deb`) attached to releases beside the APK.

## [0.7.1] - 2026-09-01

### Fixed
- Startup recovery and scan reliability.
- Hardened CI and release validation.

## [0.7.0] - 2026-08-15

### Added
- Results search, scan-wide vulnerability checks and UDP device probes.

## [0.6.0] - 2026-08-11

### Added
- Device Watch: track known devices and flag new ones on your network.

## [0.5.0] - 2026-08-10

### Added
- WPA Handshake tool with capability detection and the WPA-sec workflow.

## [0.4.0] - 2026-07-14 to [0.4.10] - 2026-08-09

### Added
- Iterative scan flow: discover, select devices, choose ports, scan, results.
- Device detail with on-demand vulnerability checks, deep re-scan and sharing.
- Scan history, named scans and a home menu.

### Fixed
- Phantom hosts on networks that answer every port with RST.
- Nearby Wi-Fi list on Android 13 and later.

## [0.3.0] - 2026-06-30

### Added
- Pull-to-refresh and a GitHub update check.

### Fixed
- Discovery hanging on the mDNS browse.

## [0.2.0] - 2026-06-17

### Added
- Non-root scanning engine: real discovery, fingerprinting and CVE correlation.

## [0.1.0] - 2026-06-11

### Added
- First release: guided navigation flow and launcher icon.
