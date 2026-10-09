# Architecture

watchDog is a guided network security assessment tool. It runs on Android,
Windows and Linux, with an optional correlation backend.

## Hands and brain

The **client** (phone or desktop app) does 100% of network I/O: network
discovery, host discovery, port enumeration, fingerprinting and verification.

The **backend** never connects to a target. It is a pure correlation engine:
vulnerability data, matching, prioritization and signed check-definitions that
the client runs locally. Because the backend has no code path that reaches a
target, server-side request forgery is impossible by construction.

The client can also correlate on its own, against OSV.dev, CISA KEV and EPSS,
using a Kotlin port of the backend engine. Pointing the client at your own
backend is optional (Settings, own-server URL).

## Repository layout

```
backend/       TypeScript correlation engine (the brain). No target I/O.
android/       Gradle root for all JVM code:
  core/        Pure Kotlin/JVM library. Scanning, correlation, WPA parsing,
               device probes. No Android dependencies.
  app/         Android app (Jetpack Compose). Depends on :core.
  desktop/     Compose for Desktop app for Windows and Linux. Depends on :core.
```

The Gradle root keeps the name `android/` so the Android build, CI working
directories and release paths stay unchanged. All modules use the
`com.watchdog.app.*` package root, so moving a file between `:app` and `:core`
needs no import changes.

The desktop app is a plain Kotlin/JVM module with the JetBrains Compose
plugin, not Kotlin Multiplatform. The UI is therefore not shared: Android uses
`androidx.compose` and desktop uses `org.jetbrains.compose`. Screen logic is
shared through `:core`.

## Platform seams

`:core` defines an interface for every platform-dependent service, and each app
supplies its own implementation. `ScanController` receives them as a
`PlatformServices` bundle.

| Seam | Android (`:app`) | Desktop (`:desktop`) |
|------|------------------|----------------------|
| `NetworkContext` | `ConnectivityManager` | `java.net.NetworkInterface`, with an adapter picker |
| `HostDiscoverer` (mDNS) | `NsdManager` | JmDNS |
| `SettingsStore` | DataStore | JSON file |
| `ScanStore`, `DeviceWatchStore`, `WpaStore` | Room | SQLite via `sqlite-jdbc` |
| `CaptureFileStore` | SAF and app files dir | `java.io.File` |
| `SecretStore` | EncryptedSharedPreferences | Java KeyStore file |
| Scan lifecycle | Foreground service and notifications | Coroutine scope |

## The scan flow

Scanning is iterative and user-driven:

```
Networks -> Discovering -> SelectDevices -> ChoosePorts -> Scanning -> Results -> DeviceDetail
```

1. **Networks** - pick the joined network. History and Settings are reachable
   from here.
2. **Discovering** - TCP-connect probing, best-effort ICMP and mDNS, merged into
   a live host list. No port scan yet.
3. **SelectDevices** - choose which discovered hosts to scan.
4. **ChoosePorts** - Top 100, Top 1000 or all ports.
5. **Scanning** - bounded-concurrency connect scan, then banner, HTTP and TLS
   probes, normalized to `{product, version, distro}`. No correlation yet.
6. **Results** - device-centric summary.
7. **DeviceDetail** - services and raw fingerprints. Vulnerability checks run
   on demand (OSV or your own backend) and their findings are added below the
   device details, never replacing them.

Every scan is persisted, so History can reopen, export or delete past scans.

## Correlation engine

The engine turns observed services into ranked, de-duplicated findings with
explicit confidence states:

```
DETECTED -> LIKELY_VULNERABLE -> VERIFIED -> EXPLOITABLE
```

It defends against false positives with distro backport suppression (a real
`dpkg` version comparator), version-only matches capped at
`LIKELY_VULNERABLE`, CVSS chosen by provenance (v4 over v3.1, CNA over NVD,
never averaged), and KEV and EPSS for prioritization.

The engine exists twice: `backend/src/{version,match,correlate}.ts` and
`android/core/.../correlate/engine/{Version,Match,CorrelateEngine}.kt`. They
are semantics-preserving ports, validated against the same golden set
(`backend/test/` and `android/core/src/test/`). A change to one must land in
the other.

## Platform limits

- Android without root can only scan the network it is joined to.
- Live WPA handshake capture is Android-only (USB adapter or root). Desktop
  supports handshake analysis, import and WPA-sec submission and tracking.
- The nearby access point list is Android-only.
- The desktop app links to GitHub releases but does not update itself.
- SYN, ARP, MAC and OS detection are reserved for a future root tier.
