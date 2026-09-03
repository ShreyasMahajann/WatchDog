# watchDog cross-platform (desktop) — design

Date: 2026-09-03
Status: approved (brainstorming), ready for implementation
Targets: **Android, Windows, Linux** (macOS out of scope — works incidentally on the JVM but is not built/tested)

## Goal

Run watchDog as a full desktop GUI on Windows and Linux, reusing the existing
Android app's scanning/correlation logic, **without breaking the working Android
app**. The operator uses it on their own / authorized networks and devices, so
every feature must be real (no mocks/stubs).

## Key finding: the core is already portable

Everything under `scan/`, `correlate/`, `net/Cidr`, `scan/model`, the WPA
handshake parsers, `wpa/wpasec`, and the `wpa/device` probes has **zero Android
imports** — it is plain Kotlin/JVM using `java.net` sockets, `ProcessBuilder`,
and OkHttp, all of which run on Windows/Linux unchanged. The Android coupling is
confined to a thin edge: Compose UI, Room, DataStore, EncryptedSharedPreferences,
`ConnectivityManager`/`WifiManager`, `NsdManager` (mDNS), the foreground service,
notifications, USB, and SAF file access.

## Decision: chosen approach

- **Simple JVM module split, no Kotlin Multiplatform.** Extract the pure code
  into a shared `:core` Kotlin/JVM library. Android and a new desktop module both
  depend on it.
- **Desktop GUI = Compose for Desktop** (`org.jetbrains.compose` plugin on a plain
  Kotlin/JVM module). This is *not* KMP.
- **Consequence — the UI is not shared.** Android's `androidx.compose` and
  desktop's `org.jetbrains.compose` are different artifacts. The desktop module
  gets its own Compose UI, adapted from the Android screens as a visual/structural
  reference (copy, swap imports, replace Android-only bits). Screen *logic* is
  shared through core + plain (non-Android) presenter/state classes where practical.
- **Desktop persistence = SQLite via `sqlite-jdbc`**, behind repository interfaces
  shared with Android's Room implementation. (Chosen over JSON files for parity
  with Android's relational model.)

## Module topology

The existing Gradle root stays at `android/` to preserve the current Android
build, CI `working-directory`, release APK paths, and Android Studio workflow.
Two sibling modules are added under it:

```
android/                 (Gradle root — the JVM workspace; name kept for low churn)
  settings.gradle.kts    includes :app, :core, :desktop
  gradle/libs.versions.toml
  core/                  NEW — pure Kotlin/JVM library (no Android deps)
  app/                   EXISTING Android app — now depends on :core
  desktop/               NEW — Compose-for-Desktop app; depends on :core
```

The `android/` directory name becomes a slight misnomer (it also hosts core +
desktop). Renaming it is cosmetic and deferred; doing it now would churn CI,
release, README, and docs for no functional gain.

All modules keep the `com.watchdog.app.*` package root, so **moving a file from
`:app` to `:core` requires no import changes** in either module — only the Gradle
module boundary moves.

## Platform seams (interface in :core, impl per platform)

`NetworkContext` already follows this pattern. The rest are refactored to match.

| Seam | Interface (in :core) | Android impl (:app) | Desktop impl (:desktop) |
|------|----------------------|---------------------|-------------------------|
| Network context | `NetworkContext` (exists) | `AndroidNetworkContext` (ConnectivityManager) | `DesktopNetworkContext` (`java.net.NetworkInterface`) |
| mDNS discovery | `HostDiscoverer` (exists) | `MdnsDiscoverer` (NsdManager) | `JmdnsDiscoverer` (JmDNS lib) |
| Settings store | `SettingsStore` (new) | DataStore-backed | JSON-file-backed |
| Scan persistence | `ScanStore` (new) | Room-backed (current repo) | sqlite-jdbc-backed |
| Device-watch persistence | `DeviceWatchStore` (new) | Room-backed | sqlite-jdbc-backed |
| WPA persistence | `WpaStore` (new) | Room-backed | sqlite-jdbc-backed |
| Capture file store | `CaptureFileStore` (new) | SAF/content-URI + filesDir | plain `java.io.File` |
| Secret store | `SecretStore` (new) | EncryptedSharedPreferences | Java KeyStore file |
| Notifications/lifecycle | `ScanRunner`/callbacks | Foreground service | coroutine scope (+ optional tray) |

Domain models that Room entities currently double as (e.g. `WatchedDeviceEntity`)
get a pure counterpart in `:core`; each platform maps its storage rows to/from the
pure model. This unblocks moving `DeviceWatchDiff` and `DeviceWatchScanner` to core.

## The one real refactor

`ScanController` today hardcodes `AndroidNetworkContext`, `WatchDogDatabase`, and
`MdnsDiscoverer(ctx)`. It changes to accept a `PlatformServices` bundle
(network context, discoverers, stores, settings) via its constructor. Android and
desktop each build the bundle. `ScanEngine` and the correlation engine are
unchanged. `ScanStateHolder`/`ScanRunState` are already pure and move to core.

## Scoped out of desktop v1 (stated honestly)

- **Live WPA handshake capture.** Android does it via USB/root (`RootCaptureEngine`,
  `UsbDetector`). Desktop needs monitor-mode wireless tools. v1 keeps handshake
  *analysis*, *import*, and *wpa-sec submit/track* (already pure) but not live
  desktop capture. (`InterfaceProbe`/`ToolProbe`/`Shell`/`RootProbe` are pure and
  move to core, so a later desktop capture path can reuse them.)
- **Nearby-AP list** (`WifiScanner`). Android context feature; desktop SSID listing
  is OS-command-specific. Deferred. Joined-network scanning works everywhere.
- **In-app update check** points at GitHub releases for the APK; desktop shows its
  own version and links to releases but does not self-update.

## Implementation phases (Android stays green at every step)

1. **Create `:core`; move the pure files.** Add the `kotlin("jvm")` module; move the
   deeply-pure clusters (`scan/`, `correlate/`, `net/Cidr`, `scan/model`,
   `update/`, `wpa/handshake`, `wpa/wpasec`, `wpa/device` probes,
   `wpa/diagnostics/DiagnosticsReport`, `service/ScanRunState`+`ScanStateHolder`,
   `devicewatch/WatchScope`) and their JVM unit tests. Split `NetworkContext.kt`:
   interface + `NetworkInfo` → core, `AndroidNetworkContext` → app. `:app` depends
   on `:core`. **Verify: `gradle :app:testDebugUnitTest :app:assembleDebug` + core tests.**
2. **Extract platform interfaces + refactor `ScanController` DI.** Introduce
   `SettingsStore`, `ScanStore`, `DeviceWatchStore`, `WpaStore`, `CaptureFileStore`,
   `SecretStore`, and pure domain models; Android supplies today's implementations.
   Move `DeviceWatchDiff`/`DeviceWatchScanner` to core against the pure model.
   **Verify: Android builds + all tests pass; behavior unchanged.**
3. **Create `:desktop` skeleton.** Compose-for-Desktop module depending on `:core`.
   Desktop impls of every seam. Get a **headless scan** running first (discover →
   enumerate → fingerprint → correlate → print), proving core works off-Android.
4. **Port the UI to Compose Desktop**, screen by screen, reusing the Android
   screens as reference: Home, Networks, Discover/Select, Scanning, Results,
   DeviceDetail, History, Settings, Device Watch, WPA (import/library/submit/key).
5. **Packaging + CI.** Desktop `packageDistributionForCurrentOS` (`.msi` on Windows,
   `.deb` on Linux) and/or a runnable fat jar. Extend CI: build `:desktop` on
   `windows-latest` and `ubuntu-latest`; the existing Android job is untouched.
   Add a desktop release job mirroring the APK release.

## Testing

- Core JVM unit tests (the current suites) run under `:core` unchanged.
- New tests: `DesktopNetworkContext` CIDR derivation, sqlite-jdbc store round-trips,
  settings/secret file stores.
- The backend↔core correlation parity contract (see `CLAUDE.md`) is unaffected;
  the Kotlin engine simply lives in `:core` now and is consumed by both apps.

## Risks / mitigations

- **Room→sqlite-jdbc divergence.** Mitigated by shared repository interfaces + the
  same pure models + round-trip tests on both sides.
- **UI drift between Android and desktop.** Mitigated by the `CLAUDE.md` parity rule
  (a user-facing change lands in both apps unless inherently platform-specific).
- **Compose Desktop build weight in CI.** Isolated to the desktop job; Android/backend
  jobs unaffected.
