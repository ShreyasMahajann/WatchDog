# Iterative scanning + device-centric results + history — Design

Date: 2026-08-10
Status: Approved (design)

## Context

Today watchDog runs an all-at-once flow: the user picks "whole network" or
"single host" and a port depth up front, then the app auto-discovers, auto
port-scans **every** host, auto-runs OSV correlation, and dumps a flat CVE list
(`FindingsScreen`). There is no way to choose *which* devices to scan, no
device-centric view of what's running, no on-demand control over the vuln check,
and although every scan is fully persisted to Room, there is no UI to revisit
past scans.

The user wants an **iterative, user-driven pipeline**: discover devices → select
some → choose ports → scan → inspect per-device details → optionally check each
device against OSV or their own server, **without** the vuln check wiping the
device details. Plus a history of previous scans.

Everything is Kotlin + Jetpack Compose under
`android/app/src/main/java/com/watchdog/app/`. Navigation is a hand-rolled
`when (stage)` in `WatchDogApp.kt` driven by `ScanViewModel.Stage`. Scan data is
already persisted in Room (`data/room/`), with query methods that mostly already
exist (`observeRecentScans`, `observeHosts`, `observeServices`,
`observeFindings`).

## Goals

1. Replace the whole-vs-single scope split with a staged flow:
   **Discover → Select devices → Choose ports → Scan → Results → (on-demand) Check vulns**.
2. Device-centric results: each scanned device lists its services/products; vuln
   findings are **additive** (shown alongside the device details, never replacing
   them).
3. On-demand correlation, per device, with a choice of **OSV** or **own server**
   at check time (falls back to OSV when no server is configured).
4. History: browse/reopen/delete/export past scans, reusing the same results
   screens.

## Non-goals

- Custom port-list entry (presets only: Top 100 / Top 1000 / All). Future.
- Scan-to-scan diffing/comparison. Future.
- Root-tier features. Unchanged.

## The staged flow (stages)

New `Stage` set (replacing `Scope`, `PickHost` semantics; `Findings` becomes
`Results`):

`Networks → Discovering → SelectDevices → ChoosePorts → Scanning → Results → DeviceDetail`
plus `History` and `Settings` reachable from `Networks`.

1. **Networks** (home) — unchanged target selection; "Continue" now starts
   discovery. A new **History** entry point sits next to Settings.
2. **Discovering** — discovery only (no port scan). Reuses the existing discovery
   engine (`ScanController.startDiscovery`). Devices stream in live.
3. **SelectDevices** — multi-select list of discovered devices (checkboxes),
   **Select all** / pick a few, and **Discover again** (re-run discovery). Continue
   with the selection.
4. **ChoosePorts** — the `ScanDepth` radio group (Top 100 / Top 1000 / All),
   moved here from the old `ScopeScreen`.
5. **Scanning** — port-scan + fingerprint **only the selected devices** at the
   chosen depth. Progress screen (existing `ScanningScreen`). **No correlation.**
6. **Results** — summary (network, depth, time, # devices, # open ports,
   # services) + device list (IP, hostname, service/port count). "Share report".
   Tap a device → DeviceDetail.
7. **DeviceDetail** — the device's services (port · service · product/version) +
   raw fingerprint (banner, HTTP headers, TLS). Actions:
   - **Check against OSV** / **Check against my server** — on-demand correlation
     for this device's observations; findings render **below** the details.
   - **Deep re-scan this device** — reuses the single-host deep-scan path.
   - **Copy / share device info** — Android share intent.
8. **History** — `observeRecentScans` list (network, date, status, device/finding
   counts) → tap reopens `Results(scanId)`. Delete (confirm; FK cascade). Export
   full report.

## Component / code changes

### Scan engine (`scan/ScanEngine.kt`)
- Remove the `correlator` parameter and the `CORRELATING` phase + `Correlated`
  event from `scan()`. It becomes discover-free (callers pass the host list):
  enumerate → fingerprint → `Done`. Services are still emitted (`ServiceFound`)
  and persisted.
- `scan(hosts, config)` already takes an explicit host list, so scanning a
  selected subset is just passing the chosen IPs.

### Controller / service (`service/ScanController.kt`, `ScanForegroundService.kt`)
- Add `scanHosts(ips: List<String>, config)` (generalizes `scanPickedHost`);
  `runScan` no longer correlates. Add a `ACTION_SCAN_HOSTS` intent carrying the
  selected IP list + depth. Keep `startDiscovery` for the discovery step.
- Drop the whole-network auto-scan path (`startWholeNetwork` / `ACTION_WHOLE`) —
  "select all" replaces it.
- Extract the private `buildCorrelator()` into a reusable
  `correlate/CorrelatorFactory(context)` returning a `Correlator` from settings,
  optionally overridden by a requested mode (OSV vs own server).

### On-demand correlation (`ScanViewModel` + `CorrelatorFactory`)
- `checkVulnerabilities(scanId, host, mode)`:
  1. Load that host's observations from Room (new DAO query — see below).
  2. `CorrelatorFactory.create(mode).correlate(observations)`.
  3. `repo.saveFindings(scanId, response.findings + response.suppressed)`.
  4. `observeFindings(scanId)` (filtered by host in the UI) reflects them.
- Per-device correlation UI state (idle / running / error) lives in the VM.

### Data / Room (`data/room/`)
- New DAO query: observations for a scan (join `services→ports→hosts`) returning
  host IP + port + product columns, so `ServiceObservation`s can be rebuilt for
  on-demand correlation — works for both live and historical scans.
- New DAO: `deleteScan(id)` (FK cascade removes hosts/ports/services/fingerprints/
  findings) and optional `deleteAll`.
- Results screens read from Room by `scanId` (`observeHosts`, `observeServices`,
  `observeFindings`), unifying live and historical rendering.

### Navigation / ViewModel (`ui/ScanViewModel.kt`, `WatchDogApp.kt`)
- Update `Stage` to the new set; add selected-device state (`Set<String>`),
  chosen depth (already present), and a `currentScanId` + selected host for
  DeviceDetail.
- `Scanning → Results` on finish (was `Findings`). `FINISHABLE_STAGES` updated.
- New `when (stage)` arms for `SelectDevices`, `ChoosePorts`, `Results`,
  `DeviceDetail`, `History`.

### Screens (`ui/`)
- New: `ui/results/ResultsScreen.kt`, `ui/results/DeviceDetailScreen.kt`,
  `ui/history/HistoryScreen.kt`, `ui/select/SelectDevicesScreen.kt` (multi-select),
  `ui/select/ChoosePortsScreen.kt` (the depth radios lifted from `ScopeScreen`).
- Keep `HostsScreen` for the **Discovering** live view only (read-only stream).
- `FindingsScreen`'s severity-row rendering is extracted into a reusable
  `FindingRow` used inside DeviceDetail for the per-device findings.
- Remove/retire `ScopeScreen` (its depth control moves to ChoosePorts; its
  scope choice is gone).
- Home (`NetworksScreen`) gains a **History** action.

### Sharing/export
- A small `share/` helper building shareable text (device info, or full scan
  report) and firing `Intent.ACTION_SEND`.

## Data flow

```
Discover ──(DiscoveredHost stream)──> SelectDevices ──(Set<ip>)──> ChoosePorts
   │                                                                   │(depth)
   └── persisted: scan + host rows                                     ▼
                                                          Scanning: scanHosts(ips, depth)
                                                                       │
                                            persisted: ports+services+fingerprints
                                                                       ▼
                                          Results(scanId)  ── read Room ──> DeviceDetail(host)
                                                                       │
                                   [Check OSV/server] ─> correlate ─> saveFindings ─> observeFindings
                                                                       │
                                           device details REMAIN; findings shown below
```

## Error handling

- Correlation failures (network/OSV/server) surface a per-device error state and
  leave device details intact; retry allowed.
- Empty selection at SelectDevices blocks Continue.
- Large-subnet guard still applies to discovery.
- Delete requires confirmation.

## Testing / verification

- JVM unit tests (no local Android SDK): `CorrelatorFactory` mode selection; the
  observation-rebuild mapping (Room row → `ServiceObservation`) round-trip; DAO
  cascade-delete via an in-memory Room test if feasible.
- Existing engine/correlate/parser suites must stay green.
- On device: discover → select a subset → choose Top 100 → scan → open a device →
  see services → Check against OSV → findings appear **below** the still-visible
  device details → open History → reopen the scan → same view → delete a scan.

## Build order (phased plan)

1. **Split correlation + scan-selected + Results/DeviceDetail** (view fingerprint,
   check-vulns on demand, share). Core of the reflow.
2. **Deep re-scan device** (reuses single-host path).
3. **History** (browse/reopen/delete/export).
