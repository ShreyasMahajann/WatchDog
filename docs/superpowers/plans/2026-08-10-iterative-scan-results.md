# Iterative Scanning + Device-Centric Results + History Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the auto whole-network scan + auto-CVE flow with a user-driven pipeline (discover → select devices → choose ports → scan → device-centric results → on-demand vuln check), keep device details visible alongside findings, and add a browsable/deletable/exportable scan history.

**Architecture:** Correlation is removed from the scan engine and becomes an additive, per-device on-demand action. All results screens read from Room by `scanId`, so live and historical results share one rendering path. Navigation stays the hand-rolled `when (stage)` machine in `WatchDogApp.kt` driven by `ScanViewModel.Stage`.

**Tech Stack:** Kotlin, Jetpack Compose (Material3, BOM 2024.10.01), coroutines/Flow, Room 2.6.1, kotlinx.serialization, OkHttp. minSdk 26, targetSdk 35, JDK 17.

## Global Constraints

- No local Android SDK: **UI is verified on-device**; automated tests are **plain JVM unit tests** (JUnit4) for android-free logic and in-memory Room where noted. Existing suites must stay green (`./gradlew testDebugUnitTest`).
- `scan/model/**` and `correlate/engine/**` must stay free of `android.*` imports (JVM-testable).
- Commit messages: **no AI attribution** (project rule).
- Follow existing screen patterns: `ui/common/Chrome.kt` (`ScreenChrome`, `LabeledCard`, `InfoBanner`, `CancelConfirmDialog`), one screen package per stage.
- Port presets only (`ScanDepth`: TOP_100 / TOP_1000 / FULL) — no custom port list.
- On-demand correlation offers OSV vs own-server at check time; own-server only when `Settings.serverBaseUrl` is non-blank, else OSV only.

---

## File Structure

**Create:**
- `correlate/CorrelatorFactory.kt` — builds a `Correlator` from settings or an explicit mode.
- `ui/select/SelectDevicesScreen.kt` — multi-select discovered devices.
- `ui/select/ChoosePortsScreen.kt` — depth radios (lifted from ScopeScreen).
- `ui/results/ResultsScreen.kt` — scan summary + device list (reads Room).
- `ui/results/DeviceDetailScreen.kt` — one device's services, fingerprint, on-demand vuln check, deep re-scan, share.
- `ui/history/HistoryScreen.kt` — past scans list.
- `ui/common/FindingRow.kt` — extracted severity row (reused by DeviceDetail).
- `share/ScanShare.kt` — build shareable text + fire ACTION_SEND.

**Modify:**
- `scan/ScanEngine.kt` — drop correlation from `scan()`.
- `service/ScanController.kt` — `scanHosts(list)`, remove whole-network path, drop inline correlation, extract correlator build.
- `service/ScanForegroundService.kt` — `ACTION_SCAN_HOSTS`, remove `ACTION_WHOLE`.
- `data/room/WatchDogDao.kt` + `ScanRepository.kt` — observations-by-scan query + `ServiceObservation` rebuild; `deleteScan`.
- `ui/ScanViewModel.kt` — new `Stage` set, selection/results state, on-demand `checkVulnerabilities`, history + delete.
- `WatchDogApp.kt` — new stage arms + History entry.
- `ui/findings/FindingsScreen.kt` — use extracted `FindingRow`.
- Retire `ui/scope/ScopeScreen.kt`.

---

## PHASE 1 — Split correlation + scan-selected + device-centric results

### Task 1: Remove correlation from the scan engine

**Files:**
- Modify: `android/app/src/main/java/com/watchdog/app/scan/ScanEngine.kt`
- Test: `android/app/src/test/java/com/watchdog/app/scan/ScanEngineNoCorrelateTest.kt` (new, JVM)

**Interfaces:**
- Produces: `ScanEngine.scan(hosts: List<String>, config: ScanConfig): Flow<ScanEvent>` (no `correlator` param). Emits `ServiceFound`, `HostFinished`, then `Phase(DONE)` + `Done`. Never emits `Correlated`.

- [ ] **Step 1: Write the failing test**

```kotlin
package com.watchdog.app.scan

import com.watchdog.app.scan.enumeration.PortScanner
import com.watchdog.app.scan.fingerprint.Fingerprinter
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertTrue
import org.junit.Test

class ScanEngineNoCorrelateTest {
    @Test
    fun `scan emits no Correlated event`() = runTest {
        // Empty host list: pipeline runs to completion without touching the network.
        val engine = ScanEngine(discoverers = emptyList(), portScanner = PortScanner(), fingerprinter = Fingerprinter())
        val events = engine.scan(emptyList(), ScanConfig(scope = ScanScope.SINGLE_HOST)).toList()
        assertTrue(events.none { it is ScanEvent.Correlated })
        assertTrue(events.any { it is ScanEvent.Done })
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew testDebugUnitTest --tests "com.watchdog.app.scan.ScanEngineNoCorrelateTest"`
Expected: FAIL to compile — `scan()` still requires a `correlator` argument.

- [ ] **Step 3: Edit `ScanEngine.scan`**

Change the signature and delete the correlation block:

```kotlin
fun scan(
    hosts: List<String>,
    config: ScanConfig,
): Flow<ScanEvent> = channelFlow {
    send(ScanEvent.Phase(ScanPhase.ENUMERATING))
    val ports = PortSets.forDepth(config.depth)

    for (ip in hosts) {
        currentCoroutineContext().ensureActive()
        send(ScanEvent.HostStarted(ip))
        var openCount = 0
        try {
            portScanner.scan(ip, ports, config).collect { open ->
                openCount++
                send(ScanEvent.PortOpen(ip, open.port, open.serviceHint))
                try {
                    val obs = fingerprinter.fingerprint(ip, open.port, config)
                    send(ScanEvent.ServiceFound(obs))
                } catch (ce: CancellationException) {
                    throw ce
                } catch (e: Exception) {
                    send(ScanEvent.Failed("fingerprint $ip:${open.port}", e.message ?: e.toString()))
                }
            }
        } catch (ce: CancellationException) {
            throw ce
        } catch (e: Exception) {
            send(ScanEvent.Failed("portscan $ip", e.message ?: e.toString()))
        }
        send(ScanEvent.HostFinished(ip, openCount))
    }

    send(ScanEvent.Phase(ScanPhase.DONE))
    send(ScanEvent.Done)
}
```

Remove the now-unused `import com.watchdog.app.correlate.Correlator` and the `observations` accumulator.

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew testDebugUnitTest --tests "com.watchdog.app.scan.ScanEngineNoCorrelateTest"`
Expected: PASS. (Task 3 fixes the `ScanController` call site; the app module may not compile until then — that's expected mid-phase.)

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/java/com/watchdog/app/scan/ScanEngine.kt android/app/src/test/java/com/watchdog/app/scan/ScanEngineNoCorrelateTest.kt
git commit -m "Remove correlation from scan engine; it becomes on-demand"
```

---

### Task 2: Extract `CorrelatorFactory`

**Files:**
- Create: `android/app/src/main/java/com/watchdog/app/correlate/CorrelatorFactory.kt`
- Test: `android/app/src/test/java/com/watchdog/app/correlate/CorrelatorFactoryTest.kt`

**Interfaces:**
- Produces:
  - `enum class CorrelationTarget { OSV, OWN_SERVER }`
  - `class CorrelatorFactory(context: Context)` with `suspend fun create(target: CorrelationTarget): Correlator` and `suspend fun availableTargets(): List<CorrelationTarget>` (OSV always; OWN_SERVER only when `settings.serverBaseUrl` non-blank).

- [ ] **Step 1: Write the failing test**

```kotlin
package com.watchdog.app.correlate

import com.watchdog.app.settings.CorrelatorMode
import com.watchdog.app.settings.Settings
import org.junit.Assert.assertEquals
import org.junit.Test

class CorrelatorFactoryTest {
    @Test
    fun `own server available only when base url set`() {
        assertEquals(
            listOf(CorrelationTarget.OSV),
            CorrelatorFactory.targetsFor(Settings(serverBaseUrl = "")),
        )
        assertEquals(
            listOf(CorrelationTarget.OSV, CorrelationTarget.OWN_SERVER),
            CorrelatorFactory.targetsFor(Settings(serverBaseUrl = "https://x.example")),
        )
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew testDebugUnitTest --tests "com.watchdog.app.correlate.CorrelatorFactoryTest"`
Expected: FAIL — `CorrelatorFactory` does not exist.

- [ ] **Step 3: Write `CorrelatorFactory`**

```kotlin
package com.watchdog.app.correlate

import android.content.Context
import com.watchdog.app.correlate.direct.DirectOsvCorrelator
import com.watchdog.app.correlate.remote.RemoteCorrelator
import com.watchdog.app.settings.Settings
import com.watchdog.app.settings.SettingsRepository
import kotlinx.coroutines.flow.first

enum class CorrelationTarget { OSV, OWN_SERVER }

/** Builds a Correlator on demand. Mirrors the old private ScanController.buildCorrelator. */
class CorrelatorFactory(context: Context) {
    private val settingsRepo = SettingsRepository(context.applicationContext)

    suspend fun availableTargets(): List<CorrelationTarget> = targetsFor(settingsRepo.settings.first())

    suspend fun create(target: CorrelationTarget): Correlator {
        val s = settingsRepo.settings.first()
        return when (target) {
            CorrelationTarget.OWN_SERVER ->
                if (s.serverBaseUrl.isNotBlank()) {
                    RemoteCorrelator(baseUrl = s.serverBaseUrl, token = s.serverToken.ifBlank { null })
                } else {
                    DirectOsvCorrelator()
                }
            CorrelationTarget.OSV -> DirectOsvCorrelator()
        }
    }

    companion object {
        fun targetsFor(s: Settings): List<CorrelationTarget> =
            if (s.serverBaseUrl.isNotBlank()) listOf(CorrelationTarget.OSV, CorrelationTarget.OWN_SERVER)
            else listOf(CorrelationTarget.OSV)
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew testDebugUnitTest --tests "com.watchdog.app.correlate.CorrelatorFactoryTest"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/java/com/watchdog/app/correlate/CorrelatorFactory.kt android/app/src/test/java/com/watchdog/app/correlate/CorrelatorFactoryTest.kt
git commit -m "Add CorrelatorFactory for on-demand correlation"
```

---

### Task 3: `scanHosts` in controller/service; drop whole-network + inline correlation

**Files:**
- Modify: `android/app/src/main/java/com/watchdog/app/service/ScanController.kt`
- Modify: `android/app/src/main/java/com/watchdog/app/service/ScanForegroundService.kt`

**Interfaces:**
- Produces:
  - `ScanController.scanHosts(ips: List<String>, config: ScanConfig)` — runs `engine.scan(ips, config)` under the existing `scanId`, folds events, `finishScan(scanId, "DONE")`, sets `finished`.
  - `ScanForegroundService.scanHosts(context, ips: List<String>, depth: ScanDepth)` (companion) via `ACTION_SCAN_HOSTS` with `EXTRA_HOSTS` (`ArrayList<String>`).
  - `ScanController.startDiscovery(config)` unchanged (discovery step).

- [ ] **Step 1: Update `ScanController`**

Remove `buildCorrelator()` and the `correlator` usage. Replace the whole-network + single-host scan methods with a generalized `scanHosts`, and make `runScan` correlation-free:

```kotlin
fun scanHosts(ips: List<String>, config: ScanConfig) {
    val scanId = ScanStateHolder.current().scanId ?: return
    job?.cancel()
    job = scope.launch {
        try {
            ScanStateHolder.update {
                it.copy(running = true, awaitingHostPick = false, hostsTotal = ips.size, hostsDone = 0)
            }
            runScan(scanId, ips, config)
        } catch (ce: CancellationException) {
            markCancelled(scanId); throw ce
        } catch (e: Exception) {
            markFailed(scanId, e.message ?: e.toString())
        } finally {
            onTerminal()
        }
    }
}

private suspend fun runScan(scanId: Long, hosts: List<String>, config: ScanConfig) {
    engine.scan(hosts, config).collect { ev -> fold(scanId, ev) }
    repo.finishScan(scanId, "DONE")
    ScanStateHolder.update { it.copy(finished = true, running = false) }
}
```

Delete `startWholeNetwork`, `scanPickedHost`, `buildCorrelator`, and the `is ScanEvent.Correlated` arm in `fold` (correlation no longer flows through the engine). Keep `startDiscovery` (its body still ends `running = false, awaitingHostPick = true`). Remove the `import com.watchdog.app.correlate.*` and settings-mode imports that are now unused.

- [ ] **Step 2: Update `ScanForegroundService`**

Replace `ACTION_WHOLE`/`ACTION_SCAN_HOST` handling with discovery + `ACTION_SCAN_HOSTS`:

```kotlin
when (intent?.action) {
    ACTION_DISCOVER -> controller.startDiscovery(config)
    ACTION_SCAN_HOSTS -> intent.getStringArrayListExtra(EXTRA_HOSTS)?.let { controller.scanHosts(it, config) }
    ACTION_CANCEL -> controller.cancel()
}
```

Add to the companion:

```kotlin
const val ACTION_SCAN_HOSTS = "com.watchdog.app.SCAN_HOSTS"
const val EXTRA_HOSTS = "hosts"

fun scanHosts(context: Context, ips: List<String>, depth: ScanDepth) =
    context.startForegroundService(
        base(context, ACTION_SCAN_HOSTS, depth, ScanScope.SINGLE_HOST, false)
            .putStringArrayListExtra(EXTRA_HOSTS, ArrayList(ips)),
    )
```

Remove `ACTION_WHOLE`, `ACTION_SCAN_HOST`, `EXTRA_HOST`, `startWholeNetwork`, `scanHost`.

- [ ] **Step 3: Compile check**

Run: `./gradlew compileDebugKotlin`
Expected: fails only on `ScanViewModel`/`WatchDogApp` call sites (fixed in Tasks 5/10). No errors inside `service/`.

- [ ] **Step 4: Commit**

```bash
git add android/app/src/main/java/com/watchdog/app/service/ScanController.kt android/app/src/main/java/com/watchdog/app/service/ScanForegroundService.kt
git commit -m "Generalize scan to a selected host list; drop whole-network + inline correlation"
```

---

### Task 4: Room — rebuild observations for a scan + `deleteScan`

**Files:**
- Modify: `android/app/src/main/java/com/watchdog/app/data/room/WatchDogDao.kt`
- Modify: `android/app/src/main/java/com/watchdog/app/data/room/ScanRepository.kt`
- Test: `android/app/src/test/java/com/watchdog/app/data/room/ObservationRebuildTest.kt`

**Interfaces:**
- Produces:
  - `WatchDogDao.observationRows(scanId): Flow<List<ObservationRow>>` where `ObservationRow(host, port, proto, serviceName, vendor, product, version, cpe, distro, distroRelease, distroPackage, distroPkgVersion, banner, httpServer, httpPoweredBy, tlsSubject, tlsIssuer, tlsNotAfter)`.
  - `WatchDogDao.deleteScan(id: Long)`.
  - `ScanRepository.observeObservations(scanId): Flow<List<ServiceObservation>>` and `observeObservations(scanId, host)`.
  - `ScanRepository.deleteScan(id)`.
  - `ScanRepository.rowToObservation(row): ServiceObservation` (internal, tested).

- [ ] **Step 1: Write the failing test** (pure mapping, no Room needed)

```kotlin
package com.watchdog.app.data.room

import org.junit.Assert.assertEquals
import org.junit.Test

class ObservationRebuildTest {
    @Test
    fun `row maps to observation with product and evidence`() {
        val row = ObservationRow(
            host = "192.168.1.5", port = 22, proto = "tcp", serviceName = "ssh",
            vendor = "openbsd", product = "openssh", version = "8.2p1", cpe = null,
            distro = "ubuntu", distroRelease = "focal", distroPackage = null, distroPkgVersion = "1:8.2p1-4",
            banner = "SSH-2.0-OpenSSH_8.2p1", httpServer = null, httpPoweredBy = null,
            tlsSubject = null, tlsIssuer = null, tlsNotAfter = null,
        )
        val obs = ScanRepository.rowToObservation(row)
        assertEquals("192.168.1.5", obs.host)
        assertEquals(22, obs.port)
        assertEquals("openssh", obs.product?.product)
        assertEquals("8.2p1", obs.product?.version)
        assertEquals("SSH-2.0-OpenSSH_8.2p1", obs.evidence?.banner)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew testDebugUnitTest --tests "com.watchdog.app.data.room.ObservationRebuildTest"`
Expected: FAIL — `ObservationRow` / `rowToObservation` do not exist.

- [ ] **Step 3: Add the DAO POJO + queries**

In `WatchDogDao.kt`:

```kotlin
data class ObservationRow(
    val host: String, val port: Int, val proto: String,
    val serviceName: String?, val vendor: String?, val product: String?, val version: String?, val cpe: String?,
    val distro: String?, val distroRelease: String?, val distroPackage: String?, val distroPkgVersion: String?,
    val banner: String?, val httpServer: String?, val httpPoweredBy: String?,
    val tlsSubject: String?, val tlsIssuer: String?, val tlsNotAfter: String?,
)

@Query(
    """
    SELECT h.ip AS host, p.port AS port, p.proto AS proto,
           s.serviceName AS serviceName, s.vendor AS vendor, s.product AS product,
           s.version AS version, s.cpe AS cpe, s.distro AS distro, s.distroRelease AS distroRelease,
           s.distroPackage AS distroPackage, s.distroPkgVersion AS distroPkgVersion,
           f.banner AS banner, f.httpServer AS httpServer, f.httpPoweredBy AS httpPoweredBy,
           f.tlsSubject AS tlsSubject, f.tlsIssuer AS tlsIssuer, f.tlsNotAfter AS tlsNotAfter
    FROM services s
    INNER JOIN ports p ON s.portId = p.id
    INNER JOIN hosts h ON p.hostId = h.id
    LEFT JOIN fingerprints f ON f.serviceId = s.id
    WHERE h.scanId = :scanId
    ORDER BY h.ip, p.port
    """,
)
fun observationRows(scanId: Long): Flow<List<ObservationRow>>

@Query("DELETE FROM scans WHERE id = :id")
suspend fun deleteScan(id: Long)
```

- [ ] **Step 4: Add repository mapping + accessors**

In `ScanRepository.kt`:

```kotlin
fun observeObservations(scanId: Long): Flow<List<ServiceObservation>> =
    dao.observationRows(scanId).map { rows -> rows.map { rowToObservation(it) } }

fun observeObservations(scanId: Long, host: String): Flow<List<ServiceObservation>> =
    observeObservations(scanId).map { list -> list.filter { it.host == host } }

suspend fun deleteScan(id: Long) = dao.deleteScan(id)

companion object {
    fun rowToObservation(r: ObservationRow) = ServiceObservation(
        host = r.host, port = r.port, proto = r.proto, serviceName = r.serviceName,
        product = r.product?.let {
            ProductIdentity(
                vendor = r.vendor, product = it, version = r.version, cpe = r.cpe,
                distro = r.distro, distroRelease = r.distroRelease,
                distroPackage = r.distroPackage, distroPkgVersion = r.distroPkgVersion,
            )
        },
        evidence = ServiceEvidence(
            banner = r.banner, httpServer = r.httpServer, httpPoweredBy = r.httpPoweredBy,
            tlsSubject = r.tlsSubject, tlsIssuer = r.tlsIssuer, tlsNotAfter = r.tlsNotAfter,
        ),
        exposure = Exposure(reachable = true),
    )
}
```

Add imports for `ServiceObservation`, `ProductIdentity`, `ServiceEvidence`, `Exposure`.

- [ ] **Step 5: Run test to verify it passes**

Run: `./gradlew testDebugUnitTest --tests "com.watchdog.app.data.room.ObservationRebuildTest"`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add android/app/src/main/java/com/watchdog/app/data/room/WatchDogDao.kt android/app/src/main/java/com/watchdog/app/data/room/ScanRepository.kt android/app/src/test/java/com/watchdog/app/data/room/ObservationRebuildTest.kt
git commit -m "Room: rebuild observations for a scan + deleteScan"
```

---

### Task 5: ViewModel — new stages, selection, results loading, on-demand check

**Files:**
- Modify: `android/app/src/main/java/com/watchdog/app/ui/ScanViewModel.kt`

**Interfaces:**
- Produces (consumed by Tasks 6–11):
  - `enum class Stage { Networks, Discovering, SelectDevices, ChoosePorts, Scanning, Results, DeviceDetail, History, Settings }`
  - `startDiscovery()`, `rediscover()`, `toggleDevice(ip)`, `selectAll()`, `clearSelection()`, `selectedDevices: StateFlow<Set<String>>`, `proceedToPorts()`, `startScanSelected()`.
  - Results flows for `currentScanId: StateFlow<Long?>`: `resultHosts: StateFlow<List<HostEntity>>`, `resultObservations: StateFlow<List<ServiceObservation>>`, `resultFindings: StateFlow<List<Finding>>`.
  - `openDevice(host)`, `selectedHost: StateFlow<String?>`.
  - `checkVulnerabilities(target: CorrelationTarget)`, `vulnCheckState: StateFlow<VulnCheckState>` (`Idle|Running|Error(msg)`), `correlationTargets: StateFlow<List<CorrelationTarget>>`.
  - `deepRescanDevice()` (re-runs `scanHosts([selectedHost], selectedDepth)`).
  - `recentScans: StateFlow<List<ScanEntity>>`, `openHistoryScan(scanId)`, `deleteScan(scanId)`, `openHistory()`.

- [ ] **Step 1: Replace the Stage enum + FINISHABLE set**

```kotlin
enum class Stage { Networks, Discovering, SelectDevices, ChoosePorts, Scanning, Results, DeviceDetail, History, Settings }
private val FINISHABLE_STAGES = setOf(Stage.Scanning)
```

- [ ] **Step 2: Add selection + results + correlation state and repo access**

Inside `ScanViewModel`:

```kotlin
private val repo = ScanRepository(WatchDogDatabase.get(app).dao())
private val correlatorFactory = CorrelatorFactory(app)

private val _selectedDevices = MutableStateFlow<Set<String>>(emptySet())
val selectedDevices: StateFlow<Set<String>> = _selectedDevices.asStateFlow()

private val _currentScanId = MutableStateFlow<Long?>(null)
val currentScanId: StateFlow<Long?> = _currentScanId.asStateFlow()

private val _selectedHost = MutableStateFlow<String?>(null)
val selectedHost: StateFlow<String?> = _selectedHost.asStateFlow()

sealed interface VulnCheckState { data object Idle: VulnCheckState; data object Running: VulnCheckState; data class Error(val message: String): VulnCheckState }
private val _vulnCheckState = MutableStateFlow<VulnCheckState>(VulnCheckState.Idle)
val vulnCheckState: StateFlow<VulnCheckState> = _vulnCheckState.asStateFlow()

private val _correlationTargets = MutableStateFlow(listOf(CorrelationTarget.OSV))
val correlationTargets: StateFlow<List<CorrelationTarget>> = _correlationTargets.asStateFlow()

@OptIn(ExperimentalCoroutinesApi::class)
val resultHosts: StateFlow<List<HostEntity>> = _currentScanId
    .flatMapLatest { id -> if (id == null) flowOf(emptyList()) else repo.observeHosts(id) }
    .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

@OptIn(ExperimentalCoroutinesApi::class)
val resultObservations: StateFlow<List<ServiceObservation>> = _currentScanId
    .flatMapLatest { id -> if (id == null) flowOf(emptyList()) else repo.observeObservations(id) }
    .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

@OptIn(ExperimentalCoroutinesApi::class)
val resultFindings: StateFlow<List<Finding>> = _currentScanId
    .flatMapLatest { id -> if (id == null) flowOf(emptyList()) else repo.observeFindings(id) }
    .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

val recentScans: StateFlow<List<ScanEntity>> =
    repo.let { r -> WatchDogDatabase.get(getApplication()).dao().observeRecentScans() }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())
```

Add imports: `ScanRepository`, `WatchDogDatabase`, `HostEntity`, `ScanEntity`, `ServiceObservation`, `Finding`, `CorrelatorFactory`, `CorrelationTarget`, `ExperimentalCoroutinesApi`, `flatMapLatest`, `flowOf`, `SharingStarted`, `stateIn`.

- [ ] **Step 3: Replace the flow methods**

```kotlin
fun startDiscovery() {
    _selectedDevices.value = emptySet()
    ScanForegroundService.startDiscovery(getApplication(), _selectedDepth.value, _allowLargeSubnet.value)
    _stage.value = Stage.Discovering
}
fun rediscover() = startDiscovery()

fun toggleDevice(ip: String) {
    _selectedDevices.value = _selectedDevices.value.toMutableSet().apply { if (!add(ip)) remove(ip) }
}
fun selectAll() { _selectedDevices.value = runState.value.discoveredHosts.map { it.ip }.toSet() }
fun clearSelection() { _selectedDevices.value = emptySet() }

fun proceedToPorts() { if (_selectedDevices.value.isNotEmpty()) _stage.value = Stage.ChoosePorts }

fun startScanSelected() {
    ScanForegroundService.scanHosts(getApplication(), _selectedDevices.value.toList(), _selectedDepth.value)
    _currentScanId.value = ScanStateHolder.current().scanId
    _stage.value = Stage.Scanning
}

fun openDevice(host: String) { _selectedHost.value = host; _vulnCheckState.value = VulnCheckState.Idle; _stage.value = Stage.DeviceDetail }
fun backToResults() { _selectedHost.value = null; _stage.value = Stage.Results }

fun checkVulnerabilities(target: CorrelationTarget) {
    val scanId = _currentScanId.value ?: return
    val host = _selectedHost.value ?: return
    viewModelScope.launch {
        _vulnCheckState.value = VulnCheckState.Running
        try {
            val obs = repo.observeObservations(scanId, host).first()
            val response = correlatorFactory.create(target).correlate(obs)
            repo.saveFindings(scanId, response.findings + response.suppressed)
            _vulnCheckState.value = VulnCheckState.Idle
        } catch (e: Exception) {
            _vulnCheckState.value = VulnCheckState.Error(e.message ?: "Check failed")
        }
    }
}

fun deepRescanDevice() {
    val host = _selectedHost.value ?: return
    ScanForegroundService.scanHosts(getApplication(), listOf(host), ScanDepth.TOP_1000)
    _stage.value = Stage.Scanning
}

fun openHistory() { _stage.value = Stage.History }
fun openHistoryScan(scanId: Long) { _currentScanId.value = scanId; _stage.value = Stage.Results }
fun deleteScan(scanId: Long) { viewModelScope.launch { repo.deleteScan(scanId) } }
```

Load `correlationTargets` once in `init`: `viewModelScope.launch { _correlationTargets.value = correlatorFactory.availableTargets() }`.

- [ ] **Step 4: Update the auto-advance collector in `init`**

```kotlin
ScanStateHolder.state.collect { s ->
    when {
        s.awaitingHostPick && _stage.value == Stage.Discovering -> _stage.value = Stage.SelectDevices
        s.finished && _stage.value in FINISHABLE_STAGES -> {
            _currentScanId.value = s.scanId
            _stage.value = Stage.Results
        }
    }
}
```

Delete `goToScope`, `startWholeNetwork`, `startSingleHost`, `pickHost` and their references.

- [ ] **Step 5: Compile check**

Run: `./gradlew compileDebugKotlin`
Expected: fails only in `WatchDogApp.kt` + deleted `ScopeScreen`/`HostsScreen` PickHost usage (Task 10). ViewModel compiles.

- [ ] **Step 6: Commit**

```bash
git add android/app/src/main/java/com/watchdog/app/ui/ScanViewModel.kt
git commit -m "ViewModel: iterative stages, device selection, Room-backed results, on-demand vuln check"
```

---

### Task 6: `SelectDevicesScreen`

**Files:**
- Create: `android/app/src/main/java/com/watchdog/app/ui/select/SelectDevicesScreen.kt`

**Interfaces:**
- Consumes: `hosts: List<DiscoveredHost>`, `selected: Set<String>`, `discovering: Boolean`.
- Produces: composable `SelectDevicesScreen(hosts, selected, onToggle, onSelectAll, onClear, onRediscover, onContinue, onBack)`.

- [ ] **Step 1: Write the screen**

```kotlin
package com.watchdog.app.ui.select

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.watchdog.app.scan.discovery.DiscoveredHost
import com.watchdog.app.ui.common.ScreenChrome

@Composable
fun SelectDevicesScreen(
    hosts: List<DiscoveredHost>,
    selected: Set<String>,
    onToggle: (String) -> Unit,
    onSelectAll: () -> Unit,
    onClear: () -> Unit,
    onRediscover: () -> Unit,
    onContinue: () -> Unit,
    onBack: () -> Unit,
) {
    ScreenChrome(
        title = "Select devices",
        subtitle = "${hosts.size} found · ${selected.size} selected",
        onBack = onBack,
        primaryLabel = "Choose ports (${selected.size})",
        primaryEnabled = selected.isNotEmpty(),
        onPrimary = onContinue,
    ) {
        Column(Modifier.fillMaxSize()) {
            Row {
                TextButton(onClick = onSelectAll) { Text("Select all") }
                TextButton(onClick = onClear) { Text("Clear") }
                Spacer(Modifier.weight(1f))
                TextButton(onClick = onRediscover) { Text("Discover again") }
            }
            LazyColumn(Modifier.weight(1f).fillMaxWidth()) {
                items(hosts, key = { it.ip }) { host ->
                    Row(
                        Modifier.fillMaxWidth().height(56.dp).clickable { onToggle(host.ip) },
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Checkbox(checked = host.ip in selected, onCheckedChange = { onToggle(host.ip) })
                        Column(Modifier.weight(1f)) {
                            Text(host.ip, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyLarge)
                            val label = host.hostname ?: host.serviceHints.firstOrNull()
                            if (label != null) Text(label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        Text(host.source, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                }
            }
        }
    }
}
```

- [ ] **Step 2: Commit**

```bash
git add android/app/src/main/java/com/watchdog/app/ui/select/SelectDevicesScreen.kt
git commit -m "Add SelectDevicesScreen (multi-select discovered devices)"
```

---

### Task 7: `ChoosePortsScreen`

**Files:**
- Create: `android/app/src/main/java/com/watchdog/app/ui/select/ChoosePortsScreen.kt`

**Interfaces:**
- Produces: composable `ChoosePortsScreen(selectedDepth, onDepthChange, deviceCount, onStart, onBack)`.

- [ ] **Step 1: Write the screen** (depth radios lifted from ScopeScreen)

```kotlin
package com.watchdog.app.ui.select

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.selection.selectable
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.watchdog.app.scan.ScanDepth
import com.watchdog.app.ui.common.ScreenChrome

@Composable
fun ChoosePortsScreen(
    selectedDepth: ScanDepth,
    onDepthChange: (ScanDepth) -> Unit,
    deviceCount: Int,
    onStart: () -> Unit,
    onBack: () -> Unit,
) {
    ScreenChrome(
        title = "What ports to scan?",
        subtitle = "$deviceCount device${if (deviceCount == 1) "" else "s"} selected",
        onBack = onBack,
        primaryLabel = "Start scan",
        onPrimary = onStart,
    ) {
        Column(Modifier.fillMaxWidth()) {
            ScanDepth.entries.forEach { depth ->
                Row(
                    Modifier.fillMaxWidth().height(48.dp)
                        .selectable(selected = depth == selectedDepth, onClick = { onDepthChange(depth) }),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioButton(selected = depth == selectedDepth, onClick = { onDepthChange(depth) })
                    Text(depth.label, style = MaterialTheme.typography.bodyMedium)
                    Spacer(Modifier.weight(1f))
                    Text(depth.estimate, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
}
```

- [ ] **Step 2: Commit**

```bash
git add android/app/src/main/java/com/watchdog/app/ui/select/ChoosePortsScreen.kt
git commit -m "Add ChoosePortsScreen (port depth after selection)"
```

---

### Task 8: Extract `FindingRow` + `ResultsScreen`

**Files:**
- Create: `android/app/src/main/java/com/watchdog/app/ui/common/FindingRow.kt`
- Modify: `android/app/src/main/java/com/watchdog/app/ui/findings/FindingsScreen.kt` (use the extracted row)
- Create: `android/app/src/main/java/com/watchdog/app/ui/results/ResultsScreen.kt`

**Interfaces:**
- Produces: `@Composable fun FindingRow(f: Finding)` (public, moved verbatim from FindingsScreen incl. `StateBadge`).
- Produces: `ResultsScreen(scanNetwork: String?, hosts: List<HostEntity>, observations: List<ServiceObservation>, onOpenDevice: (String) -> Unit, onShare: () -> Unit, onDone: () -> Unit)`.

- [ ] **Step 1: Move `FindingRow`/`StateBadge`** from `FindingsScreen.kt` into `ui/common/FindingRow.kt` (make `FindingRow` public), and update `FindingsScreen` to import it. Keep behavior identical.

- [ ] **Step 2: Write `ResultsScreen`**

```kotlin
package com.watchdog.app.ui.results

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.watchdog.app.data.room.HostEntity
import com.watchdog.app.scan.model.ServiceObservation
import com.watchdog.app.ui.common.LabeledCard
import com.watchdog.app.ui.common.ScreenChrome

@Composable
fun ResultsScreen(
    scanNetwork: String?,
    hosts: List<HostEntity>,
    observations: List<ServiceObservation>,
    onOpenDevice: (String) -> Unit,
    onShare: () -> Unit,
    onDone: () -> Unit,
) {
    val byHost = observations.groupBy { it.host }
    ScreenChrome(
        title = "Results",
        subtitle = scanNetwork,
        onBack = null,
        primaryLabel = "Done",
        onPrimary = onDone,
        secondaryLabel = "Share report",
        onSecondary = onShare,
    ) {
        Column(Modifier.fillMaxSize()) {
            LabeledCard(
                label = "Summary",
                value = "${hosts.size} devices · ${observations.size} services",
            )
            Spacer(Modifier.height(12.dp))
            LazyColumn(Modifier.weight(1f).fillMaxWidth()) {
                items(hosts, key = { it.id }) { h ->
                    val services = byHost[h.ip].orEmpty()
                    Row(
                        Modifier.fillMaxWidth().height(60.dp).clickable { onOpenDevice(h.ip) },
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(h.ip, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyLarge)
                            Text(
                                h.hostname ?: "${services.size} service${if (services.size == 1) "" else "s"}",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        Text("›", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                }
            }
        }
    }
}
```

- [ ] **Step 3: Commit**

```bash
git add android/app/src/main/java/com/watchdog/app/ui/common/FindingRow.kt android/app/src/main/java/com/watchdog/app/ui/findings/FindingsScreen.kt android/app/src/main/java/com/watchdog/app/ui/results/ResultsScreen.kt
git commit -m "Add ResultsScreen (device-centric) and extract reusable FindingRow"
```

---

### Task 9: `DeviceDetailScreen` (fingerprint, on-demand check, deep re-scan, share)

**Files:**
- Create: `android/app/src/main/java/com/watchdog/app/ui/results/DeviceDetailScreen.kt`
- Create: `android/app/src/main/java/com/watchdog/app/share/ScanShare.kt`

**Interfaces:**
- Consumes: `ScanViewModel.VulnCheckState`, `CorrelationTarget`, `ServiceObservation`, `Finding`, `FindingRow`.
- Produces: `DeviceDetailScreen(host, observations, findings, vulnState, targets, onCheck, onDeepRescan, onShare, onBack)`; `ScanShare.deviceText(host, observations, findings): String` and `ScanShare.share(context, text)`.

- [ ] **Step 1: Write `ScanShare`**

```kotlin
package com.watchdog.app.share

import android.content.Context
import android.content.Intent
import com.watchdog.app.scan.model.Finding
import com.watchdog.app.scan.model.ServiceObservation

object ScanShare {
    fun deviceText(host: String, obs: List<ServiceObservation>, findings: List<Finding>): String = buildString {
        appendLine("Device $host")
        appendLine("Services:")
        obs.forEach { o ->
            val prod = o.product?.let { " ${it.product}${it.version?.let { v -> " $v" } ?: ""}" } ?: ""
            appendLine("  ${o.port}/${o.proto} ${o.serviceName ?: ""}$prod".trimEnd())
        }
        if (findings.isNotEmpty()) {
            appendLine("Findings:")
            findings.forEach { f -> appendLine("  ${f.severity} ${f.cveId} ${f.product.product} ${f.host}:${f.port}") }
        }
    }

    fun share(context: Context, text: String) {
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, text)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        context.startActivity(Intent.createChooser(intent, "Share").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }
}
```

- [ ] **Step 2: Write `DeviceDetailScreen`**

```kotlin
package com.watchdog.app.ui.results

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.watchdog.app.correlate.CorrelationTarget
import com.watchdog.app.scan.model.Finding
import com.watchdog.app.scan.model.ServiceObservation
import com.watchdog.app.ui.ScanViewModel
import com.watchdog.app.ui.common.FindingRow
import com.watchdog.app.ui.common.InfoBanner
import com.watchdog.app.ui.common.ScreenChrome

@Composable
fun DeviceDetailScreen(
    host: String,
    observations: List<ServiceObservation>,
    findings: List<Finding>,
    vulnState: ScanViewModel.VulnCheckState,
    targets: List<CorrelationTarget>,
    onCheck: (CorrelationTarget) -> Unit,
    onDeepRescan: () -> Unit,
    onShare: () -> Unit,
    onBack: () -> Unit,
) {
    ScreenChrome(title = host, subtitle = "${observations.size} services", onBack = onBack, primaryLabel = null) {
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
            observations.forEach { o ->
                Text(
                    "${o.port}/${o.proto}  ${o.serviceName ?: ""}  ${o.product?.let { "${it.product} ${it.version ?: ""}" } ?: ""}".trim(),
                    fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyMedium,
                )
                val e = o.evidence
                if (e?.banner != null) Text(e.banner!!, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (e?.httpServer != null) Text("Server: ${e.httpServer}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (e?.tlsSubject != null) Text("TLS: ${e.tlsSubject}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            }

            Spacer(Modifier.height(16.dp))
            Text("Vulnerability check", style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(8.dp))
            Row {
                targets.forEach { t ->
                    val label = if (t == CorrelationTarget.OSV) "Check against OSV" else "Check against my server"
                    Button(onClick = { onCheck(t) }, enabled = vulnState !is ScanViewModel.VulnCheckState.Running) { Text(label) }
                    Spacer(Modifier.width(8.dp))
                }
            }
            when (vulnState) {
                is ScanViewModel.VulnCheckState.Running -> { Spacer(Modifier.height(8.dp)); LinearProgressIndicator(Modifier.fillMaxWidth()) }
                is ScanViewModel.VulnCheckState.Error -> { Spacer(Modifier.height(8.dp)); InfoBanner((vulnState).message) }
                else -> {}
            }

            if (findings.isNotEmpty()) {
                Spacer(Modifier.height(12.dp))
                findings.forEach { FindingRow(it); HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant) }
            } else if (vulnState is ScanViewModel.VulnCheckState.Idle) {
                Spacer(Modifier.height(8.dp))
                Text("No vulnerabilities checked yet.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }

            Spacer(Modifier.height(20.dp))
            TextButton(onClick = onDeepRescan) { Text("Deep re-scan this device") }
            TextButton(onClick = onShare) { Text("Share device info") }
        }
    }
}
```

- [ ] **Step 3: Commit**

```bash
git add android/app/src/main/java/com/watchdog/app/ui/results/DeviceDetailScreen.kt android/app/src/main/java/com/watchdog/app/share/ScanShare.kt
git commit -m "Add DeviceDetailScreen with on-demand OSV/server check, deep re-scan, share"
```

---

### Task 10: Wire the new stages in `WatchDogApp` + retire ScopeScreen

**Files:**
- Modify: `android/app/src/main/java/com/watchdog/app/WatchDogApp.kt`
- Delete: `android/app/src/main/java/com/watchdog/app/ui/scope/ScopeScreen.kt`
- Modify: `android/app/src/main/java/com/watchdog/app/ui/networks/NetworksScreen.kt` (Continue → discovery; add History action)
- Modify: `android/app/src/main/java/com/watchdog/app/ui/hosts/HostsScreen.kt` (Discovering-only; remove PickHost/onSelect usage from app wiring)

**Interfaces:**
- Consumes: all `ScanViewModel` methods/flows from Task 5, the screens from Tasks 6–9, HistoryScreen from Task 11.

- [ ] **Step 1: Update `NetworksScreen`** — change `onContinue` wording to "Continue" (starts discovery) and add an `onOpenHistory: () -> Unit` param rendered as a second text action near Settings (add a `Row` of `TextButton`s: "History" + keep the existing "Settings" secondary).

- [ ] **Step 2: Update the `when (stage)` in `WatchDogApp`**

```kotlin
Stage.Networks -> NetworksScreen(/* … */, onContinue = vm::startDiscovery, onOpenHistory = vm::openHistory, /* … */)
Stage.Discovering -> HostsScreen(hosts = runState.discoveredHosts, discovering = true, onSelect = null, onBack = vm::startOver, onCancel = vm::cancel)
Stage.SelectDevices -> SelectDevicesScreen(
    hosts = runState.discoveredHosts, selected = selectedDevices,
    onToggle = vm::toggleDevice, onSelectAll = vm::selectAll, onClear = vm::clearSelection,
    onRediscover = vm::rediscover, onContinue = vm::proceedToPorts, onBack = vm::startOver,
)
Stage.ChoosePorts -> ChoosePortsScreen(
    selectedDepth = selectedDepth, onDepthChange = vm::setDepth,
    deviceCount = selectedDevices.size, onStart = vm::startScanSelected, onBack = { /* back to SelectDevices */ },
)
Stage.Scanning -> ScanningScreen(state = runState, onCancel = vm::cancel)
Stage.Results -> ResultsScreen(
    scanNetwork = network?.ssid, hosts = resultHosts, observations = resultObservations,
    onOpenDevice = vm::openDevice, onShare = { ScanShare.share(context, ScanShare.reportText(resultHosts, resultObservations, resultFindings)) },
    onDone = vm::startOver,
)
Stage.DeviceDetail -> {
    val host = selectedHost
    if (host != null) DeviceDetailScreen(
        host = host,
        observations = resultObservations.filter { it.host == host },
        findings = resultFindings.filter { it.host == host },
        vulnState = vulnState, targets = correlationTargets,
        onCheck = vm::checkVulnerabilities, onDeepRescan = vm::deepRescanDevice,
        onShare = { ScanShare.share(context, ScanShare.deviceText(host, resultObservations.filter { it.host == host }, resultFindings.filter { it.host == host })) },
        onBack = vm::backToResults,
    )
}
Stage.History -> HistoryScreen(scans = recentScans, onOpen = vm::openHistoryScan, onDelete = vm::deleteScan, onExport = { id -> /* Task 11 */ }, onBack = vm::startOver)
Stage.Settings -> SettingsScreen(/* unchanged */)
```

Collect the new flows at the top: `val selectedDevices by vm.selectedDevices.collectAsStateWithLifecycle()`, `resultHosts`, `resultObservations`, `resultFindings`, `selectedHost`, `vulnState`, `correlationTargets`, `recentScans`.

Update `BackHandler`: `Stage.SelectDevices -> vm.startOver`, `Stage.ChoosePorts -> (back to SelectDevices)`, `Stage.Results -> vm.startOver`, `Stage.DeviceDetail -> vm.backToResults`, `Stage.History -> vm.startOver`, `Stage.Discovering -> vm.startOver`.

- [ ] **Step 3: Add `ScanShare.reportText`** (whole-scan export) in `share/ScanShare.kt`:

```kotlin
fun reportText(hosts: List<com.watchdog.app.data.room.HostEntity>, obs: List<ServiceObservation>, findings: List<Finding>): String = buildString {
    appendLine("watchDog scan report")
    appendLine("${hosts.size} devices, ${obs.size} services, ${findings.size} findings")
    hosts.forEach { h -> appendLine(deviceText(h.ip, obs.filter { it.host == h.ip }, findings.filter { it.host == h.ip })) }
}
```

- [ ] **Step 4: Delete `ScopeScreen.kt`** and remove its import.

- [ ] **Step 5: Compile the app**

Run: `./gradlew compileDebugKotlin`
Expected: PASS (HistoryScreen referenced by Stage.History must exist — do Task 11 before this compiles, or stub the arm). If sequencing inline, implement Task 11 first.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "Wire iterative flow stages; retire ScopeScreen; History entry on home"
```

---

## PHASE 3 — History

### Task 11: `HistoryScreen` (browse / reopen / delete / export)

**Files:**
- Create: `android/app/src/main/java/com/watchdog/app/ui/history/HistoryScreen.kt`

**Interfaces:**
- Consumes: `ScanEntity`, `recentScans`.
- Produces: `HistoryScreen(scans: List<ScanEntity>, onOpen: (Long) -> Unit, onDelete: (Long) -> Unit, onExport: (Long) -> Unit, onBack: () -> Unit)`.

- [ ] **Step 1: Write the screen**

```kotlin
package com.watchdog.app.ui.history

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.watchdog.app.data.room.ScanEntity
import com.watchdog.app.ui.common.CancelConfirmDialog
import com.watchdog.app.ui.common.ScreenChrome

@Composable
fun HistoryScreen(
    scans: List<ScanEntity>,
    onOpen: (Long) -> Unit,
    onDelete: (Long) -> Unit,
    onExport: (Long) -> Unit,
    onBack: () -> Unit,
) {
    var confirmDeleteId by remember { mutableStateOf<Long?>(null) }
    confirmDeleteId?.let { id ->
        AlertDialog(
            onDismissRequest = { confirmDeleteId = null },
            title = { Text("Delete scan?") },
            text = { Text("This permanently removes the scan and its devices/findings.") },
            confirmButton = { TextButton(onClick = { onDelete(id); confirmDeleteId = null }) { Text("Delete") } },
            dismissButton = { TextButton(onClick = { confirmDeleteId = null }) { Text("Cancel") } },
        )
    }
    ScreenChrome(title = "History", subtitle = "${scans.size} scans", onBack = onBack, primaryLabel = null) {
        LazyColumn(Modifier.fillMaxSize()) {
            items(scans, key = { it.id }) { s ->
                Row(Modifier.fillMaxWidth().height(64.dp).clickable { onOpen(s.id) }, verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("${s.networkId} · ${s.status}", style = MaterialTheme.typography.bodyLarge)
                        Text("depth ${s.depth} · started ${s.startedAt}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    TextButton(onClick = { onExport(s.id) }) { Text("Export") }
                    TextButton(onClick = { confirmDeleteId = s.id }) { Text("Delete") }
                }
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            }
        }
    }
}
```

- [ ] **Step 2: Wire export** — in `WatchDogApp` `Stage.History`, implement `onExport = { id -> vm.exportScan(id, context) }`. Add to `ScanViewModel`:

```kotlin
fun exportScan(scanId: Long, context: android.content.Context) {
    viewModelScope.launch {
        val hosts = repo.observeHosts(scanId).first()
        val obs = repo.observeObservations(scanId).first()
        val findings = repo.observeFindings(scanId).first()
        com.watchdog.app.share.ScanShare.share(context, com.watchdog.app.share.ScanShare.reportText(hosts, obs, findings))
    }
}
```

- [ ] **Step 3: Compile + verify green tests**

Run: `./gradlew compileDebugKotlin testDebugUnitTest`
Expected: compiles; all unit tests pass.

- [ ] **Step 4: Commit**

```bash
git add android/app/src/main/java/com/watchdog/app/ui/history/HistoryScreen.kt android/app/src/main/java/com/watchdog/app/ui/ScanViewModel.kt android/app/src/main/java/com/watchdog/app/WatchDogApp.kt
git commit -m "Add scan history: browse, reopen, delete, export"
```

---

## Device verification (end of implementation)

On a device (no local SDK for instrumentation):
1. Home → Continue → devices stream in → **Select** a subset (or Select all) → **Choose ports** (Top 100) → **Start scan**.
2. Results shows the selected devices with service counts; open one → services + banners visible.
3. Tap **Check against OSV** → progress → findings appear **below** the still-visible services; details are not wiped. If a server is configured, **Check against my server** also appears.
4. **Deep re-scan this device** re-scans just that host; **Share device info** opens the chooser.
5. Home → **History** → list shows the scan → reopen → same Results view → **Export** shares a report → **Delete** (confirm) removes it.
6. Cancel works at Discovering and Scanning (existing confirm dialog).

## Self-review notes

- Spec coverage: staged flow (Tasks 5–10), device-centric results (8/9), additive on-demand correlation (2/4/5/9), OSV-vs-server choice (2/9), history browse/reopen/delete/export (4/5/11). ✓
- The app module will not fully compile until Task 10/11 land (call sites); intermediate tasks compile their own units and JVM tests pass — expected for a cross-cutting reflow.
- `ScanRunState.awaitingHostPick` is reused to mean "discovery finished, awaiting selection."
