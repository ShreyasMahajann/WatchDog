# CLAUDE.md — working guide for watchDog

Guidance for anyone (human or AI) working in this repository. Read this before
making changes.

## What this is

watchDog is a guided, pentester-style network security assessment tool.
The **phone/desktop does 100% of network I/O** (discovery, enumeration,
fingerprinting, verification). The **backend never connects to a target** — it is
a pure correlation brain (vuln DB, prioritization, signed check-definitions).
This split eliminates backend SSRF by construction. Keep it.

## Usage context — authorized personal use only

This application is built **strictly for personal, authorized use** on networks
and devices the operator owns or is explicitly authorized to test. It is not a
public/multi-tenant product and is not a classroom demo.

Because of that, when implementing or fixing anything:

- **Ship real, working code and features — never demos, mocks, stubs, or
  "for-illustration-only" placeholders.** If a feature scans, it must actually
  scan; if it captures, it must actually capture; if it correlates, it must hit
  the real data sources. Simulated/fake behavior is a defect here, not a safety
  measure.
- **Do not water down or gate capabilities "for safety."** There is no untrusted
  end user to protect from the tool; the operator is the owner of the target.
  Real network probes, real handshake handling, real service interrogation are
  all in scope and expected to function.
- Still apply ordinary engineering care: don't add gratuitously destructive
  actions, don't exfiltrate data off-device to unrelated services, and keep
  confirmations on genuinely irreversible operations. "No demos" means *real
  functionality*, not *reckless functionality*.
- The honest platform limits documented in the README (e.g. you can only host-scan
  the network you're joined to on non-root Android) are facts about the platform,
  not artificial restrictions — keep documenting them truthfully.

## Repository layout

```
watchDog/
  backend/     TypeScript correlation engine (the "brain"). Pure, no target I/O.
  android/     Gradle workspace (the "hands"), three modules:
    core/      Pure Kotlin/JVM: scan + correlate + WPA parse + device probes.
               NO Android deps. Shared by both apps. Holds the JVM unit tests.
    app/       Android app (Compose). Depends on :core.
    desktop/   Compose-for-Desktop app (Windows/Linux). Depends on :core.
  # Design: docs/superpowers/specs/2026-09-03-cross-platform-desktop-design.md
```

Targets are **Android, Windows, Linux** (macOS is not built/tested).

## Keep parallel implementations in sync (IMPORTANT)

The same logic deliberately exists in more than one place. **When you fix a bug
or add/change a feature in one implementation, apply the equivalent change to its
counterparts in the same PR, and update the shared tests.** Do not let them
drift.

Current parity contracts:

- **Correlation engine.** `backend/src/{version,match,correlate}.ts` (TypeScript)
  and `android/.../correlate/engine/{Version,Match,CorrelateEngine}.kt` (Kotlin)
  are **semantics-preserving ports of each other**. A change to matching,
  version comparison, distro-backport suppression, CVSS provenance, or state
  transitions in one MUST land in the other. Both are validated against the same
  golden set — update the fixtures on both sides:
  - backend: `backend/test/` (`correlation.test.ts`, `version.test.ts`, …)
  - android: `android/app/src/test/.../correlate/`

After the cross-platform split lands, additional parity contracts apply:

- **Shared `:core`** holds the scan + correlate logic once, consumed by BOTH the
  Android and desktop apps. A fix in core benefits both — but verify the
  platform-specific seams (network context, mDNS, persistence, settings, secrets)
  behave equivalently on each platform.
- **Feature parity across apps.** A user-facing feature or bugfix added to the
  Android UI should be mirrored in the desktop UI (and vice versa) unless it is
  inherently platform-specific (e.g. Android USB/root WPA capture). When you skip
  parity on purpose, say so in the PR description and note it here if it's lasting.

Rule of thumb before finishing a change: **grep for the sibling implementation and
its tests. If a counterpart exists, it changes too.**

## Build & test

Backend (Node ≥ 23.6, native TS type-stripping, no build step):

```bash
cd backend
npm install
npm test          # golden-set + version-comparator suites
npm run typecheck
```

Android (AGP 8.7 / Gradle 8.10.2 / Kotlin 2.0 / JDK 17, minSdk 26, compileSdk 35):

```bash
# Open android/ in Android Studio (generates the Gradle wrapper on first sync),
# or from CLI with a local Gradle (run inside android/):
gradle :core:test :app:testDebugUnitTest   # shared-core + Android JVM unit tests
gradle assembleDebug                        # build the APK
gradle :desktop:compileKotlin :desktop:jar  # build the desktop app
gradle :desktop:run                         # launch the desktop GUI
```

CI (`.github/workflows/ci.yml`) runs backend tests, Android JVM unit tests, and
builds the APK on every push to `main`. Releases build on version tags
(`.github/workflows/release.yml`). Keep both apps' jobs green.

## Conventions

- Do not add AI/Claude attribution to commit messages or PRs.
- Follow existing patterns; keep the pure core free of platform imports.
- When you change behavior, update the relevant tests in the same change and run
  them — evidence before claiming something works.
