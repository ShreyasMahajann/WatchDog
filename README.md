# watchDog

A guided, pentester-style network security assessment tool for Android, with a
correlation backend. Discover the network → discover hosts → enumerate services
→ fingerprint → correlate against vulnerability intelligence → prioritize → you
decide → safe verification.

**Core principle:** automate the repetitive work, keep the human in control of
important decisions.

## Preview

![watchDog guided workflow: host discovery, service enumeration, and prioritised findings](docs/preview.svg)

*Design mockup of the guided workflow. The app is in active development — the
current build is an app skeleton.*

## Architecture in one line

The **phone does 100% of network I/O** (discovery, enumeration, fingerprinting,
and verification execution). The **backend never connects to a target** — it is a
pure brain (correlation, prioritization, the vuln DB, and serving signed
check-definitions the phone runs locally). This eliminates backend SSRF by
construction.

See the full plan: `~/.claude/plans/i-want-you-to-shimmying-bird.md`.

## Repository layout

```
watchDog/
  backend/     TypeScript vulnerability-correlation engine (the brain).
               Pure, dependency-free core; deploys into the Website's API routes.
  android/     Kotlin + Jetpack Compose app (the hands).
  .github/     CI (backend tests + APK build) and release-on-tag pipeline.
```

## backend/

The correlation engine turns observed services into ranked, de-duplicated
findings with explicit confidence states:

`DETECTED → LIKELY_VULNERABLE → VERIFIED → EXPLOITABLE`

Key false-positive defenses (the hard part of this domain):

- **CVE-List-first**, not NVD-first (NVD stopped enriching most CVEs in 2026).
- **Distro backport suppression** — a real `dpkg` version comparator so that a
  banner like `OpenSSH_8.2p1 Ubuntu-4ubuntu0.11` is correctly judged *patched*
  by the distro even though upstream `8.2p1` looks vulnerable.
- Version-only matches never rank above `LIKELY_VULNERABLE`.
- CVSS chosen by provenance (v4 > v3.1, CNA > NVD) and **never averaged**.
- KEV + EPSS drive prioritization so range-match noise doesn't drown signal.

### Develop

```bash
cd backend
npm install
npm test        # node --test over the golden-set + version-comparator suites
npm run typecheck
```

Runs on Node ≥ 23.6 via native TypeScript type-stripping (no build step).

## android/

Kotlin + Jetpack Compose app (the "hands" — does all network I/O). Open the
`android/` folder in Android Studio; on first sync it generates the Gradle
wrapper jar (not committed). AGP 8.7 / Gradle 8.10.2 / Kotlin 2.0 / JDK 17,
`minSdk 26`, `compileSdk 35`.

## Releases

CI builds the APK on every push to `main` (`.github/workflows/ci.yml`), so the
app scaffold is continuously verified. To publish an installable APK, push a
version tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

`.github/workflows/release.yml` then builds the APK, names it
`watchDog-<version>.apk`, and attaches it to an auto-created GitHub Release with
generated notes. `versionName` comes from the tag; `versionCode` from the run
number.

The APK is **debug-signed** — installable by sideloading, which is the intended
distribution channel for this tool. To ship a properly release-signed build
later, add a keystore + signing secrets and switch the release job to
`assembleRelease`.
