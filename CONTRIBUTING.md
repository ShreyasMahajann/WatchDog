# Contributing to watchDog

Thanks for helping. This guide covers how to get set up, how changes are
made, and what happens after you open a pull request.

Questions are welcome on the [Ergane Foundation Discord](https://discord.gg/gZTJfUujX).
Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
Security problems go through [SECURITY.md](SECURITY.md), never a public issue.

watchDog is a network security assessment tool for networks and devices you
own or are authorized to test. Features must do real work: if it scans, it
actually scans. Do not submit mocks, stubs or demo-only code paths.

## Finding something to work on

Issues labelled `good first issue` are small and self-contained, and say which
files are involved. Comment on an issue before starting so two people do not
pick up the same one. If an issue has had no activity for a week after being
claimed, it is open again.

For anything larger than a bug fix, open an issue first and describe what you
want to change, so the approach can be agreed before you write the code.

## The rules that matter

**The backend never connects to a target.** The phone or desktop app does all
network I/O (discovery, enumeration, fingerprinting, verification). The
backend is a pure correlation engine. This split removes backend SSRF by
construction; a change that makes the backend reach a scan target will not be
merged.

**Parallel implementations stay in sync.** Some logic exists twice on purpose:

- The correlation engine: `backend/src/{version,match,correlate}.ts` and
  `android/core/.../correlate/engine/{Version,Match,CorrelateEngine}.kt` are
  ports of each other and are tested against the same golden set. A change to
  one lands in the other, with fixtures updated on both sides.
- The apps: a user-facing feature or fix in the Android UI is mirrored in the
  desktop UI, and the other way round, unless it is platform-specific (for
  example live WPA capture over USB). If you skip parity on purpose, say why
  in the pull request.

## Development setup

The repository has these parts:

| Directory | What it is |
| --- | --- |
| `backend/` | TypeScript correlation engine. No target I/O |
| `android/core/` | Pure Kotlin/JVM library: scanning, correlation, WPA parsing, device probes. No Android dependencies |
| `android/app/` | Android app (Jetpack Compose), depends on `:core` |
| `android/desktop/` | Compose for Desktop app for Windows and Linux, depends on `:core` |
| `docs/` | Architecture notes and images |
| `.github/` | CI, release pipeline and issue templates |

Backend (Node 23.6 or later, no build step):

```bash
cd backend
npm install
npm test
npm run typecheck
```

Android and desktop (JDK 17, Gradle 8.10.2, Android SDK for `:app`). Open
`android/` in Android Studio, or run a local Gradle inside `android/`:

```bash
gradle :core:test :app:testDebugUnitTest   # unit tests
gradle assembleDebug                        # build the APK
gradle :desktop:run                         # launch the desktop app
```

See [docs/architecture.md](docs/architecture.md) for how the pieces fit.

## Making a change

1. Fork the repository and create a branch from `main`.
2. Make the change, with tests for any behaviour you add or fix.
3. Run the test suites for every part you touched.
4. Open a pull request and fill in the template.

Pull request titles follow [Conventional Commits](https://www.conventionalcommits.org/),
for example `fix(core): handle RST-spoofing gateways` or
`feat(desktop): add adapter picker`.

## After you open a pull request

CI runs the backend tests, the Android unit tests and the desktop build. A
maintainer reviews the change; every pull request needs one approval before
it is merged. Expect questions, especially about parity and about where
network I/O happens.

By contributing you agree that your work is licensed under the
[Apache License 2.0](LICENSE).
