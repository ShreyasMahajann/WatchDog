# Security Policy

## Supported versions

Security fixes are made on the `main` branch and shipped in the next tagged
release. Older releases are not patched.

## Reporting a vulnerability

Please do not report security problems in public issues, pull requests or
the Discord server.

Report them privately through GitHub instead: open the repository's
**Security** tab and choose **Report a vulnerability**. Only the maintainers
can see the report.

A useful report includes:

- what the problem is and which component it affects (correlation backend,
  scan core, Android app, desktop app, WPA handshake handling, Device Watch)
- the steps or configuration needed to reproduce it
- what an attacker could do with it
- the version or commit you tested against

Correlation mistakes are welcome too. If watchDog marks a vulnerable service
as patched, or the backend can be made to contact a scan target, report it the
same way.

## What to expect

- We acknowledge a report within 3 working days.
- We confirm or rule out the problem and tell you what we plan to do.
- Once a fix is ready we publish an advisory, and credit you unless you
  would rather stay anonymous.

## Out of scope

- watchDog is for networks and devices you own or are authorized to test.
  Using it against anything else is the operator's responsibility, not a
  vulnerability in watchDog.
- Release APKs are debug-signed by design, for sideloading.
- Scanning only the network the device is joined to is an Android platform
  limit, not a bug.
