// Test fixtures: a small in-memory vuln DB + sample observations that exercise
// the false-positive-critical paths (upstream range, distro backport patched,
// distro backport still-vulnerable, KEV prioritization, out-of-range = no
// finding).

import { normalizeProduct } from "../src/match.ts";
import type { VulnSource } from "../src/correlate.ts";
import type { ServiceObservation, VulnRecord } from "../src/types.ts";

export const VULNS: VulnRecord[] = [
  {
    // OpenSSH: affected below 8.3. Ubuntu focal backported the fix into
    // 1:8.2p1-4ubuntu0.11, so a focal box at/above that revision is NOT
    // vulnerable even though upstream "8.2p1" looks affected.
    cveId: "CVE-2020-DEMO-SSH",
    ranges: [{ vendor: "openbsd", product: "openssh", introduced: "0", fixed: "8.3" }],
    distroFixes: [
      { distro: "ubuntu", release: "focal", pkg: "openssh", status: "fixed", fixedVersion: "1:8.2p1-4ubuntu0.11" },
    ],
    cvss: [{ version: "3.1", baseScore: 7.5, severity: "HIGH", source: "nvd" }],
    summary: "Demo OpenSSH issue fixed in 8.3.",
    remediation: "Upgrade OpenSSH to 8.3+ or apply distro update.",
  },
  {
    // Apache httpd path traversal, exact version, known-exploited.
    cveId: "CVE-2021-41773",
    ranges: [{ vendor: "apache", product: "http_server", exactVersion: "2.4.49" }],
    cvss: [
      { version: "3.1", baseScore: 9.8, severity: "CRITICAL", source: "cna:apache" },
      { version: "3.1", baseScore: 7.5, severity: "HIGH", source: "nvd" },
    ],
    kev: { dateAdded: "2021-11-03", ransomware: false },
    epss: { score: 0.94, percentile: 0.99 },
    exploitMaturity: "weaponized",
    summary: "Path traversal and file disclosure in Apache HTTP Server 2.4.49.",
    remediation: "Upgrade to 2.4.51+.",
  },
  {
    // nginx bounded range, medium severity, no exploit intel.
    cveId: "CVE-2021-DEMO-NGINX",
    ranges: [{ vendor: "nginx", product: "nginx", introduced: "1.20.0", fixed: "1.20.2" }],
    cvss: [{ version: "3.1", baseScore: 5.3, severity: "MEDIUM", source: "nvd" }],
    summary: "Demo nginx issue fixed in 1.20.2.",
  },
];

export function makeSource(vulns: VulnRecord[] = VULNS): VulnSource {
  const index = new Map<string, VulnRecord[]>();
  for (const v of vulns) {
    for (const r of v.ranges) {
      const key = normalizeProduct(r.product);
      const list = index.get(key) ?? [];
      if (!list.includes(v)) list.push(v);
      index.set(key, list);
    }
  }
  return {
    byProduct: (np) => index.get(np) ?? [],
  };
}

// --- sample observations ----------------------------------------------------

export const OBS_SSH_UPSTREAM: ServiceObservation = {
  host: "192.168.1.20",
  port: 22,
  proto: "tcp",
  serviceName: "ssh",
  product: { vendor: "openbsd", product: "openssh", version: "8.2p1" },
  evidence: { banner: "SSH-2.0-OpenSSH_8.2p1" },
  exposure: { reachable: true },
};

export const OBS_SSH_FOCAL_PATCHED: ServiceObservation = {
  host: "192.168.1.21",
  port: 22,
  proto: "tcp",
  serviceName: "ssh",
  product: {
    vendor: "openbsd",
    product: "openssh",
    version: "8.2p1",
    distro: "ubuntu",
    distroRelease: "focal",
    distroPackage: "openssh",
    distroPkgVersion: "1:8.2p1-4ubuntu0.11",
  },
  evidence: { banner: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11" },
  exposure: { reachable: true },
};

export const OBS_SSH_FOCAL_VULN: ServiceObservation = {
  host: "192.168.1.22",
  port: 22,
  proto: "tcp",
  serviceName: "ssh",
  product: {
    vendor: "openbsd",
    product: "openssh",
    version: "8.2p1",
    distro: "ubuntu",
    distroRelease: "focal",
    distroPackage: "openssh",
    distroPkgVersion: "1:8.2p1-4ubuntu0.2",
  },
  evidence: { banner: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2" },
  exposure: { reachable: true },
};

export const OBS_APACHE_VULN: ServiceObservation = {
  host: "192.168.1.42",
  port: 80,
  proto: "tcp",
  serviceName: "http",
  product: { product: "Apache", version: "2.4.49" },
  evidence: { httpServer: "Apache/2.4.49 (Unix)" },
  exposure: { reachable: true, authless: true },
};

export const OBS_NGINX_PATCHED: ServiceObservation = {
  host: "192.168.1.30",
  port: 443,
  proto: "tcp",
  serviceName: "https",
  product: { product: "nginx", version: "1.20.5" },
  exposure: { reachable: true },
};

export const OBS_NGINX_VULN: ServiceObservation = {
  host: "192.168.1.31",
  port: 443,
  proto: "tcp",
  serviceName: "https",
  product: { product: "nginx", version: "1.20.1" },
  exposure: { reachable: true },
};
