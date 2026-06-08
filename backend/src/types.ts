// watchDog API contract + engine types.
//
// This file is the frozen /correlate schema (M0). The phone submits
// ServiceObservation[]; the backend returns Finding[]. The backend never
// connects to a target — every field here is evidence the phone already
// collected on the LAN.

// ---------------------------------------------------------------------------
// Product identity (what the phone extracted from a service's fingerprint)
// ---------------------------------------------------------------------------

export interface ProductIdentity {
  vendor?: string; // e.g. "openbsd"
  product: string; // e.g. "openssh" (normalized lowercase)
  version?: string; // upstream version, e.g. "8.2p1"
  cpe?: string; // if the phone/backend already resolved one

  // Distro context parsed out of the banner. This is what kills backport
  // false-positives: "OpenSSH_8.2p1 Ubuntu-4ubuntu0.11" looks vulnerable to
  // anything fixed after upstream 8.2, but the distro package may be patched.
  distro?: string; // "ubuntu" | "debian" | "redhat" | ...
  distroRelease?: string; // "focal" | "12" | ...
  distroPackage?: string; // dpkg/rpm package name if it differs from product
  distroPkgVersion?: string; // e.g. "1:8.2p1-4ubuntu0.11"
}

export interface ServiceEvidence {
  banner?: string;
  httpServer?: string;
  httpPoweredBy?: string;
  tlsSubject?: string;
  tlsIssuer?: string;
  tlsNotAfter?: string;
}

export interface Exposure {
  reachable: boolean; // the phone got a response
  authless?: boolean; // service answered without credentials
}

export interface ServiceObservation {
  host: string; // IP on the LAN
  port: number;
  proto: "tcp" | "udp";
  serviceName?: string; // "ssh", "http", ...
  product?: ProductIdentity;
  evidence?: ServiceEvidence;
  exposure?: Exposure;
}

// ---------------------------------------------------------------------------
// Vulnerability intelligence records (what the DB stores, engine consumes)
// ---------------------------------------------------------------------------

export type Severity = "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type CvssVersion = "4.0" | "3.1" | "3.0" | "2.0";

export interface CvssScore {
  version: CvssVersion;
  baseScore: number;
  severity: Severity;
  vector?: string;
  source: string; // "cna:redhat" | "nvd" | "vulncheck" ...
}

// A single affected-version constraint for a product. Mirrors NVD CPE match
// (versionStart*/versionEnd*) and CNA affected[] ranges.
export interface VersionRange {
  vendor?: string;
  product: string;
  introduced?: string; // inclusive lower bound (versionStartIncluding)
  introducedExcluding?: string; // exclusive lower bound (versionStartExcluding)
  fixed?: string; // exclusive upper bound (versionEndExcluding / "fixed in")
  lastAffected?: string; // inclusive upper bound (versionEndIncluding)
  exactVersion?: string; // a single vulnerable version
  cpe?: string;
}

// Distro fixed-version data (Debian/Ubuntu/RHEL). The suppression ground-truth.
export type DistroStatus = "fixed" | "affected" | "not-affected" | "unknown";
export interface DistroFix {
  distro: string;
  release?: string;
  pkg: string;
  status: DistroStatus;
  fixedVersion?: string; // package revision that carries the fix
}

// KEV > weaponized (metasploit/nuclei) > poc (github/edb) > none
export type ExploitMaturity = "kev" | "weaponized" | "poc" | "none";

export interface VulnRecord {
  cveId: string;
  aliases?: string[]; // GHSA / DSA / USN / RHSA ...
  ranges: VersionRange[];
  distroFixes?: DistroFix[];
  cvss?: CvssScore[]; // multiple, kept with provenance; never averaged
  kev?: { dateAdded: string; ransomware?: boolean };
  epss?: { score: number; percentile: number };
  exploitMaturity?: ExploitMaturity;
  cwe?: string[];
  summary?: string;
  remediation?: string;
}

// ---------------------------------------------------------------------------
// Findings (engine output)
// ---------------------------------------------------------------------------

// The four states from the plan. The pure correlation engine can reach up to
// VERIFIED (via distro confirmation). VERIFIED-by-active-check and EXPLOITABLE
// are set later by the on-device verification runtime.
export type FindingState =
  | "DETECTED" // product identified, version unknown/unassessable
  | "LIKELY_VULNERABLE" // version-in-range match, unconfirmed
  | "VERIFIED" // distro-confirmed (or active-check-confirmed elsewhere)
  | "EXPLOITABLE"; // verified + successful authorized PoC (set by verifier)

// How specific the version match was — drives confidence.
export type MatchBasis =
  | "exact" // matched a single vulnerable version
  | "bounded-range" // matched with both a lower and upper bound
  | "upstream-range" // matched an open-ended range
  | "product-only"; // product matched but no version to assess

export interface Finding {
  host: string;
  port: number;
  product: ProductIdentity;
  cveId: string;
  state: FindingState;
  matchBasis: MatchBasis;
  confidence: number; // 0-100
  severity: Severity;
  cvssScore?: number;
  cvssVersion?: CvssVersion;
  knownExploited: boolean;
  epss?: number;
  exploitMaturity: ExploitMaturity;
  priority: number; // 0-100 ranking score
  why: string[]; // human-readable reasons
  remediation?: string;
  suppressed: boolean; // distro says this package revision is patched
  suppressionReason?: string;
}

export interface CorrelateRequest {
  observations: ServiceObservation[];
}

export interface CorrelateResponse {
  findings: Finding[];
  suppressed: Finding[]; // patched-by-distro, surfaced separately for transparency
  generatedAt: string;
  engineVersion: string;
}
