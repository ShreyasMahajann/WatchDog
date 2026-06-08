// Correlation orchestration: observations -> findings.
//
// The engine is pure: given observations and a VulnSource (a DB query in prod,
// an in-memory map in tests), it produces ranked findings. It never performs
// I/O against a target. Max state reachable here is VERIFIED (via distro
// confirmation); EXPLOITABLE is set later by the on-device verification runtime.

import {
  classifyBasis,
  distroVerdict,
  normalizeProduct,
  productMatches,
  versionInRange,
} from "./match.ts";
import type {
  CorrelateRequest,
  CorrelateResponse,
  CvssScore,
  CvssVersion,
  ExploitMaturity,
  Finding,
  FindingState,
  MatchBasis,
  ProductIdentity,
  ServiceObservation,
  Severity,
  VersionRange,
  VulnRecord,
} from "./types.ts";

export const ENGINE_VERSION = "0.1.0";

export interface VulnSource {
  // Candidate vulns for a normalized product name (e.g. "openssh").
  byProduct(normalizedProduct: string): VulnRecord[];
}

export function correlate(
  req: CorrelateRequest,
  source: VulnSource,
  now: string = new Date().toISOString(),
): CorrelateResponse {
  const findings: Finding[] = [];
  const suppressed: Finding[] = [];

  for (const obs of req.observations) {
    if (!obs.product) continue;
    const np = normalizeProduct(obs.product.product);
    if (!np) continue;

    for (const vuln of source.byProduct(np)) {
      const f = evaluate(obs, obs.product, vuln);
      if (!f) continue;
      if (f.suppressed) suppressed.push(f);
      else findings.push(f);
    }
  }

  findings.sort(byPriority);
  suppressed.sort(byPriority);
  return { findings, suppressed, generatedAt: now, engineVersion: ENGINE_VERSION };
}

function evaluate(
  obs: ServiceObservation,
  product: ProductIdentity,
  vuln: VulnRecord,
): Finding | null {
  // Find the most specific matching range for this product.
  const candidateRanges = vuln.ranges.filter((r) => productMatches(product, r));
  const firstRange = candidateRanges[0];
  if (firstRange === undefined) return null;

  let chosen: VersionRange = firstRange;
  let basis: MatchBasis = "product-only";
  const version = product.version;

  if (version) {
    const inRange = candidateRanges.filter((r) => versionInRange(version, r));
    if (inRange.length === 0) return null; // version known and not affected
    // Prefer the most specific basis.
    chosen = mostSpecific(product, inRange);
    basis = classifyBasis(product, chosen);
  } else {
    // Product matches a known-vulnerable product but we couldn't read a
    // version. Informational only — DETECTED, never asserted vulnerable.
    basis = "product-only";
  }

  const why: string[] = [];
  const verdict = distroVerdict(product, vuln.distroFixes);

  let state: FindingState;
  let suppressedFlag = false;
  let suppressionReason: string | undefined;

  if (basis === "product-only") {
    state = "DETECTED";
    why.push(`${product.product} present; version not determined`);
  } else {
    state = "LIKELY_VULNERABLE";
    why.push(rangeReason(product.version!, chosen));
  }

  if (verdict.kind === "patched" || verdict.kind === "not-affected") {
    suppressedFlag = true;
    suppressionReason = verdict.reason;
    why.push(verdict.reason);
  } else if (verdict.kind === "confirmed") {
    state = "VERIFIED";
    why.push(verdict.reason);
  }

  const cvss = pickCvss(vuln.cvss);
  const severity: Severity = cvss?.severity ?? "NONE";
  const knownExploited = !!vuln.kev;
  const maturity: ExploitMaturity = knownExploited
    ? "kev"
    : vuln.exploitMaturity ?? "none";
  if (knownExploited) {
    why.push(
      vuln.kev?.ransomware
        ? "Known exploited (CISA KEV) — linked to ransomware"
        : "Known exploited (CISA KEV)",
    );
  }
  if (vuln.epss && vuln.epss.score >= 0.1) {
    why.push(`EPSS ${(vuln.epss.score * 100).toFixed(0)}% (exploitation likely)`);
  }
  if (cvss) why.push(`CVSS ${cvss.version} ${cvss.baseScore} (${cvss.severity})`);

  const confidence = scoreConfidence(basis, state, suppressedFlag, !!obs.evidence?.banner);
  const priority = scorePriority(
    severity,
    maturity,
    vuln.epss?.score,
    state,
    basis,
    obs,
    suppressedFlag,
  );

  return {
    host: obs.host,
    port: obs.port,
    product,
    cveId: vuln.cveId,
    state,
    matchBasis: basis,
    confidence,
    severity,
    cvssScore: cvss?.baseScore,
    cvssVersion: cvss?.version,
    knownExploited,
    epss: vuln.epss?.score,
    exploitMaturity: maturity,
    priority,
    why,
    remediation: vuln.remediation,
    suppressed: suppressedFlag,
    suppressionReason,
  };
}

function mostSpecific(
  product: ProductIdentity,
  ranges: VersionRange[],
): VersionRange {
  const order: Record<MatchBasis, number> = {
    exact: 3,
    "bounded-range": 2,
    "upstream-range": 1,
    "product-only": 0,
  };
  let best = ranges[0]!;
  let bestScore = order[classifyBasis(product, best)];
  for (const r of ranges.slice(1)) {
    const s = order[classifyBasis(product, r)];
    if (s > bestScore) {
      best = r;
      bestScore = s;
    }
  }
  return best;
}

function rangeReason(version: string, r: VersionRange): string {
  if (r.exactVersion !== undefined) {
    return `Version ${version} matches affected ${r.exactVersion}`;
  }
  const lo = r.introduced ?? r.introducedExcluding;
  const hi = r.fixed ?? r.lastAffected;
  const loStr = lo ? `>= ${lo}` : "any";
  const hiStr = r.fixed
    ? `< ${r.fixed}`
    : r.lastAffected
      ? `<= ${r.lastAffected}`
      : "up";
  return `Version ${version} within affected range (${loStr}, ${hiStr})`;
}

const CVSS_VERSION_RANK: Record<CvssVersion, number> = {
  "4.0": 4,
  "3.1": 3,
  "3.0": 2,
  "2.0": 1,
};

// Provenance order: prefer newer CVSS version, then CNA-provided over NVD.
// Never average — pick one and keep it.
function pickCvss(scores: CvssScore[] | undefined): CvssScore | undefined {
  if (!scores || scores.length === 0) return undefined;
  return [...scores].sort((a, b) => {
    const vr = CVSS_VERSION_RANK[b.version] - CVSS_VERSION_RANK[a.version];
    if (vr !== 0) return vr;
    const aCna = a.source.startsWith("cna") ? 1 : 0;
    const bCna = b.source.startsWith("cna") ? 1 : 0;
    return bCna - aCna;
  })[0];
}

function scoreConfidence(
  basis: MatchBasis,
  state: FindingState,
  suppressed: boolean,
  hasBanner: boolean,
): number {
  if (state === "VERIFIED") return 95;
  if (suppressed) return 20; // low confidence it's actually vulnerable
  const base: Record<MatchBasis, number> = {
    exact: 88,
    "bounded-range": 76,
    "upstream-range": 58,
    "product-only": 28,
  };
  let c = base[basis];
  if (hasBanner) c = Math.min(99, c + 4);
  return c;
}

const SEVERITY_WEIGHT: Record<Severity, number> = {
  CRITICAL: 1.0,
  HIGH: 0.8,
  MEDIUM: 0.55,
  LOW: 0.3,
  NONE: 0.1,
};
const MATURITY_WEIGHT: Record<ExploitMaturity, number> = {
  kev: 1.0,
  weaponized: 0.8,
  poc: 0.55,
  none: 0.3,
};
const STATE_WEIGHT: Record<FindingState, number> = {
  EXPLOITABLE: 1.0,
  VERIFIED: 1.0,
  LIKELY_VULNERABLE: 0.7,
  DETECTED: 0.3,
};
const BASIS_WEIGHT: Record<MatchBasis, number> = {
  exact: 1.0,
  "bounded-range": 0.9,
  "upstream-range": 0.7,
  "product-only": 0.5,
};

function scorePriority(
  severity: Severity,
  maturity: ExploitMaturity,
  epss: number | undefined,
  state: FindingState,
  basis: MatchBasis,
  obs: ServiceObservation,
  suppressed: boolean,
): number {
  if (suppressed) return 0;
  const sev = SEVERITY_WEIGHT[severity];
  const exploit = Math.max(MATURITY_WEIGHT[maturity], epss ?? 0);
  const stateW = STATE_WEIGHT[state];
  const basisW = BASIS_WEIGHT[basis];
  const exposureW = obs.exposure?.authless
    ? 1.0
    : obs.exposure?.reachable
      ? 0.85
      : 0.7;
  const raw = sev * (0.4 + 0.6 * exploit) * stateW * basisW * exposureW;
  return Math.round(raw * 100);
}

function byPriority(a: Finding, b: Finding): number {
  if (b.priority !== a.priority) return b.priority - a.priority;
  const sev = SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity];
  if (sev !== 0) return sev;
  return a.cveId.localeCompare(b.cveId);
}
