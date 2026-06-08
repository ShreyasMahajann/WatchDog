// Parse a CVE Record Format 5.x JSON object into our VulnRecord shape.
//
// CVE-List-first: the CNA container's affected[] version data (and CISA
// Vulnrichment in the adp[] containers) is our authoritative source of affected
// ranges, because NVD no longer enriches most CVEs. We prefer CPE-derived
// vendor/product when a CPE is present (more reliable than free-text names).

import type {
  CvssScore,
  CvssVersion,
  Severity,
  VersionRange,
  VulnRecord,
} from "../types.ts";

// Minimal structural typing of the bits of a CVE 5.x record we consume.
interface RawCve {
  cveMetadata?: { cveId?: string };
  containers?: {
    cna?: RawContainer;
    adp?: RawContainer[];
  };
}
interface RawContainer {
  title?: string;
  affected?: RawAffected[];
  metrics?: RawMetric[];
  descriptions?: { lang?: string; value?: string }[];
  providerMetadata?: { shortName?: string };
}
interface RawAffected {
  vendor?: string;
  product?: string;
  cpes?: string[];
  defaultStatus?: string;
  versions?: RawVersion[];
}
interface RawVersion {
  version?: string;
  status?: string; // "affected" | "unaffected"
  lessThan?: string;
  lessThanOrEqual?: string;
  versionType?: string;
}
type RawMetric = Record<string, RawCvss | undefined>;
interface RawCvss {
  baseScore?: number;
  baseSeverity?: string;
  vectorString?: string;
}

function parseCpe(cpe: string): { vendor?: string; product?: string } {
  // cpe:2.3:a:vendor:product:version:...
  const parts = cpe.split(":");
  if (parts.length < 5) return {};
  return { vendor: parts[3], product: parts[4] };
}

function isWildcard(v: string | undefined): boolean {
  return v === undefined || v === "*" || v === "0" || v === "-";
}

function rangesFromAffected(aff: RawAffected): VersionRange[] {
  let vendor = aff.vendor;
  let product = aff.product;
  const cpe = aff.cpes?.[0];
  if (cpe) {
    const parsed = parseCpe(cpe);
    if (parsed.product) {
      vendor = parsed.vendor;
      product = parsed.product;
    }
  }
  if (!product) return [];

  const out: VersionRange[] = [];
  const versions = aff.versions ?? [];

  // No explicit versions but the product is flagged affected by default => all
  // versions affected (a bare product CPE).
  if (versions.length === 0 && aff.defaultStatus === "affected") {
    out.push({ vendor, product, cpe });
    return out;
  }

  for (const v of versions) {
    if (v.status && v.status !== "affected") continue;
    const range: VersionRange = { vendor, product, cpe };
    const lower = isWildcard(v.version) ? undefined : v.version;
    if (v.lessThan !== undefined) {
      if (lower) range.introduced = lower;
      range.fixed = v.lessThan;
    } else if (v.lessThanOrEqual !== undefined) {
      if (lower) range.introduced = lower;
      range.lastAffected = v.lessThanOrEqual;
    } else if (lower) {
      range.exactVersion = lower;
    }
    // else: affected with a wildcard version and no bound => all versions.
    out.push(range);
  }
  return out;
}

const CVSS_KEYS: { key: string; version: CvssVersion }[] = [
  { key: "cvssV4_0", version: "4.0" },
  { key: "cvssV3_1", version: "3.1" },
  { key: "cvssV3_0", version: "3.0" },
  { key: "cvssV2_0", version: "2.0" },
];

function normSeverity(s: string | undefined, score: number | undefined): Severity {
  const up = s?.toUpperCase();
  if (up === "CRITICAL" || up === "HIGH" || up === "MEDIUM" || up === "LOW" || up === "NONE") {
    return up;
  }
  // Derive from score if severity string is missing (common for CVSS v2).
  if (score === undefined) return "NONE";
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  if (score > 0) return "LOW";
  return "NONE";
}

function cvssFromMetrics(metrics: RawMetric[] | undefined, source: string): CvssScore[] {
  const out: CvssScore[] = [];
  for (const m of metrics ?? []) {
    for (const { key, version } of CVSS_KEYS) {
      const c = m[key];
      if (c && typeof c.baseScore === "number") {
        out.push({
          version,
          baseScore: c.baseScore,
          severity: normSeverity(c.baseSeverity, c.baseScore),
          vector: c.vectorString,
          source,
        });
      }
    }
  }
  return out;
}

export function parseCveRecord(raw: unknown): VulnRecord | null {
  const cve = raw as RawCve;
  const cveId = cve.cveMetadata?.cveId;
  if (!cveId) return null;

  const cna = cve.containers?.cna;
  const adps = cve.containers?.adp ?? [];

  const ranges: VersionRange[] = [];
  for (const aff of cna?.affected ?? []) ranges.push(...rangesFromAffected(aff));
  for (const adp of adps) {
    for (const aff of adp.affected ?? []) ranges.push(...rangesFromAffected(aff));
  }

  const cvss: CvssScore[] = [
    ...cvssFromMetrics(cna?.metrics, `cna:${cna?.providerMetadata?.shortName ?? "cna"}`),
    ...adps.flatMap((a) => cvssFromMetrics(a.metrics, "adp:cisa")),
  ];

  const summary = cna?.descriptions?.find((d) => d.lang?.startsWith("en"))?.value;

  return {
    cveId,
    ranges,
    cvss: cvss.length ? cvss : undefined,
    summary,
  };
}
