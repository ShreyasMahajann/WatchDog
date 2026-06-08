// Matching: does an observed product fall within a vuln's affected ranges,
// and does distro data override that verdict?

import { compareDebian, compareUpstream } from "./version.ts";
import type {
  DistroFix,
  MatchBasis,
  ProductIdentity,
  VersionRange,
} from "./types.ts";

// Small product-name alias map. Banners and CVE data don't always agree on the
// product token; normalize before comparing. Extend as fixtures grow.
const PRODUCT_ALIASES: Record<string, string> = {
  "openssh_server": "openssh",
  "openssh-server": "openssh",
  httpd: "http_server", // Apache httpd == apache http_server (CPE)
  "apache": "http_server",
  "apache2": "http_server",
  nginx: "nginx",
};

export function normalizeProduct(name: string | undefined): string {
  if (!name) return "";
  const key = name.trim().toLowerCase().replace(/\s+/g, "_");
  return PRODUCT_ALIASES[key] ?? key;
}

export function productMatches(
  obs: ProductIdentity,
  range: VersionRange,
): boolean {
  const op = normalizeProduct(obs.product);
  const rp = normalizeProduct(range.product);
  if (op === "" || rp === "") return false;
  if (op !== rp) return false;
  // If both carry a vendor, they must agree; missing vendor on either side is
  // tolerated (banners often omit it).
  if (obs.vendor && range.vendor) {
    if (obs.vendor.trim().toLowerCase() !== range.vendor.trim().toLowerCase()) {
      return false;
    }
  }
  return true;
}

// Is `version` within this affected range? Uses the upstream comparator.
export function versionInRange(version: string, range: VersionRange): boolean {
  const cmp = compareUpstream;

  if (range.exactVersion !== undefined) {
    return cmp(version, range.exactVersion) === 0;
  }

  // Lower bound
  if (range.introduced !== undefined && cmp(version, range.introduced) < 0) {
    return false;
  }
  if (
    range.introducedExcluding !== undefined &&
    cmp(version, range.introducedExcluding) <= 0
  ) {
    return false;
  }

  // Upper bound
  if (range.fixed !== undefined && cmp(version, range.fixed) >= 0) {
    return false;
  }
  if (
    range.lastAffected !== undefined &&
    cmp(version, range.lastAffected) > 0
  ) {
    return false;
  }

  // With no bounds at all and no exact version, a bare product CPE means "all
  // versions affected" — treat as in-range.
  return true;
}

export function classifyBasis(
  obs: ProductIdentity,
  range: VersionRange,
): MatchBasis {
  if (!obs.version) return "product-only";
  if (range.exactVersion !== undefined) return "exact";
  const hasLower =
    range.introduced !== undefined || range.introducedExcluding !== undefined;
  const hasUpper =
    range.fixed !== undefined || range.lastAffected !== undefined;
  if (hasLower && hasUpper) return "bounded-range";
  if (hasLower || hasUpper) return "upstream-range";
  return "product-only";
}

export type DistroVerdict =
  | { kind: "patched"; reason: string } // suppress the finding
  | { kind: "confirmed"; reason: string } // distro says still vulnerable -> VERIFIED
  | { kind: "not-affected"; reason: string } // suppress
  | { kind: "none" }; // no applicable distro data

// The backport ground-truth. If the observation carries a distro package
// version, distro fixed-version data OVERRIDES the upstream range verdict.
export function distroVerdict(
  obs: ProductIdentity,
  fixes: DistroFix[] | undefined,
): DistroVerdict {
  if (!fixes || !obs.distro || !obs.distroPkgVersion) return { kind: "none" };
  const distro = obs.distro.trim().toLowerCase();
  const release = obs.distroRelease?.trim().toLowerCase();

  const applicable = fixes.filter((f) => {
    if (f.distro.trim().toLowerCase() !== distro) return false;
    if (release && f.release && f.release.trim().toLowerCase() !== release) {
      return false;
    }
    return true;
  });
  if (applicable.length === 0) return { kind: "none" };

  for (const f of applicable) {
    if (f.status === "not-affected") {
      return {
        kind: "not-affected",
        reason: `${obs.distro} marks ${f.pkg} not affected`,
      };
    }
    if (f.status === "fixed" && f.fixedVersion) {
      const c = compareDebian(obs.distroPkgVersion, f.fixedVersion);
      if (c >= 0) {
        return {
          kind: "patched",
          reason: `${obs.distro} package ${obs.distroPkgVersion} >= fixed ${f.fixedVersion} (backported)`,
        };
      }
      return {
        kind: "confirmed",
        reason: `${obs.distro} package ${obs.distroPkgVersion} < fixed ${f.fixedVersion}`,
      };
    }
    if (f.status === "affected") {
      return {
        kind: "confirmed",
        reason: `${obs.distro} marks ${f.pkg} affected (no fix available)`,
      };
    }
  }
  return { kind: "none" };
}
