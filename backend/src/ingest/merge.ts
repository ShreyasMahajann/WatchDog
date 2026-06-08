// Merge normalized sources into the final VulnRecord set keyed by CVE ID.
//
// CVE records provide the authoritative ranges + CVSS; KEV and EPSS are
// prioritization overlays attached by CVE ID (the canonical join key). Distro
// fixes are attached separately by the distro ingesters (not wired here yet).

import type { VulnRecord } from "../types.ts";
import type { KevEntry } from "./kev.ts";
import type { EpssEntry } from "./epss.ts";

export interface MergeInputs {
  cveRecords: VulnRecord[];
  kev?: Map<string, KevEntry>;
  epss?: Map<string, EpssEntry>;
}

export function buildVulnRecords(inputs: MergeInputs): VulnRecord[] {
  const byId = new Map<string, VulnRecord>();

  for (const rec of inputs.cveRecords) {
    const existing = byId.get(rec.cveId);
    if (existing) {
      // De-dup: same CVE seen twice — union the ranges, keep first CVSS.
      existing.ranges.push(...rec.ranges);
      if (!existing.cvss && rec.cvss) existing.cvss = rec.cvss;
    } else {
      byId.set(rec.cveId, { ...rec, ranges: [...rec.ranges] });
    }
  }

  if (inputs.kev) {
    for (const [cveId, entry] of inputs.kev) {
      const rec = byId.get(cveId);
      if (rec) {
        rec.kev = { dateAdded: entry.dateAdded, ransomware: entry.ransomware };
        if (!rec.exploitMaturity || rec.exploitMaturity === "none") {
          rec.exploitMaturity = "kev";
        }
      }
    }
  }

  if (inputs.epss) {
    for (const [cveId, entry] of inputs.epss) {
      const rec = byId.get(cveId);
      if (rec) rec.epss = { score: entry.score, percentile: entry.percentile };
    }
  }

  return [...byId.values()];
}
