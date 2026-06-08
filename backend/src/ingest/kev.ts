// Parse the CISA Known Exploited Vulnerabilities catalog (CC0 JSON).
// Gives us the highest-precision prioritization bit: known-exploited.

export interface KevEntry {
  dateAdded: string;
  ransomware: boolean;
}

interface RawKev {
  vulnerabilities?: {
    cveID?: string;
    dateAdded?: string;
    knownRansomwareCampaignUse?: string; // "Known" | "Unknown"
  }[];
}

export function parseKev(raw: unknown): Map<string, KevEntry> {
  const doc = raw as RawKev;
  const map = new Map<string, KevEntry>();
  for (const v of doc.vulnerabilities ?? []) {
    if (!v.cveID) continue;
    map.set(v.cveID, {
      dateAdded: v.dateAdded ?? "",
      ransomware: v.knownRansomwareCampaignUse === "Known",
    });
  }
  return map;
}
