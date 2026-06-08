// Parse the EPSS daily CSV. Rows are: cve,epss,percentile. The file begins
// with a "#model_version..." comment line and a header row, both skipped.

export interface EpssEntry {
  score: number;
  percentile: number;
}

export function parseEpssCsv(text: string): Map<string, EpssEntry> {
  const map = new Map<string, EpssEntry>();
  for (const line of text.split(/\r?\n/)) {
    const row = line.trim();
    if (!row || row.startsWith("#")) continue;
    if (row.startsWith("cve,")) continue; // header
    const [cve, epss, percentile] = row.split(",");
    if (!cve || !cve.startsWith("CVE-")) continue;
    const score = Number(epss);
    const pct = Number(percentile);
    if (!Number.isFinite(score)) continue;
    map.set(cve, { score, percentile: Number.isFinite(pct) ? pct : 0 });
  }
  return map;
}
