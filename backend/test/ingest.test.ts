import { test } from "node:test";
import assert from "node:assert/strict";
import { parseCveRecord } from "../src/ingest/cve.ts";
import { parseKev } from "../src/ingest/kev.ts";
import { parseEpssCsv } from "../src/ingest/epss.ts";
import { buildVulnRecords } from "../src/ingest/merge.ts";
import { correlate, type VulnSource } from "../src/correlate.ts";
import { normalizeProduct } from "../src/match.ts";
import type { VulnRecord } from "../src/types.ts";
import { OBS_APACHE_VULN } from "./fixtures.ts";

// A trimmed but structurally-real CVE 5.x record.
const CVE_41773 = {
  cveMetadata: { cveId: "CVE-2021-41773", state: "PUBLISHED" },
  containers: {
    cna: {
      providerMetadata: { shortName: "apache" },
      affected: [
        {
          vendor: "Apache Software Foundation",
          product: "Apache HTTP Server",
          cpes: ["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"],
          versions: [{ version: "2.4.49", status: "affected" }],
        },
      ],
      metrics: [
        { cvssV3_1: { baseScore: 7.5, baseSeverity: "HIGH", vectorString: "CVSS:3.1/AV:N" } },
      ],
      descriptions: [{ lang: "en", value: "Path traversal in Apache HTTP Server 2.4.49." }],
    },
    adp: [
      {
        metrics: [{ cvssV3_1: { baseScore: 9.8, baseSeverity: "CRITICAL" } }],
      },
    ],
  },
};

const KEV_JSON = {
  vulnerabilities: [
    { cveID: "CVE-2021-41773", dateAdded: "2021-11-03", knownRansomwareCampaignUse: "Unknown" },
  ],
};

const EPSS_CSV = [
  "#model_version:v2025.03.14,score_date:2026-08-10T00:00:00Z",
  "cve,epss,percentile",
  "CVE-2021-41773,0.94237,0.99911",
  "CVE-0000-0000,0.00042,0.10000",
].join("\n");

function sourceFrom(records: VulnRecord[]): VulnSource {
  const index = new Map<string, VulnRecord[]>();
  for (const v of records) {
    for (const r of v.ranges) {
      const key = normalizeProduct(r.product);
      const list = index.get(key) ?? [];
      list.push(v);
      index.set(key, list);
    }
  }
  return { byProduct: (np) => index.get(np) ?? [] };
}

test("parseCveRecord: CPE-derived product + exact version range", () => {
  const rec = parseCveRecord(CVE_41773);
  assert.ok(rec);
  assert.equal(rec.cveId, "CVE-2021-41773");
  assert.equal(rec.ranges.length, 1);
  assert.equal(rec.ranges[0]!.product, "http_server"); // from CPE, not free-text
  assert.equal(rec.ranges[0]!.vendor, "apache");
  assert.equal(rec.ranges[0]!.exactVersion, "2.4.49");
  // Both CNA and ADP CVSS captured, with provenance.
  assert.equal(rec.cvss!.length, 2);
  assert.ok(rec.cvss!.some((c) => c.source.startsWith("cna")));
  assert.ok(rec.cvss!.some((c) => c.source.startsWith("adp")));
});

test("parseKev + parseEpss", () => {
  const kev = parseKev(KEV_JSON);
  assert.equal(kev.get("CVE-2021-41773")?.ransomware, false);
  const epss = parseEpssCsv(EPSS_CSV);
  assert.equal(epss.get("CVE-2021-41773")?.score, 0.94237);
  assert.equal(epss.size, 2); // comment + header skipped
});

test("end-to-end: ingest -> merge -> correlate surfaces the KEV finding", () => {
  const records = buildVulnRecords({
    cveRecords: [parseCveRecord(CVE_41773)!],
    kev: parseKev(KEV_JSON),
    epss: parseEpssCsv(EPSS_CSV),
  });
  assert.equal(records.length, 1);
  assert.ok(records[0]!.kev, "KEV overlay attached");
  assert.equal(records[0]!.epss?.score, 0.94237);

  const { findings } = correlate({ observations: [OBS_APACHE_VULN] }, sourceFrom(records));
  assert.equal(findings.length, 1);
  const f = findings[0]!;
  assert.equal(f.cveId, "CVE-2021-41773");
  assert.equal(f.matchBasis, "exact");
  assert.equal(f.knownExploited, true);
  assert.equal(f.exploitMaturity, "kev");
  // CVSS provenance: CNA (7.5/HIGH) wins over ADP enrichment per our rule.
  assert.equal(f.severity, "HIGH");
  assert.equal(f.cvssScore, 7.5);
  assert.ok(f.epss && f.epss > 0.9);
});
