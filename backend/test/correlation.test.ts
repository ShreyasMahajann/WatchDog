import { test } from "node:test";
import assert from "node:assert/strict";
import { correlate } from "../src/correlate.ts";
import type { Finding } from "../src/types.ts";
import {
  makeSource,
  OBS_APACHE_VULN,
  OBS_NGINX_PATCHED,
  OBS_NGINX_VULN,
  OBS_SSH_FOCAL_PATCHED,
  OBS_SSH_FOCAL_VULN,
  OBS_SSH_UPSTREAM,
} from "./fixtures.ts";

const source = makeSource();
const NOW = "2026-08-10T00:00:00.000Z";

function run(...obs: (typeof OBS_SSH_UPSTREAM)[]) {
  return correlate({ observations: obs }, source, NOW);
}

function only(findings: Finding[], cveId: string): Finding {
  const m = findings.filter((f) => f.cveId === cveId);
  assert.equal(m.length, 1, `expected exactly one ${cveId}, got ${m.length}`);
  return m[0]!;
}

test("upstream version in range -> LIKELY_VULNERABLE, bounded basis", () => {
  const { findings, suppressed } = run(OBS_SSH_UPSTREAM);
  assert.equal(suppressed.length, 0);
  const f = only(findings, "CVE-2020-DEMO-SSH");
  assert.equal(f.state, "LIKELY_VULNERABLE");
  assert.equal(f.matchBasis, "bounded-range");
  assert.equal(f.suppressed, false);
  assert.equal(f.severity, "HIGH");
});

test("distro backport patched -> suppressed, not a live finding", () => {
  const { findings, suppressed } = run(OBS_SSH_FOCAL_PATCHED);
  assert.equal(findings.length, 0, "patched box should surface no live findings");
  const f = only(suppressed, "CVE-2020-DEMO-SSH");
  assert.equal(f.suppressed, true);
  assert.equal(f.priority, 0);
  assert.match(f.suppressionReason ?? "", /backported|>=/i);
});

test("distro package below fixed revision -> VERIFIED", () => {
  const { findings } = run(OBS_SSH_FOCAL_VULN);
  const f = only(findings, "CVE-2020-DEMO-SSH");
  assert.equal(f.state, "VERIFIED");
  assert.equal(f.suppressed, false);
  assert.ok(f.confidence >= 90, `confidence ${f.confidence} should be high when distro-confirmed`);
});

test("known-exploited exact match ranks highest and flags KEV", () => {
  const { findings } = run(OBS_APACHE_VULN);
  const f = only(findings, "CVE-2021-41773");
  assert.equal(f.knownExploited, true);
  assert.equal(f.exploitMaturity, "kev");
  assert.equal(f.matchBasis, "exact");
  // CVSS provenance: CNA CRITICAL should win over NVD HIGH.
  assert.equal(f.severity, "CRITICAL");
  assert.equal(f.cvssScore, 9.8);
  assert.ok(f.why.some((w) => /KEV/.test(w)));
});

test("version above fixed -> no finding (false-positive guard)", () => {
  const { findings, suppressed } = run(OBS_NGINX_PATCHED);
  assert.equal(findings.length, 0);
  assert.equal(suppressed.length, 0);
});

test("nginx in bounded range -> medium LIKELY", () => {
  const { findings } = run(OBS_NGINX_VULN);
  const f = only(findings, "CVE-2021-DEMO-NGINX");
  assert.equal(f.state, "LIKELY_VULNERABLE");
  assert.equal(f.severity, "MEDIUM");
});

test("prioritization: KEV critical outranks a verified high and a medium", () => {
  const { findings } = run(OBS_APACHE_VULN, OBS_SSH_FOCAL_VULN, OBS_NGINX_VULN);
  const order = findings.map((f) => f.cveId);
  assert.equal(order[0], "CVE-2021-41773", `KEV critical should be first, got ${order.join(",")}`);
  // medium nginx should rank last of the three
  assert.equal(order[order.length - 1], "CVE-2021-DEMO-NGINX");
});

test("response envelope shape", () => {
  const res = run(OBS_APACHE_VULN);
  assert.equal(res.engineVersion, "0.1.0");
  assert.equal(res.generatedAt, NOW);
  assert.ok(Array.isArray(res.findings));
  assert.ok(Array.isArray(res.suppressed));
});
