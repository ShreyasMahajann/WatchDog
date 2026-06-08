import { test } from "node:test";
import assert from "node:assert/strict";
import { compareDebian, compareUpstream } from "../src/version.ts";

test("compareUpstream: service point/patch releases", () => {
  assert.equal(compareUpstream("8.2p1", "8.3"), -1);
  assert.equal(compareUpstream("8.2p1", "8.2"), 1); // p1 is newer than plain 8.2
  assert.equal(compareUpstream("2.4.49", "2.4.50"), -1);
  assert.equal(compareUpstream("1.20.2", "1.20.2"), 0);
});

test("compareUpstream: numeric segments are not lexical", () => {
  assert.equal(compareUpstream("1.21.0", "1.9.0"), 1); // 21 > 9
  assert.equal(compareUpstream("1.20.0", "1.20"), 1); // extra segment sorts higher
});

test("compareDebian: revision ordering", () => {
  assert.equal(compareDebian("1:8.2p1-4ubuntu0.11", "1:8.2p1-4"), 1);
  assert.equal(compareDebian("1:8.2p1-4ubuntu0.11", "1:8.2p1-4ubuntu0.11"), 0);
  // 0.2 < 0.11 numerically within the revision
  assert.equal(compareDebian("1:8.2p1-4ubuntu0.2", "1:8.2p1-4ubuntu0.11"), -1);
});

test("compareDebian: epoch dominates", () => {
  assert.equal(compareDebian("2.0", "1:1.0"), -1);
  assert.equal(compareDebian("1:1.0", "2.0"), 1);
});

test("compareDebian: tilde sorts before everything", () => {
  assert.equal(compareDebian("1.0~rc1", "1.0"), -1);
  assert.equal(compareDebian("1.0~~", "1.0~"), -1);
  assert.equal(compareDebian("1.0", "1.0.1"), -1);
});
