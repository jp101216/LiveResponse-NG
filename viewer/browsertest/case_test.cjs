"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const test = require("node:test");
const vm = require("node:vm");
const page = fs.readFileSync(path.join(__dirname, "..", "lrng-viewer.html"), "utf8");
const start = page.indexOf("  function parseReport(text) {");
const end = page.indexOf("  // ---- The model", start);
const isObj = page.match(/^  const isObj = .*;$/m);
assert.ok(start >= 0 && end > start && isObj, "actual case loader must be found");
const parse = vm.runInNewContext(`(() => { ${isObj[0]}\n${page.slice(start, end)}\nreturn parseReport; })()`);

function source(name) {
  const data = fs.readFileSync(path.join(__dirname, "..", "..", "demo", name));
  const sha256 = crypto.createHash("sha256").update(data).digest("hex");
  return { id: "sha256:" + sha256, name, sha256, bytes: data.length, report: JSON.parse(data) };
}
function workspace() {
  return { kind: "lrng_case", case_schema_version: "1.0", case_id: "test", name: "Test case", sources: [source("case-before.json"), source("case-after.json")] };
}
function comparison(c) {
  c.comparison = { before_source: c.sources[0].id, after_source: c.sources[1].id, identity_basis: "operator_attested_same_machine", collectors: [{ collector: "services", changes: [{ kind: "changed", key: "example", before: [{ source_id: c.sources[0].id, result: 0, record: 0 }], after: [{ source_id: c.sources[1].id, result: 0, record: 0 }] }] }] };
  return c;
}

test("cases preserve host/run boundaries, repeated PIDs and exact source references", () => {
  const c = comparison(workspace());
  const got = parse(JSON.stringify(c)).workspace;
  assert.equal(got.sources.length, 2);
  assert.equal(got.sources[0].report.host, got.sources[1].report.host);
  assert.notEqual(got.sources[0].report.run_id, got.sources[1].report.run_id);
  assert.equal(got.sources[0].report.results[2].records[0].fields.pid, got.sources[1].report.results[2].records[0].fields.pid);
  assert.equal(got.comparison.collectors[0].changes[0].after[0].source_id, c.sources[1].id);
});
test("case source IDs, run IDs and collector names cannot alias", () => {
  for (const mutate of [
    (c) => { c.sources.push(c.sources[0]); },
    (c) => { c.sources[1].report.run_id = c.sources[0].report.run_id; },
    (c) => { c.sources[0].report.results.push(c.sources[0].report.results[0]); },
    (c) => { c.sources[0].id = "__proto__"; },
    (c) => { c.sources[0].report.results[0].records[0].findings = [null]; },
  ]) {
    const c = workspace(); mutate(c);
    assert.throws(() => parse(JSON.stringify(c)), /duplicate|invalid|ambiguous/);
  }
});
test("comparison references cannot leave their before/after source or collector", () => {
  for (const mutate of [
    (r, c) => { r.source_id = c.sources[1].id; },
    (r) => { r.result = 2; },
    (r) => { r.record = -1; },
    (r) => { r.record = 1e12; },
    (r) => { r.result = "0"; },
  ]) {
    const c = comparison(workspace()); mutate(c.comparison.collectors[0].changes[0].before[0], c);
    assert.throws(() => parse(JSON.stringify(c)), /source scope/);
  }
});
test("cases reject source-count and byte-budget abuse", () => {
  const c = workspace();
  c.sources = Array.from({ length: 17 }, () => source("case-before.json"));
  assert.throws(() => parse(JSON.stringify(c)), /oversized/);
  const big = workspace(); big.sources[0].bytes = 16 * 1024 * 1024 + 1;
  assert.throws(() => parse(JSON.stringify(big)), /source size/);
  const zero = workspace(); zero.sources[0].bytes = 0;
  assert.throws(() => parse(JSON.stringify(zero)), /source size/);
});
test("unknown case versions fail while ordinary JSON reports retain their loader", () => {
  const c = workspace(); c.case_schema_version = "99";
  assert.throws(() => parse(JSON.stringify(c)), /unsupported/);
  assert.equal(parse(JSON.stringify(source("case-before.json").report)).rep.run_id, "demo-before");
});
