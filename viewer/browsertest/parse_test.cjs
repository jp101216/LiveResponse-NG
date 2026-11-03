// Exercise the actual HTML page's loader without a browser or a build step.
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const page = fs.readFileSync(path.join(__dirname, "..", "lrng-viewer.html"), "utf8");
const start = page.indexOf("  function parseReport(text) {");
const end = page.indexOf("  // ---- The model", start);
assert.ok(start >= 0 && end > start, "the page's report loader must be found");
const isObj = page.match(/^  const isObj = .*;$/m);
assert.ok(isObj, "the loader's object predicate must be found");
const parseReport = vm.runInNewContext(`(() => { ${isObj[0]}\n${page.slice(start, end)}\nreturn parseReport; })()`);

const run = (id = "r1", host = "host-one") => ({ type: "run", run_id: id, host });
const collector = (id = "r1", name = "processes") => ({ type: "collector", run_id: id, collector: name });
const record = (i, id = "r1", name = "processes") => ({ type: "record", run_id: id, collector: name, record: i, fields: { pid: i + 1 } });
const jsonl = (...events) => events.map((e) => JSON.stringify(e)).join("\n");

test("JSON envelopes and a complete JSONL run retain their records", () => {
  const envelope = { host: "one", results: [] };
  assert.equal(parseReport(JSON.stringify(envelope)).rep.host, "one");
  const { rep, skipped } = parseReport(jsonl(run(), collector(), record(0), record(1),
    { type: "finding", run_id: "r1", collector: "processes", record: 0 }));
  assert.equal(rep.host, "host-one");
  assert.equal(rep.results[0].records.length, 2);
  assert.equal(rep.results[0].records[1].fields.pid, 2);
  assert.equal(skipped, 0);
});

test("older JSONL events without run IDs still load", () => {
  const text = jsonl(run(), { type: "collector", collector: "processes" },
    { type: "record", collector: "processes", fields: { pid: 7 } });
  assert.equal(parseReport(text).rep.results[0].records[0].fields.pid, 7);
});

test("unreadable lines are counted and CRLF is supported", () => {
  const text = jsonl(run(), collector(), record(0)).replace(/\n/g, "\r\n") + '\r\nnot JSON\r\n42\r\n';
  assert.equal(parseReport(text).skipped, 2);
});

test("concatenated runs cannot attribute one host's records to another", () => {
  assert.throws(() => parseReport(jsonl(run(), collector(), record(0), run("r2", "host-two"),
    collector("r2"), record(0, "r2"))), /multiple runs/);
  assert.throws(() => parseReport(jsonl(run(), collector(), run())), /multiple runs/);
});

test("foreign collector, record and finding events are rejected", () => {
  for (const ev of [collector("r2"), record(0, "r2"), { type: "finding", run_id: "r2" }]) {
    assert.throws(() => parseReport(jsonl(run(), collector(), ev)), /different run/);
  }
});

test("events before a run header cannot be attributed to a later run", () => {
  assert.throws(() => parseReport(jsonl(collector("r2"), record(0, "r2"), run())), /run header/);
});

test("a tiny file cannot allocate a large sparse record array", () => {
  assert.throws(() => parseReport(jsonl(run(), collector(), record(1000))), /record indices/);
});

test("the sparse-record budget is shared across collectors", () => {
  const events = [run()];
  for (let i = 0; i < 20; i++) events.push(collector("r1", "c" + i), record(30, "r1", "c" + i));
  assert.throws(() => parseReport(jsonl(...events)), /record indices/);
});

test("ordinary large runs and bounded gaps keep their record indices", () => {
  const events = [run(), collector()];
  for (let i = 0; i < 2000; i++) events.push(record(i));
  assert.equal(parseReport(jsonl(...events)).rep.results[0].records.length, 2000);
  const { rep } = parseReport(jsonl(run(), collector(), record(2)));
  assert.equal(rep.results[0].records.length, 3);
  assert.equal(rep.results[0].records[2].fields.pid, 3);
});
