// Browser test for the report viewer, in Chromium through Playwright.
//
//   node viewer/browsertest/browser_test.cjs [report.json ...] [--shots DIR]
//
// It opens a deliberately hostile report (markup, script and URL payloads in
// every string, prototype keys, cycles, absurd nesting) both embedded, the way
// `-format html` writes it, and dropped onto the standalone viewer as JSON and
// as JSONL; then any real reports named on the command line. In each it walks
// every view and opens every finding, process and record, and fails if
// anything executes, any markup from the report becomes an element, any
// request leaves the page, or the console logs an error. It also checks that
// the content security policy really blocks scripts and connections.
//
// Needs Node and Playwright (or playwright-core with a Chrome on the machine:
// set LRNG_CHROME to its path).
"use strict";
const fs = require("fs");
const os = require("os");
const path = require("path");

let chromium;
try { ({ chromium } = require("playwright")); } catch { ({ chromium } = require("playwright-core")); }

const viewerPath = path.join(__dirname, "..", "lrng-viewer.html");
const viewer = fs.readFileSync(viewerPath, "utf8");
const PLACEHOLDER = '<script type="application/json" id="lrng-report"></script>';

// What `viewer.Render` does: the report's JSON, HTML-escaped, in the data block.
function embed(report) {
  const data = JSON.stringify(report).replace(/[<>&\u2028\u2029]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
  if (viewer.split(PLACEHOLDER).length !== 2) throw new Error("placeholder missing");
  return viewer.replace(PLACEHOLDER, '<script type="application/json" id="lrng-report">' + data + "</script>");
}

const X = [
  `<img src=x onerror="alert('img')">`,
  `</script><script>alert('close')</script>`,
  `<svg/onload=alert('svg')>`,
  `javascript:alert('url')`,
  `<iframe srcdoc="<script>alert('frame')</script>"></iframe>`,
  `"><b onmouseover=alert('attr')>bold</b>`,
  `line\u2028separator\u2029`,
  "{{constructor.constructor('alert(1)')()}}",
  "${alert('tpl')}",
  `<a href="javascript:alert('a')">link</a>`,
];
const pick = (i) => X[i % X.length];

function hostileReport() {
  const procs = [
    { fields: { pid: 1, ppid: 0, name: pick(0), command_line: pick(1), image_path: pick(3) }, findings: [{ rule: pick(2), severity: "critical", technique: "T1059.001", confidence: 90, detail: pick(4) }] },
    { fields: { pid: 10, ppid: 11, name: "cycle-a" } },
    { fields: { pid: 11, ppid: 10, name: "cycle-b" } },
    { fields: { pid: 12, ppid: 12, name: "own-parent" } },
    { fields: { pid: pick(5), ppid: 1, name: pick(6) }, findings: [{ rule: "r", severity: pick(5), technique: pick(3), confidence: "high", detail: pick(7) }] },
    { fields: { pid: 13, ppid: 1, name: "proto", __proto__x: 1 } },
  ];
  // A chain thousands of processes deep.
  for (let i = 0; i < 3000; i++) procs.push({ fields: { pid: 1000 + i, ppid: i ? 999 + i : 1, name: "deep" + i } });
  const protoRecord = JSON.parse('{"fields":{"__proto__":{"polluted":"yes"},"constructor":{"prototype":{"polluted":"yes"}},"<b>key</b>":"' + "v".repeat(5000) + '"}}');
  return {
    schema_version: "1.2", tool: "liveresponse-ng", tool_version: pick(1), tool_commit: pick(0), run_id: pick(5),
    host: pick(0), os: pick(2), arch: pick(9), collected_at: "2026-10-31T12:00:00.123456789Z",
    host_info: { os_name: pick(4), domain: pick(5), join_type: "domain", errors: [pick(1)], [pick(6)]: pick(7) },
    run: { started_at: pick(3), finished_at: "nope", elevated: false, interrupted: true, args: [pick(0), pick(1)], collectors: pick(2), exe_path: pick(9) },
    results: [
      null, 42, "string",
      { collector: "processes", records: procs, meta: { [pick(0)]: pick(1), nested: { deep: [pick(2)] } }, errors: [pick(4), pick(5)] },
      { collector: pick(0), records: [protoRecord, null, 7, { fields: null, findings: "nope" }, { fields: { time: "2026-10-31T11:00:00Z", message: pick(1) }, findings: [{ rule: pick(9), severity: "suspect", technique: "javascript:alert(1)", confidence: 50, detail: pick(8) }] }], errors: [pick(9)] },
      { collector: "timeline", records: [
        { fields: { time: "2026-10-31T10:00:00Z", source: pick(0), artifact: pick(1), detail: pick(2), source_record: 0, top_severity: "critical", top_rule: pick(3) } },
        { fields: { time: pick(4), source: "processes", artifact: "x", source_record: 999999 } },
        { fields: { time: "2026-10-31T10:00:01Z", source: "processes", artifact: pick(5), source_record: 0 } },
      ] },
      { collector: "iocs", records: [{ fields: { type: pick(0), value: pick(1), max_severity: pick(2), rules: [pick(3), pick(4)], source_count: pick(5), intel_org: pick(6), intel_asn: pick(7), intel_country: pick(8), intel_categories: [pick(9)] } }] },
      { collector: "network", records: Array.from({ length: 450 }, (_, i) => ({ fields: { remote: pick(i), pid: i, state: pick(i + 3) }, findings: i % 7 ? [] : [{ rule: pick(i), severity: ["critical", "suspect", "notable", "info"][i % 4], technique: "T1071.001", confidence: i % 100, detail: pick(i + 1) }] })) },
    ],
    summary: { findings: pick(0), by_rule: { [pick(1)]: 1 } },
  };
}

function jsonl(rep) {
  const lines = [JSON.stringify(Object.assign({ type: "run" }, rep, { results: undefined }))];
  for (const r of rep.results) {
    if (!r || typeof r !== "object") continue;
    lines.push(JSON.stringify({ type: "collector", collector: r.collector, meta: r.meta, errors: r.errors }));
    (r.records || []).forEach((rec, i) => {
      if (rec && typeof rec === "object") lines.push(JSON.stringify({ type: "record", collector: r.collector, record: i, fields: rec.fields, findings: rec.findings }));
    });
  }
  lines.push("{not json", '"a string"', "");
  return lines.join("\n");
}

const failures = [];
const fail = (where, what) => failures.push(`${where}: ${what}`);

async function exercise(page, where) {
  // Every view, then every collector's data; open everything that opens.
  const views = ["findings", "processes", "timeline", "indicators", "run"];
  for (const v of views) {
    await page.evaluate((x) => { location.hash = "#" + x; }, v);
    await page.waitForTimeout(60);
    if (v === "findings") {
      const rows = await page.locator(".f-row").count();
      for (let i = 0; i < Math.min(rows, 40); i++) await page.locator(".f-row").nth(i).click();
      const more = page.locator(".pager .btn");
      if (await more.count()) await more.first().click();
    }
    if (v === "processes") {
      const expand = page.getByRole("button", { name: "Expand all" });
      if (await expand.count()) await expand.click();
      const names = await page.locator(".p-name").count();
      for (let i = 0; i < Math.min(names, 12); i++) await page.locator(".p-name").nth(i).click();
      const search = page.locator("main .search");
      if (await search.count()) { await search.fill("deep2999"); await page.waitForTimeout(250); await search.fill(""); await page.waitForTimeout(250); }
    }
  }
  const collectors = await page.locator("nav .nav-item").evaluateAll((els) => els.length);
  for (let i = views.length; i < collectors; i++) {
    await page.locator("nav .nav-item").nth(i).click();
    await page.waitForTimeout(40);
    const opens = await page.locator(".row-btn").count();
    for (let j = 0; j < Math.min(opens, 6); j++) await page.locator(".row-btn").nth(j * 2 < opens ? j : 0).click();
    const all = page.locator("main .filters .btn");
    if (await all.count()) await all.first().click();
    const ths = await page.locator("th.sortable").count();
    for (let j = 0; j < Math.min(ths, 4); j++) await page.locator("th.sortable").nth(j).click();
  }
  // A hash naming something that isn't a collector is ignored.
  await page.evaluate(() => { location.hash = "#collector/" + encodeURIComponent("<img src=x onerror=alert('hash')>"); });
  await page.waitForTimeout(60);
  for (const t of await page.locator(".tactic").all()) await t.click();

  const audit = await page.evaluate(() => ({
    foreign: [...document.querySelectorAll("img, svg, iframe, object, embed, frame, form, b, a:not(.tech)")].map((e) => e.outerHTML.slice(0, 80)),
    scripts: document.querySelectorAll("script").length,
    hrefs: [...document.querySelectorAll("a[href]")].map((a) => a.getAttribute("href")).filter((h) => !/^https:\/\/attack\.mitre\.org\/techniques\/T\d{4}(\/\d{3})?\/$/.test(h)),
    polluted: ({}).polluted !== undefined || Object.prototype.polluted !== undefined,
    host: (document.querySelector(".case h1") || {}).textContent,
  }));
  if (audit.foreign.length) fail(where, "elements from report markup: " + audit.foreign.join(" | "));
  if (audit.scripts !== 2) fail(where, `${audit.scripts} script elements, want 2`);
  if (audit.hrefs.length) fail(where, "links outside attack.mitre.org: " + audit.hrefs.join(" "));
  if (audit.polluted) fail(where, "Object.prototype was polluted");
  return audit;
}

async function openPage(browser, where, url, shots) {
  const ctx = await browser.newContext({ viewport: { width: 1360, height: 860 } });
  const page = await ctx.newPage();
  page.on("dialog", async (d) => { fail(where, "a dialog opened: " + d.message()); await d.dismiss(); });
  page.on("pageerror", (e) => fail(where, "page error: " + e.message));
  page.on("console", (m) => { if (m.type() === "error") fail(where, "console error: " + m.text()); });
  page.on("request", (r) => { if (!/^(file|data|about):/.test(r.url())) fail(where, "request left the page: " + r.url()); });
  await page.goto(url);
  await page.waitForTimeout(150);
  return { ctx, page, shots };
}

(async () => {
  const args = process.argv.slice(2);
  const shotDir = args.includes("--shots") ? args[args.indexOf("--shots") + 1] : "";
  const reports = args.filter((a, i) => !a.startsWith("--") && args[i - 1] !== "--shots");
  const exe = process.env.LRNG_CHROME;
  const browser = await chromium.launch(exe ? { executablePath: exe } : {});
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "lrng-viewer-"));
  const hostile = hostileReport();

  // 1. Embedded, as -format html writes it.
  const embeddedPath = path.join(tmp, "hostile.html");
  fs.writeFileSync(embeddedPath, embed(hostile));
  {
    const { ctx, page } = await openPage(browser, "embedded", "file://" + embeddedPath);
    const audit = await exercise(page, "embedded");
    if (audit.host !== X[0]) fail("embedded", `host shown as ${JSON.stringify(audit.host)}, want the payload verbatim`);
    // The policy is live: an injected script doesn't run, a connection is refused.
    // (Both log the refusal; only those expected lines are dropped below.)
    const before = failures.length;
    const csp = await page.evaluate(async () => {
      const s = document.createElement("script");
      s.textContent = "window.__ran = true";
      document.body.append(s);
      let net = "reached";
      try { await fetch("https://example.com/"); } catch { net = "blocked"; }
      return { ran: window.__ran === true, net };
    });
    if (csp.ran) fail("embedded", "an injected inline script ran: the content security policy isn't in force");
    if (csp.net !== "blocked") fail("embedded", "fetch reached the network: the content security policy isn't in force");
    const expected = /Refused to (execute|connect)|Content Security Policy|Fetch API cannot load|Failed to fetch/;
    failures.splice(before, failures.length - before, ...failures.slice(before).filter((f) => !expected.test(f)));
    await ctx.close();
  }

  // 2. Dropped on the standalone viewer: JSON, then JSONL, then a file that isn't a report.
  const standalone = "file://" + viewerPath;
  const files = [["hostile.json", JSON.stringify(hostile)], ["hostile.jsonl", jsonl(hostile)]];
  for (const [name, text] of files) {
    const where = "opened " + name;
    const p = path.join(tmp, name);
    fs.writeFileSync(p, text);
    const { ctx, page } = await openPage(browser, where, standalone);
    await page.setInputFiles("#file", p);
    await page.waitForSelector(".case h1", { timeout: 5000 }).catch(() => fail(where, "the report didn't open"));
    const audit = await exercise(page, where);
    if (audit.host !== X[0]) fail(where, `host shown as ${JSON.stringify(audit.host)}`);
    if (name.endsWith(".jsonl") && !(await page.locator(".warn", { hasText: "unreadable line" }).count())) fail(where, "skipped JSONL lines weren't reported");
    await ctx.close();
  }
  {
    const where = "not a report";
    const p = path.join(tmp, "notes.txt");
    fs.writeFileSync(p, "<script>alert(1)</script> plain text, not a report");
    const { ctx, page } = await openPage(browser, where, standalone);
    await page.setInputFiles("#file", p);
    await page.waitForTimeout(150);
    const msg = await page.locator("#load-error").textContent();
    if (!/isn't an lrng report/.test(msg || "")) fail(where, "no error message: " + msg);
    await ctx.close();
  }

  // 3. Real reports: every view renders cleanly. JSON is embedded the way
  // -format html does it; JSONL is opened on the standalone viewer.
  for (const r of reports) {
    const where = path.basename(r);
    let ctx, page;
    if (r.endsWith(".jsonl")) {
      ({ ctx, page } = await openPage(browser, where, standalone));
      await page.setInputFiles("#file", r);
      await page.waitForSelector(".case h1", { timeout: 15000 }).catch(() => fail(where, "the report didn't open"));
    } else {
      const p = path.join(tmp, where + ".html");
      fs.writeFileSync(p, embed(JSON.parse(fs.readFileSync(r, "utf8"))));
      ({ ctx, page } = await openPage(browser, where, "file://" + p));
    }
    await exercise(page, where);
    if (shotDir) {
      for (const v of ["findings", "processes", "timeline", "indicators", "run"]) {
        await page.evaluate((x) => { location.hash = "#" + x; window.scrollTo(0, 0); }, v);
        await page.waitForTimeout(80);
        await page.screenshot({ path: path.join(shotDir, `${where}-${v}.png`) });
      }
    }
    await ctx.close();
  }

  await browser.close();
  fs.rmSync(tmp, { recursive: true, force: true });
  if (failures.length) {
    console.error(`viewer browser test: ${failures.length} failure(s)`);
    for (const f of failures) console.error("  " + f);
    process.exit(1);
  }
  console.log(`viewer browser test: passed (hostile report embedded, as JSON and as JSONL; ${reports.length} real report(s))`);
})().catch((e) => { console.error(e); process.exit(1); });
