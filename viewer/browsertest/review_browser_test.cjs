"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { chromium } = require("playwright");

const viewer = fs.readFileSync(path.join(__dirname, "..", "lrng-viewer.html"), "utf8");
const placeholder = '<script type="application/json" id="lrng-report"></script>';
function embed(report) {
  const data = JSON.stringify(report).replace(/[<>&\u2028\u2029]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
  return viewer.split(placeholder).join('<script type="application/json" id="lrng-report">' + data + "</script>");
}
function report(pid = 4242, osName = "windows") {
  return { tool: "liveresponse-ng", schema_version: "1.2", host: "LAB-01", os: osName, run_id: "same-run-id", collected_at: "2026-01-01T00:00:00Z",
    results: [{ collector: "processes", records: [{ fields: { pid, ppid: 100, name: "sample.exe", image_path: 'C:\\<img src=x>\\$(echo injected).exe', created_at: "2025-12-31T23:00:00Z" }, findings: [{ rule: "defense.amsi_patched", severity: "critical", confidence: 90, detail: "Fixture signal" }] }] }] };
}
const fixtures = new Map([["/report", report()], ["/changed", report()]]);
fixtures.get("/changed").results[0].records[0].fields.extra = "changed evidence with identical host/run/PID metadata";
const many = report();
many.results[0].records = Array.from({ length: 210 }, (_, i) => ({ fields: { pid: 5000 + i, name: "many.exe" }, findings: [{ rule: "exec.fixture", severity: "suspect", confidence: 80, detail: "Priority signal " + i }] }));
fixtures.set("/many", many);
if (process.argv[2]) {
  const caseA = JSON.parse(fs.readFileSync(process.argv[2], "utf8")), caseB = structuredClone(caseA);
  caseB.sources[0].report.results[0].records[0].fields.extra = "changed nested evidence; recorded source hash is unchanged";
  fixtures.set("/case", caseA); fixtures.set("/case-changed", caseB);
}
const failures = [];
async function ready(page) {
  await page.getByRole("heading", { name: "Start here", exact: true }).waitFor();
  await page.waitForFunction(() => { const n = document.querySelector('[aria-label="Analyst handoff summary"]'); return n && !n.disabled; });
}
async function dirty(page) {
  return page.evaluate(() => !window.dispatchEvent(new Event("beforeunload", { cancelable: true })));
}
async function handoff(page, temp, name) {
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download analyst handoff", exact: true }).click();
  const file = path.join(temp, name); await (await download).saveAs(file);
  return fs.readFileSync(file, "utf8");
}
async function openContext(browser, url, init) {
  const context = await browser.newContext({ acceptDownloads: true });
  if (init) await context.addInitScript(init);
  const page = await context.newPage();
  page.on("pageerror", (e) => failures.push(e.message));
  page.on("dialog", async (d) => { if (d.type() === "beforeunload") await d.accept(); else { failures.push("Unexpected " + d.type()); await d.dismiss(); } });
  await page.goto(url);
  await page.locator("nav").getByRole("button", { name: /Start here/ }).click(); await ready(page);
  return { context, page };
}

(async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "lrng-review-tests-"));
  const server = http.createServer((req, res) => {
    const data = fixtures.get(req.url);
    if (!data) { res.writeHead(404).end(); return; }
    res.setHeader("Content-Type", "text/html; charset=utf-8"); res.setHeader("Cache-Control", "no-store"); res.end(embed(data));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  let browser;
  try {
    browser = await chromium.launch(process.env.LRNG_CHROME ? { executablePath: process.env.LRNG_CHROME } : {});
    {
      const { context, page } = await openContext(browser, base + "/report");
      assert.equal(await dirty(page), false, "pristine review must not warn");
      const summary = page.getByLabel("Analyst handoff summary");
      await summary.click(); await summary.fill("Keep this investigation write-up after refreshing.");
      assert.equal(await dirty(page), true, "edited summary must enable the close warning");
      // Exercise the real browser prompt, including Cancel retaining the page.
      page.removeAllListeners("dialog");
      page.once("dialog", async (d) => { assert.equal(d.type(), "beforeunload"); await d.dismiss(); });
      await page.reload().catch((e) => assert.match(e.message, /ERR_ABORTED|cancel|Navigation/i));
      assert.equal(await summary.inputValue(), "Keep this investigation write-up after refreshing.");
      page.on("dialog", async (d) => { assert.equal(d.type(), "beforeunload"); await d.accept(); });
      await page.reload(); await ready(page);
      assert.equal(await page.getByLabel("Analyst handoff summary").inputValue(), "Keep this investigation write-up after refreshing.");
      assert.equal(await dirty(page), true, "restored unexported notes remain dirty");
      await handoff(page, temp, "summary.txt"); assert.equal(await dirty(page), false, "successful export clears only its source's warning");
      await page.getByLabel("Analyst handoff summary").fill("Changed after export");
      assert.equal(await dirty(page), true);
      await page.goto(base + "/changed"); await ready(page);
      assert.equal(await page.getByLabel("Analyst handoff summary").inputValue(), "", "host/run/PID alone must not restore another report's notes");
      assert.equal(await dirty(page), true, "other unexported cached source still needs a close warning");
      await page.goto(base + "/report"); await ready(page);
      assert.equal(await page.getByLabel("Analyst handoff summary").inputValue(), "Changed after export");
      await handoff(page, temp, "reopened.txt"); assert.equal(await dirty(page), false, "reopening a report must not leave an orphan dirty state after export");
      await context.close();
      console.log("Close warning, same-tab refresh recovery and content-hash isolation passed.");
    }
    {
      const { context, page } = await openContext(browser, base + "/report", () => {
        Object.defineProperty(window, "sessionStorage", { get() { throw new DOMException("blocked", "SecurityError"); } });
      });
      await page.getByLabel("Analyst handoff summary").fill("Storage blocked, but keep the in-memory review.");
      assert.match(await page.locator(".review-save-state").textContent(), /unavailable/);
      assert.equal(await dirty(page), true);
      assert.match(await handoff(page, temp, "blocked.txt"), /Storage blocked, but keep the in-memory review/);
      assert.equal(await dirty(page), false);
      await context.close();
      console.log("Blocked-storage fallback passed.");
    }
    {
      const { context, page } = await openContext(browser, base + "/report");
      await page.getByLabel("Analyst handoff summary").fill("First draft");
      await page.evaluate(() => { Storage.prototype.setItem = function () { throw new DOMException("full", "QuotaExceededError"); }; });
      await page.getByLabel("Analyst handoff summary").fill("New draft that could not be cached");
      assert.match(await page.locator(".review-save-state").textContent(), /unavailable/);
      assert.equal(await dirty(page), true);
      const keys = await page.evaluate(() => Object.keys(sessionStorage).filter((k) => /^lrng-review-v1:[a-f0-9]{64}$/.test(k)));
      assert.equal(keys.length, 0, "failed cache update must not leave a stale draft that looks current");
      await context.close();
      console.log("Quota-failure fallback passed.");
    }
    {
      const { context, page } = await openContext(browser, base + "/many");
      await page.getByRole("button", { name: "Review priority findings", exact: true }).click();
      await page.getByRole("button", { name: "Show 10 more", exact: true }).click();
      await page.locator(".f-row").last().click();
      await page.getByLabel("Finding review notes", { exact: true }).fill("Do not lose this annotation beyond the priority limit.");
      await page.locator("nav").getByRole("button", { name: /Start here/ }).click();
      const text = await handoff(page, temp, "many.txt");
      assert.match(text, /Do not lose this annotation beyond the priority limit/); assert.match(text, /additional unreviewed priority signals/);
      assert.equal(await dirty(page), false); await context.close();
      console.log("Handoff retains annotations beyond the priority limit.");
    }
    if (fixtures.has("/case")) {
      const { context, page } = await openContext(browser, base + "/case#review");
      const ids = await page.getByRole("combobox", { name: "Source report", exact: true }).locator("option").evaluateAll((xs) => xs.map((x) => x.value));
      await page.getByLabel("Analyst handoff summary").fill("First source draft");
      await page.getByRole("combobox", { name: "Source report", exact: true }).selectOption(ids[1]);
      await page.locator("nav").getByRole("button", { name: /Start here/ }).click(); await ready(page);
      await page.getByLabel("Analyst handoff summary").fill("Second source draft");
      await handoff(page, temp, "second-source.txt"); assert.equal(await dirty(page), true, "exporting source two must not mark source one exported");
      await page.reload(); await page.locator("nav").getByRole("button", { name: /Start here/ }).click(); await ready(page);
      assert.equal(await page.getByLabel("Analyst handoff summary").inputValue(), "First source draft");
      await page.goto(base + "/case-changed#review");
      await page.locator("nav").getByRole("button", { name: /Start here/ }).click(); await ready(page);
      assert.equal(await page.getByLabel("Analyst handoff summary").inputValue(), "", "recorded case-source hash alone must not bind a draft");
      await context.close();
      console.log("Case-source recovery and dirty-state isolation passed.");
    }
    for (const [label, pid, osName, expected] of [["windows", 4242, "windows", true], ["linux", 4242, "linux", true], ["string", "4242; whoami", "windows", false], ["fraction", 42.5, "windows", false], ["zero", 0, "windows", false], ["overflow", 4294967296, "windows", false], ["unsupported", 42, "unknown", false]]) {
      const fixture = report(pid, osName); fixtures.set("/pid-" + label, fixture);
      const { context, page } = await openContext(browser, base + "/pid-" + label);
      const command = page.locator(".scan-command");
      assert.equal(await command.count(), expected ? 1 : 0, label);
      if (expected) {
        const text = await command.textContent();
        assert.match(text, osName === "windows" ? /^\.\\lrng\.exe / : /^\.\/lrng /);
        assert.match(text, / -collectors memory -mem-pids 4242 -mem-budget 60s -mem-timeout 90s -mem-workers 1 -no-dns -format html -out memory-pid-4242-[0-9TZ]+\.html$/);
        assert.ok(!text.includes("$(") && !text.includes("img") && !text.includes("-force") && !text.includes("mem-include-lsass"));
        assert.match(await page.locator(".memory-followup").textContent(), /PID may have been reused/);
        await page.evaluate(() => { Object.defineProperty(navigator, "clipboard", { value: { writeText: async (text) => { window.copiedCommand = text; } }, configurable: true }); });
        await page.getByRole("button", { name: "Copy memory-scan command", exact: true }).click();
        assert.equal(await page.evaluate(() => window.copiedCommand), text);
      }
      assert.equal(await page.locator("img,iframe,form").count(), 0);
      await context.close();
    }
    const duplicate = report(); duplicate.results[0].records.push(structuredClone(duplicate.results[0].records[0])); fixtures.set("/duplicate", duplicate);
    const { context, page } = await openContext(browser, base + "/duplicate"); assert.equal(await page.locator(".scan-command").count(), 0); await context.close();
    assert.deepEqual(failures, []);
    console.log("Review polish passed: close warning, refresh recovery, report-content isolation, storage failures, all annotations exported, and bounded PID-only memory commands.");
  } finally { if (browser) await browser.close(); await new Promise((resolve) => server.close(resolve)); fs.rmSync(temp, { recursive: true, force: true }); }
})().catch((e) => { console.error(e); process.exitCode = 1; });
