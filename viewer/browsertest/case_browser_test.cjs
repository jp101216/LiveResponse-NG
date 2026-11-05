// Walk the real CLI-produced case JSON/HTML in Chromium and verify that every
// case/comparison pivot lands in its own original report. No report data may
// execute, insert markup, or make a network request.
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { pathToFileURL } = require("node:url");
const { chromium } = require("playwright");
const viewerPath = path.join(__dirname, "..", "lrng-viewer.html");
const viewer = fs.readFileSync(viewerPath, "utf8");
const placeholder = '<script type="application/json" id="lrng-report"></script>';
function embed(c) {
  const data = JSON.stringify(c).replace(/[<>&\u2028\u2029]/g, (ch) => "\\u" + ch.charCodeAt(0).toString(16).padStart(4, "0"));
  const parts = viewer.split(placeholder);
  assert.equal(parts.length, 2);
  return parts[0] + '<script type="application/json" id="lrng-report">' + data + "</script>" + parts[1];
}
const errors = [];
const temp = fs.mkdtempSync(path.join(os.tmpdir(), "lrng-case-browser-"));
const nav = (page, name) => page.locator("nav").getByRole("button", { name, exact: true });
async function check(browser, file, hostile = false) {
  const context = await browser.newContext({ viewport: { width: 1360, height: 900 } });
  const page = await context.newPage();
  page.on("pageerror", (e) => errors.push(e.message));
  page.on("dialog", async (d) => { errors.push("report opened a dialog"); await d.dismiss(); });
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  page.on("request", (r) => { if (!/^(file|data|about):/.test(r.url())) errors.push("network request: " + r.url()); });
  if (file.endsWith(".html")) await page.goto(pathToFileURL(path.resolve(file)).href);
  else {
    await page.goto(pathToFileURL(viewerPath).href);
    await page.setInputFiles("#file", file);
  }
  await page.waitForSelector(".case-source");
  assert.ok(await page.locator(".case-source").count() >= 2, "case kept separate reports");
  await page.getByRole("button", { name: "Open source record", exact: true }).first().click();
  await page.waitForFunction(() => location.hash === "#collector/services" && document.querySelector("#case").textContent.includes("demo-after") && document.querySelector("main").textContent.includes("v2"));
  assert.match(await page.locator("#case").textContent(), /demo-after/);
  assert.match(await page.locator("#case").textContent(), /Recorded original file SHA-256/);
  assert.match(await page.locator("main").textContent(), /v2/);
  await nav(page, "Case overview").click();
  await page.waitForSelector(".case-source");
  const search = page.getByRole("searchbox", { name: "Search case findings, hosts and runs" });
  await search.fill("no-such-finding");
  await page.waitForTimeout(250);
  assert.equal(await page.locator(".case-finding").count(), 0);
  await search.fill("");
  await page.waitForSelector(".case-finding");
  if (await nav(page, "Report comparison").count()) {
    for (const [side, run, version] of [["before", "demo-before", "v1"], ["after", "demo-after", "v2"]]) {
      await nav(page, "Report comparison").click();
      const service = page.locator(".comparison-group").filter({ has: page.locator("h3", { hasText: /^services/ }) });
      const changed = service.locator(".comparison-change").filter({ has: page.locator("summary", { hasText: /^changed/ }) }).first();
      await changed.locator("summary").click();
      await changed.getByRole("button", { name: `Open ${side} source record`, exact: true }).click();
      await page.waitForFunction(({ run, version }) => location.hash === "#collector/services" && document.querySelector("#case").textContent.includes(run) && document.querySelector("main").textContent.includes(version), { run, version });
      assert.ok((await page.locator("#case").textContent()).includes(run), "comparison opened the correct source run");
      assert.ok((await page.locator("main").textContent()).includes(version), "comparison opened original source values");
    }
  }
  await nav(page, "Case overview").click();
  await page.waitForSelector(".case-source");
  // Review notes follow the exact source object, even when hostnames and PIDs
  // repeat across source runs. Source switching must not transfer assessments.
  const sourcePick=page.getByRole("combobox",{name:"Source report",exact:true});
  const sourceIDs=await sourcePick.locator("option").evaluateAll((xs)=>xs.map((x)=>x.value));
  await sourcePick.selectOption(sourceIDs[0]);
  await page.locator("nav").getByRole("button",{name:/Start here/}).click();
  await page.getByLabel("Analyst handoff summary").fill("Review belongs to the first source only.");
  await page.getByRole("combobox",{name:"Source report",exact:true}).selectOption(sourceIDs[1]);
  await page.locator("nav").getByRole("button",{name:/Start here/}).click();
  assert.equal(await page.getByLabel("Analyst handoff summary").inputValue(),"");
  await page.getByRole("combobox",{name:"Source report",exact:true}).selectOption(sourceIDs[0]);
  await page.locator("nav").getByRole("button",{name:/Start here/}).click();
  assert.equal(await page.getByLabel("Analyst handoff summary").inputValue(),"Review belongs to the first source only.");
  await nav(page,"Case overview").click();
  await page.waitForSelector(".case-source");
  const audit = await page.evaluate(() => ({ foreign: document.querySelectorAll("img,svg,iframe,object,embed,form").length, scripts: document.scripts.length, polluted: ({}).polluted, nodes: document.querySelectorAll("*").length }));
  assert.equal(audit.foreign, 0, "hostile data stayed text");
  assert.equal(audit.scripts, 2);
  assert.equal(audit.polluted, undefined);
  assert.ok(audit.nodes < 5000, "case rendering is paginated");
  if (hostile) assert.match(await page.locator("#case h1").textContent(), /<img/);
  await context.close();
  console.log(path.basename(file) + ": case/source/comparison navigation and hostile-content checks passed");
}
(async () => {
  const files = process.argv.slice(2);
  assert.ok(files.length && files.some((f) => f.endsWith(".json")), "pass CLI-generated case JSON and HTML fixtures");
  const browser = await chromium.launch(process.env.LRNG_CHROME ? { executablePath: process.env.LRNG_CHROME } : {});
  try {
    for (const file of files) await check(browser, file);
    const hostile = JSON.parse(fs.readFileSync(files.find((f) => f.endsWith(".json")), "utf8"));
    const payload = '<img src=x onerror=alert(1)></script><script>alert(2)</script>';
    hostile.name = payload;
    for (const s of hostile.sources) {
      s.name = payload;
      for (const r of s.report.results) for (const rec of r.records || []) {
        rec.fields.__proto__x = payload;
        for (const f of rec.findings || []) {
          f.detail = payload;
          // JSON objects with own coercion members must still render as text.
          f.severity = { toString: "malformed", valueOf: "malformed" };
        }
      }
    }
    const file = path.join(temp, "hostile-case.html");
    fs.writeFileSync(file, embed(hostile));
    await check(browser, file, true);
    assert.deepEqual(errors, []);
  } finally {
    await browser.close();
    fs.rmSync(temp, { recursive: true, force: true });
  }
})().catch((err) => { console.error(err); process.exitCode = 1; });
