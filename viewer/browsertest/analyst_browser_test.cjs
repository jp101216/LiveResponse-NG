"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { pathToFileURL } = require("node:url");
const { chromium } = require("playwright");

(async () => {
  const temp=fs.mkdtempSync(path.join(os.tmpdir(),"lrng-analyst-browser-"));
  const child=spawn(path.resolve(process.argv[2]||"./lrng"),["-ui","-ui-no-open","-ui-reports",temp]);
  let output="", exited=false;
  child.on("exit",()=>{exited=true;});
  let browser;
  try {
  const url=await new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(new Error("console did not start: "+output)),15000);
    child.on("error",reject);
    child.stderr.on("data",(data)=>{output+=data;const m=output.match(/analyst console: (http:\/\/127\.0\.0\.1:\d+\/[a-f0-9]+\/)/);if(m){clearTimeout(timer);resolve(m[1]);}});
    child.on("exit",(code)=>{if(!output.includes("analyst console:")){clearTimeout(timer);reject(new Error("console exited "+code+": "+output));}});
  });
  browser=await chromium.launch(process.env.LRNG_CHROME?{executablePath:process.env.LRNG_CHROME}:{});
  const errors=[];
  const context=await browser.newContext({acceptDownloads:true,viewport:{width:1360,height:960}});
  context.on("page",(page)=>{
    page.on("pageerror",(e)=>errors.push(e.message));
    page.on("dialog",async (d)=>{errors.push("unexpected dialog");await d.dismiss();});
    page.on("request",(r)=>{if(!r.url().startsWith(url)&&!r.url().startsWith("file:")&&!r.url().startsWith("blob:"))errors.push("foreign request: "+r.url());});
  });
    const page=await context.newPage();await page.goto(url);
    await page.getByRole("button",{name:/Quick triage/}).waitFor();
    assert.equal(await page.getByRole("button",{name:"Start collection",exact:true}).isDisabled(),true);
    const popup=context.waitForEvent("page");await page.getByRole("link",{name:"Try a sample investigation"}).click();
    const sample=await popup;await sample.getByRole("heading",{name:"Start here",exact:true}).waitFor();
    assert.match(await sample.locator("#case").textContent(),/Synthetic training report/);
    await sample.getByRole("button",{name:"Review priority findings",exact:true}).click();
    await sample.locator(".f-row").first().click();
    await sample.getByLabel("Review status",{exact:true}).selectOption("Needs follow-up");
    const payload='<img src=x onerror=alert(1)> Verify the change owner.';
    await sample.getByLabel("Finding review notes",{exact:true}).fill(payload);
    await sample.locator("nav").getByRole("button",{name:/Start here/}).click();
    await sample.getByLabel("Analyst handoff summary").fill("Ask the workstation owner about the scheduled task.");
    const downloaded=sample.waitForEvent("download");await sample.getByRole("button",{name:"Download analyst handoff",exact:true}).click();
    const file=path.join(temp,"handoff.txt");await (await downloaded).saveAs(file);
    const handoff=fs.readFileSync(file,"utf8");
    assert.match(handoff,/SYNTHETIC TRAINING DATA/);assert.match(handoff,/Needs follow-up/);assert.ok(handoff.includes(payload));assert.match(handoff,/Security events were unavailable/);assert.match(handoff,/source result 0, record 0/);
    assert.equal(await sample.locator("img,svg,iframe,form").count(),0);
    await sample.getByRole("button",{name:"Review priority findings",exact:true}).click();
    if(await sample.locator(".f-row").first().getAttribute("aria-expanded")!=="true")await sample.locator(".f-row").first().click();
    assert.equal(await sample.getByLabel("Finding review notes",{exact:true}).inputValue(),payload);
    await sample.close();
    // The sample and report review did not start a collection.
    assert.equal((await (await page.request.get(url+"api/jobs")).json()||[]).length,0);
    await page.locator("#case-label").fill("<img src=x onerror=alert(1)>");
    await page.locator("#confirm").check();await page.getByRole("button",{name:"Start collection",exact:true}).click();
    await page.getByRole("link",{name:"Review findings",exact:true}).waitFor({timeout:120000});
    assert.equal(await page.locator("img,svg,iframe,form").count(),0);
    assert.match(await page.locator(".job").textContent(),/collection complete|Partial collection/i);
    const reviewPage=context.waitForEvent("page");await page.getByRole("link",{name:"Review findings",exact:true}).click();const actual=await reviewPage;
    await actual.getByRole("heading",{name:"Start here",exact:true}).waitFor();
    await actual.close();
    const saved=page.waitForEvent("download");await page.getByRole("link",{name:"Save JSON",exact:true}).click();const download=await saved;await download.saveAs(path.join(temp,"saved.json"));
    const report=JSON.parse(fs.readFileSync(path.join(temp,"saved.json"),"utf8"));assert.equal(report.tool,"liveresponse-ng");assert.equal(report.run.dns_lookups,false);
    // A different source report cannot inherit the synthetic report's notes.
    const offline=await context.newPage();await offline.goto(pathToFileURL(path.join(__dirname,"..","lrng-viewer.html")).href);
    await offline.setInputFiles("#file",path.join(__dirname,"..","..","demo","case-after.json"));
    await offline.getByRole("heading",{name:"Start here",exact:true}).waitFor();assert.equal(await offline.getByLabel("Analyst handoff summary").inputValue(),"");
    if(process.env.LRNG_SHOTS){fs.mkdirSync(process.env.LRNG_SHOTS,{recursive:true});await page.screenshot({path:path.join(process.env.LRNG_SHOTS,"analyst-console.png"),fullPage:true});await offline.screenshot({path:path.join(process.env.LRNG_SHOTS,"guided-review.png"),fullPage:true});}
    await offline.close();await page.getByRole("button",{name:"Close console",exact:true}).click();
    await page.getByRole("alert").filter({hasText:/Console closed/}).waitFor();
    assert.deepEqual(errors,[]);
    console.log("Analyst browser workflow passed: sample, notes, handoff, local collection, report downloads, source isolation and close.");
  } finally {
    if(browser)await browser.close();if(!exited)child.kill("SIGTERM");fs.rmSync(temp,{recursive:true,force:true});
  }
})().catch((e)=>{console.error(e);process.exitCode=1;});
