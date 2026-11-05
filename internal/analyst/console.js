"use strict";
(() => {
  const $ = (id) => document.getElementById(id);
  let info, selected = "quick", busy = false, closed = false, jobText = "";
  function el(tag, text, cls) { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (cls) n.className = cls; return n; }
  function error(message) { $("error").textContent = message; $("error").hidden = !message; }
  async function api(path, value) {
    const response = await fetch(path, value === undefined ? { cache:"no-store" } : { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(value) });
    if (!response.ok) throw new Error((await response.text()).trim());
    return response.json();
  }
  function controls() { $("start").disabled = !info || busy || closed || !$("confirm").checked; $("close").disabled = busy || closed; }
  function choose(id) {
    selected = id;
    for (const b of $("profiles").children) b.setAttribute("aria-pressed", String(b.dataset.id === id));
    $("scope").textContent = info.profiles.find((p) => p.id === id).collectors.join(", ");
  }
  function link(text, href, view = false) { const a = el("a", text, "button"); a.href = href; if (view) { a.target = "_blank"; a.rel = "noopener"; } return a; }
  function showJobs(jobs) {
    jobs = jobs || [];
    busy = jobs.some((j) => j.state === "running" || j.state === "stopping"); controls();
    const text = JSON.stringify(jobs); if (text === jobText) return; jobText = text;
    $("session-count").textContent = jobs.length + (jobs.length === 1 ? " collection" : " collections");
    if (!jobs.length) return;
    $("jobs").replaceChildren();
    for (const j of [...jobs].reverse()) {
      const card = el("article", undefined, "job " + j.state);
      const top = el("div", undefined, "job-top");
      const names = el("div"); names.append(el("h3", j.case || j.profile), el("p", j.profile + " · " + new Date(j.started).toLocaleString()));
      const status = { running:"Collecting", stopping:"Stopping · keeping partial evidence", complete:"Collection complete", partial:"Partial collection · check gaps", failed:"Collection failed" }[j.state] || j.state;
      top.append(names, el("span", status, "badge")); card.append(top);
      const active = ["running", "stopping"].includes(j.state);
      const progress = el("progress"); progress.max = Math.max(j.total, 1); progress.value = j.completed.length; progress.setAttribute("aria-label", `${j.completed.length} of ${j.total} collectors finished`); card.append(progress);
      const counts = `${j.completed.length} of ${j.total} collectors finished`;
      const message = active ? counts + ". Finalizing the report can take a moment after collection." : `${counts}. ${j.findings} findings. A completed collection still needs analyst review.`;
      const line = el("p", message); line.setAttribute("role", "status"); card.append(line);
      if (j.state === "partial") card.append(el("p", "The report contains collector errors or an interrupted run. Open Start here to review coverage before drawing conclusions."));
      if (j.error) card.append(el("p", j.error, "notice"));
      const actions = el("div", undefined, "actions");
      if (j.state === "running") {
        const stop = el("button", "Stop and keep partial report"); stop.type = "button";
        stop.onclick = async () => { stop.disabled = true; try { await api(`api/jobs/${j.id}/cancel`, {}); await refresh(); } catch (e) { error(e.message); stop.disabled=false; } };
        actions.append(stop);
      }
      if (["complete", "partial"].includes(j.state)) {
        actions.append(link("Review findings", `api/jobs/${j.id}/report.html#review`, true), link("Save HTML report", `api/jobs/${j.id}/report.html?download=1`), link("Save JSON", `api/jobs/${j.id}/report.json`), link("Save JSON checksum", `api/jobs/${j.id}/checksum`));
        const details = el("details"); details.append(el("summary", "Saved report and collector results"), el("p", j.path));
        const list = el("ul", undefined, "results"); for (const c of j.completed) list.append(el("li", `${c.name}: ${c.records} records, ${c.errors} collection errors`)); details.append(list); card.append(details);
      }
      card.append(actions); $("jobs").append(card);
    }
  }
  async function refresh() { showJobs(await api("api/jobs")); }
  $("confirm").onchange = controls;
  $("start").onclick = async () => {
    busy = true; controls(); error("");
    try { await api("api/jobs", { profile:selected, case:$("case-label").value }); $("confirm").checked=false; await refresh(); $("history").scrollIntoView({behavior:"smooth",block:"start"}); }
    catch (e) { busy=false; controls(); error(e.message); }
  };
  $("close").onclick = async () => {
    try { await api("api/close", {}); closed=true; controls(); error("Console closed. Saved reports remain in the report folder shown below. You can close this browser tab."); }
    catch (e) { error(e.message); }
  };
  async function init() {
    try {
      info = await api("api/info");
      $("machine").replaceChildren();
      for (const [label,value] of [["Host",info.host],["Platform",`${info.os} · ${info.arch}`],["Elevated",info.elevated === "true" ? "Yes" : info.elevated === "false" ? "No" : "Unknown"]]) $("machine").append(el("dt",label),el("dd",value));
      $("elevation").textContent = info.elevated === "true" ? "Elevated collection is available. Check coverage in the report for any remaining gaps." : "Protected artifacts may be unavailable. For broader coverage on Windows, close this console and run Start-LRNG.cmd as administrator, then open a new session.";
      if (info.os !== "windows" && info.elevated !== "true") $("elevation").textContent = "Protected artifacts may be unavailable. Run the launcher with your approved elevated workflow if broader coverage is needed.";
      $("storage").textContent = "Reports saved in: " + info.directory + ". Session history is kept in memory; saved report files remain after you close the console.";
      $("version").textContent = info.version;
      for (const p of info.profiles) {
        const b=el("button",undefined,"profile"); b.type="button"; b.dataset.id=p.id; b.disabled=!p.collectors.length; b.append(el("strong",p.name),el("span",p.description)); b.onclick=()=>choose(p.id); $("profiles").append(b);
      }
      choose(selected); controls(); await refresh();
    } catch (e) { error("Could not load the local console: " + e.message); }
  }
  init();
  setInterval(async () => { if (closed || document.hidden) return; try { await refresh(); } catch (e) { error("Cannot reach the local console. If it stopped, saved reports remain on disk. " + e.message); } }, 1200);
})();
