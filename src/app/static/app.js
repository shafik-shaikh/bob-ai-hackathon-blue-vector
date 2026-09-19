"use strict";

const $ = (s, r = document) => r.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const num = (n) => Number(n).toLocaleString();
const pct = (x, d = 1) => (x * 100).toFixed(d) + "%";
const f3 = (x) => Number(x).toFixed(3);
const sum = (a) => a.reduce((s, v) => s + v, 0);

let R = null;          // current result
let threshold = 0.5;   // slider value

/* ---------- upload ---------- */
const drop = $("#drop"), fileInput = $("#file");
fileInput.addEventListener("change", () => fileInput.files[0] && analyse(fileInput.files[0]));
drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileInput.click(); } });
["dragenter", "dragover"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add("over"); }));
["dragleave", "drop"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
drop.addEventListener("drop", (e) => e.dataTransfer.files[0] && analyse(e.dataTransfer.files[0]));
document.querySelectorAll("[data-sample]").forEach((b) => b.addEventListener("click", () => analyse(null, b.dataset.sample)));

async function analyse(file, sample) {
  const label = file ? `${file.name} (${(file.size / 1048576).toFixed(1)} MB)` : sample;
  if (typeof stopStory === "function") stopStory();
  setStatus(`<span class="spin"></span>Scoring ${esc(label)} …`);
  $("#results").hidden = true;
  try {
    let res;
    if (file) {
      const fd = new FormData();
      fd.append("file", file);
      res = await fetch("/api/predict", { method: "POST", body: fd });
    } else {
      res = await fetch(`/api/predict/sample/${encodeURIComponent(sample)}`, { method: "POST" });
    }
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.detail || `HTTP ${res.status}`);
    R = body;
    threshold = R.threshold;
    setStatus("");
    renderResult();
  } catch (err) {
    setStatus(esc(err.message), true);
  } finally {
    fileInput.value = "";
  }
}

function setStatus(html, isErr = false) {
  const el = $("#status");
  el.hidden = !html;
  el.className = "status" + (isErr ? " err" : "");
  el.innerHTML = html;
}

/* ---------- threshold maths (from 100-bin histograms) ---------- */
const cutBin = (t) => Math.min(100, Math.max(0, Math.ceil(t * 100 - 1e-9)));
const atServer = (t) => Math.abs(t - R.threshold) < 1e-9;

function confusion(t) {
  if (atServer(t) && R.metrics && R.metrics.confusion) return R.metrics.confusion;
  const k = cutBin(t), m = R.metrics;
  return { tp: sum(m.hist_pos.slice(k)), fn: sum(m.hist_pos.slice(0, k)), fp: sum(m.hist_neg.slice(k)), tn: sum(m.hist_neg.slice(0, k)) };
}
function flaggedCount(t) {
  return atServer(t) ? R.summary.flagged : sum(R.summary.hist_all.slice(cutBin(t)));
}
function rates(c) {
  const p = c.tp + c.fp ? c.tp / (c.tp + c.fp) : 0, r = c.tp + c.fn ? c.tp / (c.tp + c.fn) : 0;
  return { precision: p, recall: r, f1: p + r ? (2 * p * r) / (p + r) : 0, fpr: c.fp + c.tn ? c.fp / (c.fp + c.tn) : 0 };
}

/* ---------- rendering ---------- */
function renderResult() {
  const { summary: s, metrics: m } = R;
  const labelled = m && m.roc_auc !== undefined;
  const cats = labelled && m.by_category ? m.by_category : [];
  $("#results").innerHTML = `
    <div class="filebar">
      <div><h2>${esc(R.filename)}</h2><small>${num(R.rows)} events · scored in ${R.seconds}s · ${R.columns.found}/${R.columns.expected} model columns found</small></div>
      <a class="btn ghost" href="/api/results/${R.id}/predictions.csv">Download predictions (CSV)</a>
    </div>
    ${R.warnings.map((w) => `<div class="warn">${esc(w)}</div>`).join("")}
    <div class="viewtabs"><button class="vt on" data-view="story">▶ Step-by-step walkthrough</button><button class="vt" data-view="full">Full statistics</button></div>
    <div id="story"></div>
    <div id="full" hidden>
    ${m && m.note ? `<div class="warn">${esc(m.note)}</div>` : ""}
    <div class="card slider">
      <strong>Flag events with score ≥</strong>
      <input id="thr" type="range" min="0" max="1" step="any" value="${threshold}">
      <b id="thrv"></b>
      <button class="link" id="thr-reset">reset to model default (${R.default_threshold.toFixed(2)})</button>
      <small>Moves at 0.01 resolution. Lower = catches more, more false alarms.</small>
    </div>
    <div id="live"></div>
    <div class="grid" style="margin-top:14px">
      ${labelled ? `<div class="card wide"><h3>Detection by attack type <small>at threshold ${R.threshold.toFixed(2)}</small></h3><div id="cats"></div></div>` : ""}
      <div class="card wide"><h3>Flagged events over time <small>red = flagged, grey = all</small></h3>${timelineSvg(s.timeline)}</div>
      <div class="card"><h3>Flag rate by protocol</h3>${rateBars(s.by_proto)}</div>
      <div class="card"><h3>Flag rate by service</h3>${rateBars(s.by_service)}</div>
      <div class="card"><h3>Top flagged sources</h3>${countBars(s.top_sources)}</div>
      <div class="card"><h3>Top flagged destination ports</h3>${countBars(s.top_ports)}</div>
    </div>
    <h2>Most suspicious events <small style="color:var(--muted);font-weight:400">top ${R.top.length}, highest score first</small></h2>
    <div class="card tbl">${topTable()}</div></div>`;
  $("#results").hidden = false;
  renderCats();

  const slider = $("#thr");
  slider.addEventListener("input", () => { threshold = +slider.value; renderLive(); });
  $("#thr-reset").addEventListener("click", () => { threshold = R.default_threshold; slider.value = threshold; renderLive(); });
  const more = $("#more");
  if (more) more.addEventListener("click", () => { document.querySelectorAll("tr.more").forEach((r) => (r.hidden = false)); more.remove(); });
  renderLive();
  document.querySelectorAll(".vt").forEach((b) => b.addEventListener("click", () => showView(b.dataset.view)));
  renderStory($("#story"), R);
  $("#results").scrollIntoView({ behavior: "smooth", block: "start" });
}

function showView(view) {
  document.querySelectorAll(".vt").forEach((b) => b.classList.toggle("on", b.dataset.view === view));
  $("#story").hidden = view !== "story";
  $("#full").hidden = view !== "full";
  if (view === "story") renderStory($("#story"), R);
  else stopStory();
  $(".viewtabs").scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderLive() {
  $("#thrv").textContent = threshold.toFixed(2);
  const { summary: s, metrics: m } = R;
  const labelled = m && m.roc_auc !== undefined;
  const flagged = flaggedCount(threshold);
  const kpis = [`<div class="kpi"><span>Events</span><b>${num(R.rows)}</b></div>`,
    `<div class="kpi bad"><span>Flagged malicious</span><b>${num(flagged)}</b><em>${pct(flagged / R.rows)} of events</em></div>`];
  let side = "";
  if (labelled) {
    const c = confusion(threshold), r = rates(c);
    kpis.push(`<div class="kpi"><span>Precision</span><b>${pct(r.precision)}</b><em>flagged that were real</em></div>`,
      `<div class="kpi"><span>Recall</span><b>${pct(r.recall)}</b><em>attacks caught</em></div>`,
      `<div class="kpi"><span>F1</span><b>${f3(r.f1)}</b></div>`,
      `<div class="kpi"><span>ROC-AUC</span><b>${f3(m.roc_auc)}</b><em>threshold-free</em></div>`,
      `<div class="kpi"><span>PR-AUC</span><b>${f3(m.pr_auc)}</b><em>base rate ${pct(m.prevalence)}</em></div>`);
    side = `
      <div class="card"><h3>Confusion matrix</h3>${confusionHtml(c)}</div>
      <div class="card"><h3>ROC curve <small>AUC ${f3(m.roc_auc)}</small></h3>${lineSvg(m.roc_curve, [r.fpr, r.recall], "false positive rate", "true positive rate", true)}</div>
      <div class="card"><h3>Precision–recall <small>AP ${f3(m.pr_auc)}</small></h3>${lineSvg(m.pr_curve, [r.recall, r.precision], "recall", "precision", false)}</div>`;
  } else {
    kpis.push(`<div class="kpi"><span>Mean score</span><b>${f3(s.mean_score)}</b></div>`,
      `<div class="kpi"><span>No labels</span><b style="font-size:14px">Score-only mode</b><em>add a <code>label</code> column for accuracy stats</em></div>`);
  }
  $("#live").innerHTML = `<div class="kpis">${kpis.join("")}</div>
    <div class="grid g2">
      <div class="card ${labelled ? "" : "wide"}"><h3>Score distribution <small>log scale</small></h3>${histSvg()}
        <div class="legend">${labelled ? `<span><i style="background:var(--good)"></i>benign</span><span><i style="background:var(--bad)"></i>malicious</span>` : `<span><i style="background:var(--accent)"></i>all events</span>`}<span>│ threshold</span></div></div>
      ${side}</div>`;
}

function renderCats() {
  const el = $("#cats");
  if (!el) return;
  const rows = R.metrics.by_category || [];
  if (!rows.length) { el.innerHTML = `<div class="empty">No attack_cat column in this file.</div>`; return; }
  el.innerHTML = `<div class="bars">${rows.map((c) => `<div class="bar"><span class="k" title="${esc(c.category)}">${esc(c.category)}</span>
      <span class="track"><span class="fill good" style="display:block;width:${c.recall * 100}%"></span></span>
      <span class="v">${pct(c.recall, 0)} of ${num(c.count)}</span></div>`).join("")}</div>`;
}

function confusionHtml(c) {
  return `<div class="cm">
    <span></span><span class="h">predicted benign</span><span class="h">predicted malicious</span>
    <span class="h">actually benign</span><div class="good"><b>${num(c.tn)}</b>true negative</div><div class="bad"><b>${num(c.fp)}</b>false alarm</div>
    <span class="h">actually malicious</span><div class="bad"><b>${num(c.fn)}</b>missed attack</div><div class="good"><b>${num(c.tp)}</b>true positive</div></div>`;
}

/* ---------- charts ---------- */
function histSvg() {
  const W = 460, H = 190, L = 34, B = 22, T = 8, plotW = W - L - 8, plotH = H - B - T;
  const rebin = (a) => Array.from({ length: 50 }, (_, i) => a[2 * i] + a[2 * i + 1]);
  const m = R.metrics && R.metrics.hist_pos ? R.metrics : null;
  const series = m ? [[rebin(m.hist_neg), "var(--good)", 0.85], [rebin(m.hist_pos), "var(--bad)", 0.75]] : [[rebin(R.summary.hist_all), "var(--accent)", 0.9]];
  const top = Math.log10(1 + Math.max(...series.flatMap(([a]) => a), 1));
  const bw = plotW / 50;
  let out = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="score distribution">`;
  for (let g = 0; g <= Math.floor(top); g++) {
    const y = T + plotH - (g / top) * plotH;
    out += `<line x1="${L}" x2="${W - 8}" y1="${y}" y2="${y}" stroke="#eceef4"/><text x="${L - 5}" y="${y + 3}" text-anchor="end">${num(Math.pow(10, g))}</text>`;
  }
  for (const [data, colour, op] of series) {
    data.forEach((v, i) => {
      const h = (Math.log10(1 + v) / top) * plotH;
      if (h > 0) out += `<rect x="${L + i * bw + 0.5}" y="${T + plotH - h}" width="${bw - 1}" height="${h}" fill="${colour}" opacity="${op}"/>`;
    });
  }
  const x = L + threshold * plotW;
  out += `<line x1="${x}" x2="${x}" y1="${T}" y2="${T + plotH}" stroke="var(--ink)" stroke-dasharray="4 3"/>`;
  for (const v of [0, 0.25, 0.5, 0.75, 1]) out += `<text x="${L + v * plotW}" y="${H - 6}" text-anchor="middle">${v}</text>`;
  return out + "</svg>";
}

function lineSvg(points, marker, xl, yl, diagonal) {
  const W = 340, H = 230, L = 40, B = 30, T = 8, R_ = 10, w = W - L - R_, h = H - B - T;
  const px = (x) => L + x * w, py = (y) => T + (1 - y) * h;
  let out = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${yl} vs ${xl}">`;
  for (const v of [0, 0.5, 1]) {
    out += `<line x1="${L}" x2="${W - R_}" y1="${py(v)}" y2="${py(v)}" stroke="#eceef4"/><text x="${L - 5}" y="${py(v) + 3}" text-anchor="end">${v}</text>`;
    out += `<text x="${px(v)}" y="${H - B + 14}" text-anchor="middle">${v}</text>`;
  }
  if (diagonal) out += `<line x1="${px(0)}" y1="${py(0)}" x2="${px(1)}" y2="${py(1)}" stroke="#c7ccd9" stroke-dasharray="4 3"/>`;
  out += `<polyline fill="none" stroke="var(--accent)" stroke-width="2" points="${points.map(([x, y]) => `${px(x)},${py(y)}`).join(" ")}"/>`;
  out += `<circle cx="${px(marker[0])}" cy="${py(marker[1])}" r="5" fill="var(--bad)" stroke="#fff" stroke-width="2"/>`;
  out += `<text x="${L + w / 2}" y="${H - 4}" text-anchor="middle">${xl}</text>`;
  return out + `<text transform="translate(9 ${T + h / 2}) rotate(-90)" text-anchor="middle">${yl}</text></svg>`;
}

function timelineSvg(tl) {
  if (!tl || !tl.length) return `<div class="empty">No usable timestamp (stime) column, so no timeline.</div>`;
  const W = 940, H = 150, L = 40, B = 22, T = 6, bw = (W - L - 8) / tl.length, plotH = H - B - T;
  const max = Math.max(...tl.map((b) => b.events), 1);
  let out = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="flagged events over time">`;
  out += `<text x="${L - 5}" y="${T + 8}" text-anchor="end">${num(max)}</text><text x="${L - 5}" y="${T + plotH}" text-anchor="end">0</text>`;
  tl.forEach((b, i) => {
    const h1 = (b.events / max) * plotH, h2 = (b.flagged / max) * plotH;
    out += `<rect x="${L + i * bw + 1}" y="${T + plotH - h1}" width="${bw - 2}" height="${h1}" fill="#dfe3ee"><title>${num(b.events)} events, ${num(b.flagged)} flagged</title></rect>`;
    if (h2 > 0) out += `<rect x="${L + i * bw + 1}" y="${T + plotH - h2}" width="${bw - 2}" height="${h2}" fill="var(--bad)"/>`;
  });
  const fmt = (t) => new Date(t * 1000).toISOString().replace("T", " ").slice(0, 16) + " UTC";
  out += `<text x="${L}" y="${H - 5}">${fmt(tl[0].t)}</text><text x="${W - 8}" y="${H - 5}" text-anchor="end">${fmt(tl[tl.length - 1].t)}</text>`;
  return out + "</svg>";
}

function rateBars(rows) {
  if (!rows || !rows.length) return `<div class="empty">Column not in file.</div>`;
  return `<div class="bars">${rows.map((r) => `<div class="bar"><span class="k" title="${esc(r.value)}">${esc(r.value)}</span>
    <span class="track"><span class="fill bad" style="display:block;width:${Math.max(r.rate * 100, r.flagged ? 1.5 : 0)}%"></span></span>
    <span class="v">${num(r.flagged)} / ${num(r.events)}</span></div>`).join("")}</div>`;
}

function countBars(rows) {
  if (!rows || !rows.length) return `<div class="empty">Nothing flagged, or column not in file.</div>`;
  const max = Math.max(...rows.map((r) => r.flagged), 1);
  return `<div class="bars">${rows.map((r) => `<div class="bar"><span class="k mono" title="${esc(r.value)}">${esc(r.value)}</span>
    <span class="track"><span class="fill" style="display:block;width:${(r.flagged / max) * 100}%"></span></span>
    <span class="v">${num(r.flagged)}</span></div>`).join("")}</div>`;
}

function topTable() {
  const labelled = R.labelled;
  const head = `<tr><th>Row</th><th>Score</th><th>Source → destination</th><th>Proto / service</th>${labelled ? "<th>Ground truth</th>" : ""}<th>Why it scored high</th></tr>`;
  const rows = R.top.map((e, i) => {
    const truth = e.label === undefined ? "" : e.label === 1 ? `<span class="tag ok">attack${e.attack_cat && e.attack_cat !== "Normal" ? " · " + esc(e.attack_cat) : ""}</span>` : `<span class="tag no">false alarm</span>`;
    const why = e.reasons.map((r) => `<span class="chip">${esc(r.feature)} = ${esc(r.value)}<i>+${r.push}</i></span>`).join("");
    const dst = e.dstip ? `${esc(e.dstip)}${e.dsport ? ":" + esc(e.dsport) : ""}` : e.dsport ? "port " + esc(e.dsport) : "—";
    return `<tr${i >= 25 ? ' class="more" hidden' : ""}><td>${e.row}</td><td><span class="score">${e.score.toFixed(3)}</span></td>
      <td class="mono">${esc(e.srcip ?? "—")}${e.sport ? ":" + esc(e.sport) : ""} → ${dst}</td>
      <td>${esc(e.proto ?? "—")} / ${esc(e.service ?? "—")}</td>${labelled ? `<td>${truth}</td>` : ""}<td>${why || "—"}</td></tr>`;
  });
  return `<table><thead>${head}</thead><tbody>${rows.join("")}</tbody></table>${R.top.length > 25 ? `<p style="text-align:center;margin:12px 0 0"><button class="link" id="more">Show all ${R.top.length}</button></p>` : ""}`;
}

/* ---------- tabs + model page ---------- */
document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => {
  document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("on", x === t));
  $("#tab-analyse").hidden = t.dataset.tab !== "analyse";
  $("#tab-model").hidden = t.dataset.tab !== "model";
  if (t.dataset.tab === "model") loadModel();
}));

let modelLoaded = false;
async function loadModel() {
  if (modelLoaded) return;
  const el = $("#tab-model");
  el.innerHTML = `<div class="status"><span class="spin"></span>Loading model details …</div>`;
  try {
    const m = await (await fetch("/api/model")).json();
    const t = m.test;
    const cm = t.confusion;
    el.innerHTML = `
      <div class="filebar"><div><h2>${esc(m.name)}</h2><small>${esc(m.algorithm)} · trained ${esc(m.trained_at)}</small></div></div>
      <p style="color:var(--muted);margin:4px 0 12px">Data: ${esc(m.data_source)}. Trained on ${num(m.train_rows)} flows (${pct(m.train_attack_rate)} attacks), tuned on ${num(m.validation_rows)}, and scored on a <b>later capture it never saw</b>: ${num(m.test_rows)} flows (${pct(m.test_attack_rate)} attacks).</p>
      <div class="kpis">
        <div class="kpi"><span>ROC-AUC</span><b>${f3(t.roc_auc)}</b></div><div class="kpi"><span>PR-AUC</span><b>${f3(t.pr_auc)}</b></div>
        <div class="kpi"><span>Precision</span><b>${pct(t.precision)}</b></div><div class="kpi"><span>Recall</span><b>${pct(t.recall)}</b></div>
        <div class="kpi"><span>F1</span><b>${f3(t.f1)}</b></div><div class="kpi"><span>False-alarm rate</span><b>${pct(t.fpr, 2)}</b><em>of benign flows</em></div></div>
      <div class="grid">
        <div class="card"><h3>Confusion matrix <small>held-out capture, threshold ${m.threshold.toFixed(2)}</small></h3>${confusionHtml(cm)}</div>
        <div class="card"><h3>Recall by attack type <small>held-out</small></h3><div class="bars">${t.by_category.map((c) => `<div class="bar"><span class="k">${esc(c.category)}</span><span class="track"><span class="fill good" style="display:block;width:${c.recall * 100}%"></span></span><span class="v">${pct(c.recall, 0)} of ${num(c.count)}</span></div>`).join("")}</div></div>
        <div class="card"><h3>What the model looks at most <small>share of total gain</small></h3><div class="bars">${m.feature_importance.slice(0, 10).map((f) => `<div class="bar"><span class="k" title="${esc(f.feature)}">${esc(f.feature)}</span><span class="track"><span class="fill" style="display:block;width:${f.share * 100 / m.feature_importance[0].share}%"></span></span><span class="v">${pct(f.share)}</span></div>`).join("")}</div></div>
        <div class="card"><h3>How easy is this data? <small>held-out ROC-AUC / PR-AUC</small></h3>
          <table class="abl"><thead><tr><th>Model uses</th><th>ROC-AUC</th><th>PR-AUC</th></tr></thead><tbody>${m.ablation.map((a) => `<tr><td>${esc(a.variant)}</td><td>${f3(a.roc_auc)}</td><td>${f3(a.pr_auc)}</td></tr>`).join("")}</tbody></table>
          <ul class="list"><li>Even one field (source TTL) separates most attacks here, and removing all TTL fields changes nothing. That is how clean this lab traffic is.</li></ul></div>
        <div class="card wide"><h3>Read this before trusting the numbers</h3><ul class="list">${m.caveats.map((c) => `<li>${esc(c)}</li>`).join("")}<li>Default threshold: ${esc(m.threshold_rule)} (${m.threshold.toFixed(3)}).</li></ul></div>
      </div>`;
    modelLoaded = true;
  } catch (err) {
    el.innerHTML = `<div class="status err">${esc(err.message)}</div>`;
  }
}
