"use strict";
/* Step-by-step walkthrough of what the model did with the uploaded file.
   Every number shown comes from the real run (see app/story.py); nothing here is illustrative. */

const REDUCED = !!(window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches);
const sleep = (ms) => new Promise((r) => setTimeout(r, REDUCED ? 0 : ms));
const sigmoid = (x) => 1 / (1 + Math.exp(-x));
const int = (v) => num(Math.round(v));
const pctSmart = (p) => (p * 100).toFixed(p < 0.1 || p > 0.9 ? 1 : 0) + "%";
const bytesText = (b) => (b >= 1048576 ? (b / 1048576).toFixed(1) + " MB" : Math.max(1, Math.round(b / 1024)) + " KB");
const svgEl = (root, sel) => root.querySelector(sel);

let storyRun = 0;      // bumped on every step change so stale animations stop themselves
let stopCurrent = () => {};
function stopStory() { storyRun++; stopCurrent(); }

function countUp(el, to, ms, fmt = int, run = storyRun) {
  if (!el) return;
  if (REDUCED) { el.textContent = fmt(to); return; }
  const t0 = performance.now();
  const tick = (t) => {
    if (run !== storyRun) return;
    const p = Math.min(1, (t - t0) / ms);
    el.textContent = fmt(to * (1 - Math.pow(1 - p, 3)));
    if (p < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

const head = (n, title, text) => `<div class="st-head"><span class="st-num">${n}</span><div><h3>${title}</h3><p>${text}</p></div></div>`;
const evLine = (e) => `${esc(e.srcip ?? "?")}${e.sport ? ":" + esc(e.sport) : ""} → ${esc(e.dstip ?? "?")}${e.dsport ? ":" + esc(e.dsport) : ""}`;
const truthTag = (e) => e.label === undefined ? "" : e.label === 1
  ? `<span class="tag ok">really an attack${e.attack_cat && e.attack_cat !== "Normal" ? " · " + esc(e.attack_cat) : ""}</span>`
  : `<span class="tag no">really normal</span>`;

/* ---------------- steps ---------------- */
const STEPS = [
  {
    title: "Data received", hold: 6500,
    html(S, R) {
      const I = S.input;
      const rows = I.preview.map((r, i) => `<tr class="rowin" style="--d:${0.5 + i * 0.28}s">${I.preview_cols.map((c) => `<td class="mono">${esc(r[c])}</td>`).join("")}</tr>`).join("");
      return head(1, "Data received", "This is your file exactly as uploaded. Nothing has been changed yet.") + `
        <div class="two">
          <div class="filecard pop">
            <div class="doc"><span>${esc(I.format)}</span></div>
            <b class="fname">${esc(R.filename)}</b>
            <div class="badges">
              <span class="b">${bytesText(I.bytes)}</span>
              <span class="b"><i data-count="${I.rows}">0</i> events</span>
              <span class="b">${I.columns} columns</span>
              <span class="b ${I.labelled ? "ok" : ""}">${I.labelled ? "has ground-truth labels" : "no labels"}</span>
            </div>
            ${I.headerless ? `<p class="note">No header row found, so the original UNSW-NB15 column order was recognised.</p>` : ""}
          </div>
          <div class="preview pop" style="--d:.2s"><h4>First ${I.preview.length} rows</h4>
            <div class="tbl"><table><thead><tr>${I.preview_cols.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead><tbody>${rows}</tbody></table></div></div>
        </div>`;
    },
    after(stage, S, R, run) { countUp(svgEl(stage, "[data-count]"), S.input.rows, 1100, int, run); },
  },
  {
    title: "Columns matched", hold: 7500,
    html(S) {
      const M = S.mapping, total = M.found.length + M.missing.length;
      const chips = [...M.found.map((n) => [n, true]), ...M.missing.map((n) => [n, false])]
        .map(([n, ok], i) => `<span class="chip2 ${ok ? "ok" : "no"}" style="--d:${0.2 + i * 0.03}s">${esc(n)}</span>`).join("");
      const cats = ["proto", "service", "state"].map((c, i) => `<span class="chip2 cat ${M.categorical_found.includes(c) ? "ok" : "no"}" style="--d:${1.5 + i * 0.1}s">${c}</span>`).join("");
      const ren = M.renamed.length ? `<p class="mini pop" style="--d:1.9s">Renamed to match: ${M.renamed.map((r) => `<span class="chip2 ren">${esc(r.from)} → ${esc(r.to)}</span>`).join(" ")}</p>` : "";
      const disp = M.display_only.length ? `<p class="mini pop" style="--d:2.1s">Kept for display only, <b>not</b> used by the model: ${M.display_only.map((c) => `<span class="chip2 dim">${esc(c)}</span>`).join(" ")}
        <span class="fine">IPs and timestamps identify the lab testbed, not the behaviour, so using them would inflate scores without teaching the model anything real.</span></p>` : "";
      return head(2, "Columns matched", `The model reads ${total} flow measurements and 3 categories. Each column in your file is matched by name.`) + `
        <div class="matchbar pop"><b><i data-count="${M.found.length}">0</i> / ${total}</b> measurements found${M.missing.length ? ` <span class="warnpill">${M.missing.length} missing → treated as unknown</span>` : ""}</div>
        <div class="chips">${chips}</div><div class="chips cats">${cats}</div>${ren}${disp}`;
    },
    after(stage, S, R, run) { countUp(svgEl(stage, "[data-count]"), S.mapping.found.length, 1300, int, run); },
  },
  {
    title: "Features built", hold: 7500,
    html(S) {
      const F = S.features, e = S.attack;
      const groups = [];
      F.vector.forEach((c) => { const last = groups[groups.length - 1]; if (last && last.g === c.g) last.items.push(c); else groups.push({ g: c.g, items: [c] }); });
      let idx = 0;
      const blocks = groups.map((grp) => `<div class="fgroup"><span class="fname2">${grp.g === "numeric" ? `${grp.items.length} measurements` : `${esc(grp.g)} · ${grp.items.length} switches`}</span>
        <div class="cells">${grp.items.map((c) => {
          const on = grp.g !== "numeric" && c.v === 1;
          const shade = grp.g === "numeric" ? (c.v === null ? "miss" : "") : on ? "on" : "off";
          const alpha = grp.g === "numeric" && c.v !== null ? Math.min(1, 0.15 + Math.log10(1 + Math.abs(c.v)) / 8) : 1;
          return `<i class="cell ${shade}" style="--d:${0.4 + idx++ * 0.018}s;--a:${alpha}" title="${esc(c.n)} = ${c.v === null ? "missing" : c.v}"></i>`;
        }).join("")}</div></div>`).join("");
      const lit = F.vector.filter((c) => c.g !== "numeric" && c.v === 1).map((c) => c.n.replace("=", " = "));
      return head(3, "Features built", `The model can't read text. Each event becomes a row of <b>${F.count} numbers</b>. Below: the highest-scoring event in your file.`) + `
        <div class="evcard pop"><b class="mono">${evLine(e)}</b><span>${esc(e.proto ?? "")} / ${esc(e.service ?? "")}</span>${truthTag(e)}</div>
        <div class="fvec">${blocks}</div>
        <p class="mini pop" style="--d:2.2s">Text categories become on/off switches, one lit per group: ${lit.map((l) => `<span class="chip2 on">${esc(l)}</span>`).join(" ")}
          <span class="fine">Each square is one number the model reads; darker = larger.</span></p>`;
    },
  },
  {
    title: "Trees vote", hold: 8000,
    html(S) {
      const T = S.model.trees;
      const W = 780, H = 300, L = 58, R_ = 150, Tp = 16, B = 38, w = W - L - R_, h = H - Tp - B;
      const all = [...S.attack.trace, ...S.normal.trace, 0];
      const lo = Math.min(...all) - 0.8, hi = Math.max(...all) + 0.8;
      const px = (k) => L + ((k - 1) / (T - 1)) * w, py = (v) => Tp + (1 - (v - lo) / (hi - lo)) * h;
      const ticks = [-8, -6, -4, -2, 0, 2, 4, 6, 8].filter((v) => v > lo && v < hi);
      let svg = `<svg id="tsvg" viewBox="0 0 ${W} ${H}" role="img" aria-label="score growing tree by tree">`;
      ticks.forEach((v) => { svg += `<line x1="${L}" x2="${W - R_}" y1="${py(v)}" y2="${py(v)}" stroke="${v === 0 ? "#9aa3b8" : "#eceef4"}" ${v === 0 ? 'stroke-dasharray="5 4"' : ""}/><text x="${L - 8}" y="${py(v) + 4}" text-anchor="end">${pctSmart(sigmoid(v))}</text>`; });
      svg += `<text x="${W - R_ + 8}" y="${py(0) + 4}">← 50%: the line between normal and attack</text>`;
      svg += `<text x="${L + w / 2}" y="${H - 6}" text-anchor="middle">trees added (1 → ${T})</text>`;
      svg += `<polyline id="pn" fill="none" stroke="var(--good)" stroke-width="3" stroke-linejoin="round" points=""/><polyline id="pa" fill="none" stroke="var(--bad)" stroke-width="3" stroke-linejoin="round" points=""/>`;
      svg += `<circle id="da" r="6" fill="var(--bad)" stroke="#fff" stroke-width="2" opacity="0"/><circle id="dn" r="6" fill="var(--good)" stroke="#fff" stroke-width="2" opacity="0"/></svg>`;
      return head(4, "Trees vote", `${T} small decision trees each look at the numbers and push the score up (attack) or down (normal). Watch two real events from your file; the curves are measured from the trained model.`) + `
        <div class="legend2 pop"><span><i style="background:var(--bad)"></i>Highest-scoring event <b class="mono">${evLine(S.attack)}</b> <em id="ra">50%</em></span>
          <span><i style="background:var(--good)"></i>Lowest-scoring event <b class="mono">${evLine(S.normal)}</b> <em id="rn">50%</em></span></div>
        <div class="tcount pop">tree <b id="tk">0</b> of ${T}</div>${svg}`;
    },
    async after(stage, S, R, run) {
      const A = S.attack.trace, N = S.normal.trace, T = A.length;
      const W = 780, H = 300, L = 58, R_ = 150, Tp = 16, B = 38, w = W - L - R_, h = H - Tp - B;
      const all = [...A, ...N, 0], lo = Math.min(...all) - 0.8, hi = Math.max(...all) + 0.8;
      const px = (k) => L + ((k - 1) / (T - 1)) * w, py = (v) => Tp + (1 - (v - lo) / (hi - lo)) * h;
      const draw = (k) => {
        svgEl(stage, "#pa").setAttribute("points", A.slice(0, k).map((v, i) => `${px(i + 1)},${py(v)}`).join(" "));
        svgEl(stage, "#pn").setAttribute("points", N.slice(0, k).map((v, i) => `${px(i + 1)},${py(v)}`).join(" "));
        svgEl(stage, "#tk").textContent = k;
        svgEl(stage, "#ra").textContent = pctSmart(sigmoid(A[k - 1]));
        svgEl(stage, "#rn").textContent = pctSmart(sigmoid(N[k - 1]));
      };
      await sleep(600);
      for (let k = 1; k <= T; k++) {
        if (run !== storyRun) return;
        if (REDUCED && k < T) continue;
        draw(k);
        await sleep(85);
      }
      if (run !== storyRun) return;
      [["da", A], ["dn", N]].forEach(([id, arr]) => {
        const d = svgEl(stage, "#" + id);
        d.setAttribute("cx", px(T)); d.setAttribute("cy", py(arr[T - 1])); d.setAttribute("opacity", 1);
      });
    },
  },
  {
    title: "Decision", hold: 7000,
    html(S, R) {
      const W = 780, H = 290, L = 44, B = 30, Tp = 12, plotW = W - L - 12, plotH = H - B - Tp;
      const hist = Array.from({ length: 50 }, (_, i) => R.summary.hist_all[2 * i] + R.summary.hist_all[2 * i + 1]);
      const top = Math.log10(1 + Math.max(...hist, 1)), bw = plotW / 50, thr = S.model.threshold;
      let svg = `<svg id="dsvg" viewBox="0 0 ${W} ${H}" role="img" aria-label="scores of all events and the threshold">`;
      svg += `<rect id="rl" x="${L}" y="${Tp}" width="${thr * plotW}" height="${plotH}" fill="var(--good-soft)" opacity="0"/><rect id="rr" x="${L + thr * plotW}" y="${Tp}" width="${(1 - thr) * plotW}" height="${plotH}" fill="var(--bad-soft)" opacity="0"/>`;
      for (let g = 0; g <= Math.floor(top); g++) { const y = Tp + plotH - (g / top) * plotH; svg += `<line x1="${L}" x2="${W - 12}" y1="${y}" y2="${y}" stroke="#eceef4"/><text x="${L - 6}" y="${y + 4}" text-anchor="end">${num(Math.pow(10, g))}</text>`; }
      hist.forEach((v, i) => { const bh = (Math.log10(1 + v) / top) * plotH; if (bh > 0) svg += `<rect class="hbar" x="${L + i * bw + 1}" y="${Tp + plotH - bh}" width="${bw - 2}" height="${bh}" fill="var(--accent)" style="--d:${0.15 + i * 0.03}s"/>`; });
      svg += `<g id="tl" style="transform:translateX(0);transition:transform 1.5s cubic-bezier(.5,0,.2,1)"><line x1="${L}" x2="${L}" y1="${Tp - 4}" y2="${Tp + plotH}" stroke="var(--ink)" stroke-width="2" stroke-dasharray="5 3"/><text x="${L + 6}" y="${Tp + 10}" style="fill:var(--ink);font-weight:600">threshold ${thr.toFixed(2)}</text></g>`;
      [0, 0.25, 0.5, 0.75, 1].forEach((v) => { svg += `<text x="${L + v * plotW}" y="${H - 8}" text-anchor="middle">${v}</text>`; });
      svg += `<text x="${L + plotW / 2}" y="${H}" text-anchor="middle" style="opacity:0">.</text></svg>`;
      return head(5, "Decision", `Every event ends with a score from 0 (normal) to 1 (attack). Anything at or above <b>${thr.toFixed(2)}</b> is flagged. That cut-off was picked on validation data to balance false alarms against missed attacks.`) + `
        ${svg}<div class="split"><div class="side good"><b id="cb">0</b><span>left alone as benign</span></div><div class="side bad"><b id="cf">0</b><span>flagged as malicious</span></div></div>`;
    },
    async after(stage, S, R, run) {
      const W = 780, L = 44, plotW = W - L - 12, thr = S.model.threshold;
      await sleep(1900);
      if (run !== storyRun) return;
      svgEl(stage, "#tl").style.transform = `translateX(${thr * plotW}px)`;
      await sleep(1300);
      if (run !== storyRun) return;
      svgEl(stage, "#rl").setAttribute("opacity", 1); svgEl(stage, "#rr").setAttribute("opacity", 1);
      countUp(svgEl(stage, "#cb"), R.rows - R.summary.flagged, 1100, int, run);
      countUp(svgEl(stage, "#cf"), R.summary.flagged, 1100, int, run);
    },
  },
  {
    title: "Why flagged", hold: 11000,
    html(S) {
      const E = S.explain, ev = S.attack;
      const seq = [{ label: `Starting point (${pctSmart(E.start_prob)} malicious)`, value: E.bias, start: true }]
        .concat(E.parts.map((p) => ({ label: `${p.feature} = ${p.value}`, value: p.push })))
        .concat(Math.abs(E.other) > 0.005 ? [{ label: "all other features", value: E.other }] : []);
      let cum = 0; const pts = seq.map((s, i) => { const a = i === 0 ? 0 : cum; cum = i === 0 ? s.value : cum + s.value; return { ...s, a, b: cum }; });
      const vals = pts.flatMap((p) => [p.a, p.b]).concat(0);
      const lo = Math.min(...vals) - 0.6, hi = Math.max(...vals) + 0.6, pos = (v) => ((v - lo) / (hi - lo)) * 100;
      const rows = pts.map((p, i) => {
        const l = Math.min(p.a, p.b), r = Math.max(p.a, p.b), up = p.value >= 0;
        return `<div class="wrow" style="--d:${0.6 + i * 0.75}s"><span class="wl" title="${esc(p.label)}">${esc(p.label)}</span>
          <span class="wt"><i class="zero" style="left:${pos(0)}%"></i><i class="wbar ${p.start ? "base" : up ? "up" : "down"}" style="left:${pos(l)}%;width:${Math.max(pos(r) - pos(l), 0.8)}%"></i></span>
          <span class="wv ${p.start ? "" : up ? "up" : "down"}">${p.start ? "" : up ? "+" : ""}${p.value.toFixed(2)}</span></div>`;
      }).join("");
      const end = 0.6 + pts.length * 0.75;
      return head(6, "Why flagged", "Why did the highest-scoring event score so high? These are the exact pushes from the model: red toward attack, green toward normal.") + `
        <div class="evcard pop"><b class="mono">${evLine(ev)}</b><span>${esc(ev.proto ?? "")} / ${esc(ev.service ?? "")}</span>${truthTag(ev)}</div>
        <div class="wf">${rows}</div>
        <div class="final pop" style="--d:${end}s"><span>Add it all up →</span><b id="fp">0%</b><span>chance this flow is malicious</span></div>
        <p class="fine pop" style="--d:${end + 0.3}s">Bars are in log-odds; the thin line marks 0 = 50%. Only the six biggest pushes are shown; the rest are grouped.</p>`;
    },
    after(stage, S, R, run) {
      const E = S.explain;
      setTimeout(() => countUp(svgEl(stage, "#fp"), E.prob * 100, 1200, (v) => v.toFixed(1) + "%", run), REDUCED ? 0 : (0.6 + (E.parts.length + 2) * 0.75) * 1000);
    },
  },
  {
    title: "Result", hold: 0,
    html(S, R) {
      const m = R.metrics, ok = m && m.roc_auc !== undefined;
      if (ok) {
        const c = m.confusion;
        const ring = (label, v, i) => `<div class="ring pop" style="--d:${1.2 + i * 0.2}s"><svg viewBox="0 0 100 100"><circle cx="50" cy="50" r="38" class="rt"/><circle cx="50" cy="50" r="38" class="rf" data-v="${v}"/></svg><b data-pct="${v * 100}">0%</b><span>${label}</span></div>`;
        return head(7, "Result", "Your file had labels, so the model's answers can be checked against the truth.") + `
          <div class="tiles">
            <div class="tile good pop"><b data-c="${c.tp}">0</b><span>attacks caught</span></div>
            <div class="tile bad pop" style="--d:.15s"><b data-c="${c.fp}">0</b><span>false alarms</span></div>
            <div class="tile bad pop" style="--d:.3s"><b data-c="${c.fn}">0</b><span>attacks missed</span></div>
            <div class="tile good pop" style="--d:.45s"><b data-c="${c.tn}">0</b><span>normal traffic left alone</span></div></div>
          <div class="rings">${ring("precision: flagged that were real", m.precision, 0)}${ring("recall: attacks caught", m.recall, 1)}${ring("F1: balance of both", m.f1, 2)}</div>
          <p class="verdict pop" style="--d:2s">Of <b>${num(R.rows)}</b> events it flagged <b>${num(R.summary.flagged)}</b>. <b>${num(c.tp)}</b> were real attacks and <b>${num(c.fn)}</b> attacks slipped through. ROC-AUC ${f3(m.roc_auc)}.</p>
          <p class="fine pop" style="--d:2.2s">This is lab traffic. A real network will score lower; the “About the model” tab shows how easy this data is.</p>${cta()}`;
      }
      const s = R.summary;
      return head(7, "Result", "This file has no label column, so accuracy can't be measured, but here is what the model found.") + `
        <div class="tiles">
          <div class="tile pop"><b data-c="${R.rows}">0</b><span>events scored</span></div>
          <div class="tile bad pop" style="--d:.15s"><b data-c="${s.flagged}">0</b><span>flagged as malicious</span></div>
          <div class="tile pop" style="--d:.3s"><b>${pct(s.flag_rate)}</b><span>of all events</span></div>
          <div class="tile pop" style="--d:.45s"><b>${s.top_sources[0] ? esc(s.top_sources[0].value) : "—"}</b><span>top flagged source</span></div></div>
        <p class="verdict pop" style="--d:1s">Add a <code>label</code> (0/1) or <code>attack_cat</code> column to see precision, recall and the confusion matrix.</p>${cta()}`;
      function cta() { return `<div class="cta pop" style="--d:2.4s"><button class="btn" id="go-full">Open full statistics →</button><button class="btn ghost" id="replay">Replay</button></div>`; }
    },
    after(stage, S, R, run) {
      stage.querySelectorAll("[data-c]").forEach((el) => countUp(el, +el.dataset.c, 1300, int, run));
      stage.querySelectorAll(".rf").forEach((c) => { const C = 2 * Math.PI * 38; c.style.strokeDasharray = C; c.style.strokeDashoffset = C; requestAnimationFrame(() => requestAnimationFrame(() => { c.style.strokeDashoffset = C * (1 - +c.dataset.v); })); });
      stage.querySelectorAll("[data-pct]").forEach((el) => setTimeout(() => countUp(el, +el.dataset.pct, 1200, (v) => v.toFixed(1) + "%", run), REDUCED ? 0 : 1200));
      const full = svgEl(stage, "#go-full"), replay = svgEl(stage, "#replay");
      if (full) full.addEventListener("click", () => showView("full"));
      if (replay) replay.addEventListener("click", () => showView("story"));
    },
  },
];

/* ---------------- controller ---------------- */
function renderStory(host, R) {
  stopStory();
  const S = R.story, N = STEPS.length;
  const state = { i: 0, playing: !REDUCED, timer: null };
  host.innerHTML = `<div class="story">
    <ol class="steps">${STEPS.map((s, i) => `<li><button data-i="${i}" aria-label="Step ${i + 1}: ${s.title}"><span class="dot">${i + 1}</span><span class="lbl">${s.title}</span></button></li>`).join("")}<div class="steps-line"><i id="sp"></i></div></ol>
    <div class="stage card"><div id="stage"></div></div>
    <div class="ctl"><button class="btn ghost sm" id="prev">← Back</button><button class="btn sm" id="play">${state.playing ? "❚❚ Pause" : "▶ Play"}</button><button class="btn ghost sm" id="next">Next →</button>
      <span class="hint" id="hint"></span><button class="link" id="skip">Skip to full statistics</button></div></div>`;
  const stage = $("#stage", host);

  function go(i, manual) {
    clearTimeout(state.timer);
    storyRun++;
    state.i = Math.max(0, Math.min(N - 1, i));
    if (manual) { state.playing = false; $("#play", host).textContent = "▶ Play"; }
    const step = STEPS[state.i], run = storyRun;
    stage.innerHTML = `<div class="stage-in">${step.html(S, R)}</div>`;
    host.querySelectorAll(".steps button").forEach((b) => {
      const n = +b.dataset.i;
      b.classList.toggle("active", n === state.i); b.classList.toggle("done", n < state.i);
    });
    $("#sp", host).style.width = `${(state.i / (N - 1)) * 100}%`;
    $("#hint", host).textContent = `Step ${state.i + 1} of ${N}`;
    $("#prev", host).disabled = state.i === 0; $("#next", host).disabled = state.i === N - 1;
    if (step.after) step.after(stage, S, R, run);
    if (state.playing && state.i < N - 1) state.timer = setTimeout(() => go(state.i + 1), step.hold);
    else if (state.i === N - 1 && state.playing) { state.playing = false; $("#play", host).textContent = "↻ Replay"; }
  }

  host.querySelectorAll(".steps button").forEach((b) => b.addEventListener("click", () => go(+b.dataset.i, true)));
  $("#prev", host).addEventListener("click", () => go(state.i - 1, true));
  $("#next", host).addEventListener("click", () => go(state.i + 1, true));
  $("#skip", host).addEventListener("click", () => showView("full"));
  $("#play", host).addEventListener("click", () => {
    if (state.playing) { state.playing = false; clearTimeout(state.timer); $("#play", host).textContent = "▶ Play"; return; }
    state.playing = true; $("#play", host).textContent = "❚❚ Pause";
    go(state.i === N - 1 ? 0 : state.i);
  });
  stopCurrent = () => clearTimeout(state.timer);
  go(0);
}
