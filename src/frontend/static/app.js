/* AEGIS analyst console — application.
 *
 * Plain ES2020, no build step, no framework. Sections:
 *
 *   1. Utilities        — HTML escaping, formatting, domain constants
 *   2. Data access      — the `api` object (one function per endpoint) with a
 *                         mock adapter over fixtures.js for offline demos
 *   3. Shell            — hash router, header stats, mock badge, toasts
 *   4. Shared renderers — badges, score bars, queue rows, score decomposition
 *   5. Views            — queue, incident, alerts, feeds, ATT&CK
 *   6. Alert drawer     — indicators, raw payload, "why is this ranked here?"
 *
 * All text that reaches innerHTML goes through the `html` tagged template,
 * which escapes every interpolation unless it is explicitly marked `raw()`.
 */
(function () {
  'use strict';

  // ===========================================================================
  // 1. Utilities
  // ===========================================================================

  const API_BASE = (window.AEGIS_API_BASE || '').replace(/\/$/, '');

  class Raw { constructor(s) { this.s = s; } toString() { return this.s; } }
  const raw = (s) => new Raw(String(s));
  const esc = (s) => String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  const toHtml = (v) => {
    if (v instanceof Raw) return v.s;
    if (Array.isArray(v)) return v.map(toHtml).join('');
    if (v === null || v === undefined || v === false) return '';
    return esc(v);
  };
  /** Tagged template: html`<b>${userText}</b>` — interpolations are escaped. Returns Raw so it nests. */
  const html = (strings, ...vals) => raw(strings.reduce((out, s, i) => out + s + (i < vals.length ? toHtml(vals[i]) : ''), ''));

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  /** Small inline icon set — functional glyphs only (search, close, copy, chevrons). No icon font, works offline. */
  const ICONS = {
    search: '<path d="M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16Zm10 2-4.35-4.35" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
    close: '<path d="M6 6l12 12M18 6 6 18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>',
    copy: '<rect x="9" y="9" width="12" height="12" rx="2" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M5 15V5a2 2 0 0 1 2-2h10" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>',
    chevLeft: '<path d="M15 6l-6 6 6 6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
    chevRight: '<path d="M9 6l6 6-6 6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
    check: '<path d="M5 13l4 4L19 7" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>',
  };
  const icon = (name, cls = '') => raw(`<svg class="icon ${cls}" viewBox="0 0 24 24" aria-hidden="true">${ICONS[name] || ''}</svg>`);

  /** Small "copy id to clipboard" button, used next to incident/alert ids throughout the console. */
  const copyBtn = (text, label) => html`<button type="button" class="icon-btn copy-btn" data-copy="${text}" title="Copy ${label || text}" aria-label="Copy ${label || text}">${icon('copy')}</button>`;
  function bindCopyButtons(root) {
    $$('.copy-btn[data-copy]', root).forEach((btn) => {
      btn.addEventListener('click', (ev) => {
        ev.stopPropagation();
        copyText(btn.dataset.copy, false);
        btn.classList.add('copied');
        setTimeout(() => btn.classList.remove('copied'), 900);
      });
    });
  }

  /** ISO timestamp → "2026-09-14 09:14:07Z" (monospace friendly, no locale surprises). */
  const fmtTs = (iso) => {
    if (!iso) return '—';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return String(iso);
    return d.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, 'Z');
  };
  const fmtTime = (iso) => fmtTs(iso).slice(11);
  const fmtDate = (iso) => fmtTs(iso).slice(0, 10);
  const pct = (x) => Math.round((x || 0) * 100);
  const truncate = (s, n) => (s && s.length > n ? s.slice(0, n - 1) + '…' : s || '');

  /** MITRE ATT&CK Enterprise tactics in kill-chain order — mirrors src/models.py::Tactic. */
  const TACTICS = [
    ['reconnaissance', 'Reconnaissance', 'Recon'],
    ['resource-development', 'Resource Development', 'Resource Dev'],
    ['initial-access', 'Initial Access', 'Initial Access'],
    ['execution', 'Execution', 'Execution'],
    ['persistence', 'Persistence', 'Persistence'],
    ['privilege-escalation', 'Privilege Escalation', 'Priv Esc'],
    ['defense-evasion', 'Defense Evasion', 'Def Evasion'],
    ['credential-access', 'Credential Access', 'Cred Access'],
    ['discovery', 'Discovery', 'Discovery'],
    ['lateral-movement', 'Lateral Movement', 'Lateral Mvmt'],
    ['collection', 'Collection', 'Collection'],
    ['command-and-control', 'Command and Control', 'C2'],
    ['exfiltration', 'Exfiltration', 'Exfiltration'],
    ['impact', 'Impact', 'Impact'],
  ];
  const TACTIC_INDEX = new Map(TACTICS.map(([id], i) => [id, i]));
  const tacticName = (id) => (TACTICS.find(([t]) => t === id) || [id, id])[1];
  const deepestTactic = (tactics) => (tactics || []).reduce((best, t) =>
    (TACTIC_INDEX.get(t) ?? -1) > (TACTIC_INDEX.get(best) ?? -1) ? t : best, tactics && tactics[0]);

  const SOURCES = {
    siem: { label: 'SIEM', color: '#5b8def' },
    syslog: { label: 'syslog', color: '#e0a63c' },
    geo: { label: 'geo', color: '#4fbf7a' },
    intel: { label: 'intel', color: '#b07ce8' },
  };
  const SOURCE_ORDER = ['siem', 'syslog', 'geo', 'intel'];

  /** Vendor severity strings are verbatim and vendor-specific; this only picks a colour. */
  const sevClass = (s) => {
    const v = String(s || '').toLowerCase();
    if (/crit|p1|emerg|fatal/.test(v)) return 's-critical';
    if (/high|err|p2|alert/.test(v)) return 's-high';
    if (/med|warn|p3/.test(v)) return 's-medium';
    if (/low|info|notice|p4|p5|debug/.test(v)) return 's-low';
    return '';
  };
  const SEV_RANK = { critical: 0, crit: 0, p1: 0, high: 1, err: 1, error: 1, p2: 1, medium: 2, warning: 2, warn: 2, p3: 2, low: 3, notice: 3, info: 3, p4: 3, p5: 4 };

  const SIGNAL_LABEL = {
    shared_indicator: 'shared indicator',
    temporal: 'temporal proximity',
    asset_adjacency: 'asset adjacency',
    tactic_progression: 'tactic progression',
  };

  const topTechnique = (alert) => (alert.techniques || []).reduce((b, t) => (!b || t.score > b.score ? t : b), null);

  // ===========================================================================
  // 2. Data access layer
  // ===========================================================================

  class ApiError extends Error {
    constructor(status, detail) { super(detail || `HTTP ${status}`); this.status = status; this.detail = detail; }
  }
  class NetworkError extends Error {}

  const state = {
    mock: /[?&]mock=1(&|$)/.test(location.search),
    ruleNames: null,     // rule_id → name, from GET /suppression-rules
    assets: null,        // asset_id → AssetInventory record, from GET /assets
    graph: null,         // live CorrelationGraph instance on the incident view
  };

  /** fetch wrapper: builds the query string, throws ApiError on non-2xx and NetworkError when unreachable. */
  async function request(path, params = {}) {
    const qs = Object.entries(params)
      .filter(([, v]) => v !== undefined && v !== null && v !== '')
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
      .join('&');
    const url = `${API_BASE}${path}${qs ? '?' + qs : ''}`;
    let res;
    try {
      res = await fetch(url, { headers: { Accept: 'application/json' } });
    } catch (err) {
      throw new NetworkError(`${url}: ${err.message}`);
    }
    if (!res.ok) {
      let detail = res.statusText;
      try { detail = (await res.json()).detail || detail; } catch (_) { /* non-JSON error body */ }
      throw new ApiError(res.status, detail);
    }
    return res.json();
  }

  /** fetch wrapper for POST/PATCH/DELETE with a JSON body. Same error semantics as `request`. */
  async function mutate(path, method, body) {
    const url = `${API_BASE}${path}`;
    let res;
    try {
      res = await fetch(url, {
        method,
        headers: { Accept: 'application/json', ...(body ? { 'Content-Type': 'application/json' } : {}) },
        body: body ? JSON.stringify(body) : undefined,
      });
    } catch (err) {
      throw new NetworkError(`${url}: ${err.message}`);
    }
    if (!res.ok) {
      let detail = res.statusText;
      try { detail = (await res.json()).detail || detail; } catch (_) { /* non-JSON error body */ }
      throw new ApiError(res.status, detail);
    }
    return res.status === 204 ? null : res.json();
  }

  /** Pairs a live implementation with its mock; a network failure flips the whole console into mock mode. */
  function endpoint(live, mock) {
    return async (...args) => {
      if (state.mock) return mock(...args);
      try {
        return await live(...args);
      } catch (err) {
        if (err instanceof NetworkError) {
          enableMock(err.message);
          return mock(...args);
        }
        throw err;
      }
    };
  }

  // --- Mock adapter over fixtures.js. Filtering mimics the server semantics. --
  // Dispositions and asset overrides are session-local (not persisted) in mock mode —
  // there is no server to write them to, so a page reload resets them, same as any
  // other in-memory mock state.
  const mockDispositions = new Map();
  const Mock = (() => {
    const F = () => window.AEGIS_FIXTURES;
    const notFound = (what) => { throw new ApiError(404, `${what} not found`); };
    const contains = (hay, q) => String(hay || '').toLowerCase().includes(q.toLowerCase());
    const incidentAlerts = (id) => F().alerts.filter((a) => a.incident_id === id).sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    const withDisposition = (inc) => Object.assign({}, inc, { disposition: mockDispositions.get(inc.incident_id) || null });
    const summary = (id) => withDisposition(F().incidents.find((i) => i.incident_id === id) || notFound(`incident ${id}`));

    const detail = (id) => {
      const inc = summary(id);
      return Object.assign({}, inc, { alerts: incidentAlerts(id), edges: F().edges[id] || [], bluf: F().blufs[id] || null });
    };

    /** Deterministic fallback brief, mirroring the backend's template generator. */
    const templateBluf = (inc) => {
      const alerts = incidentAlerts(inc.incident_id);
      const conf = inc.score.composite >= 70 ? 'High' : inc.score.composite >= 40 ? 'Medium' : 'Low';
      return {
        incident_id: inc.incident_id,
        bottom_line: `${inc.title}: ${inc.alert_count} correlated alert${inc.alert_count === 1 ? '' : 's'} on ${inc.assets.join(', ') || 'unknown assets'}, composite priority ${inc.score.composite}/100.`,
        confidence: conf,
        confidence_rationale: `correlation confidence ${inc.score.correlation_confidence.toFixed(2)}, deepest tactic ${tacticName(deepestTactic(inc.tactics))}, false-positive likelihood ${inc.score.false_positive_likelihood.toFixed(2)}.`,
        assessment: inc.rationale,
        attack_chain: inc.attack_chain.map((t) => ({ technique_id: t.technique_id, technique_name: t.technique_name, tactic: t.tactic, score: t.score, method: 'blended' })),
        evidence: alerts.map((a) => `${a.alert_id} (${a.source}, ${fmtTs(a.timestamp).slice(0, 16)}Z): ${truncate(a.raw_text, 110)}`),
        recommended_actions: ['Review the correlated alerts and confirm the asset owner.', 'Escalate if any further alert joins this incident.'],
        gaps: ['Template brief: no analyst narrative; watsonx generation was not available.'],
        generated_by: 'template',
      };
    };

    const explain = (id, a, b) => {
      const inc = detail(id);
      const ids = new Set(inc.alerts.map((x) => x.alert_id));
      const same = ids.has(a) && ids.has(b);
      const direct = inc.edges.find((e) => (e.alert_a === a && e.alert_b === b) || (e.alert_a === b && e.alert_b === a)) || null;
      let path = [];
      if (!direct && same && a !== b) {
        // Breadth-first shortest path over the incident's edges.
        const adj = new Map();
        for (const e of inc.edges) {
          (adj.get(e.alert_a) || adj.set(e.alert_a, []).get(e.alert_a)).push(e);
          (adj.get(e.alert_b) || adj.set(e.alert_b, []).get(e.alert_b)).push(e);
        }
        const prev = new Map([[a, null]]);
        const queue = [a];
        while (queue.length && !prev.has(b)) {
          const cur = queue.shift();
          for (const e of adj.get(cur) || []) {
            const nxt = e.alert_a === cur ? e.alert_b : e.alert_a;
            if (!prev.has(nxt)) { prev.set(nxt, e); queue.push(nxt); }
          }
        }
        if (prev.has(b)) {
          let cur = b;
          while (prev.get(cur)) { const e = prev.get(cur); path.unshift(e); cur = e.alert_a === cur ? e.alert_b : e.alert_a; }
        }
      }
      let narrative;
      if (!same) narrative = `${a} and ${b} are not both members of ${id}; there is no correlation path between them in this incident.`;
      else if (a === b) narrative = `${a} is the same alert.`;
      else if (direct) {
        const parts = direct.contributions.map((c) => `${SIGNAL_LABEL[c.signal] || c.signal} (${c.weight.toFixed(2)}): ${c.rationale}`);
        narrative = `${a} and ${b} are directly linked with total weight ${direct.total_weight.toFixed(2)}. ${parts.join(' ')}`;
      } else if (path.length) {
        const hops = [a]; let cur = a;
        for (const e of path) { cur = e.alert_a === cur ? e.alert_b : e.alert_a; hops.push(cur); }
        narrative = `${a} and ${b} share no direct edge; they are linked transitively through ${hops.join(' → ')} (${path.length} hops). The weakest link carries weight ${Math.min(...path.map((e) => e.total_weight)).toFixed(2)}.`;
      } else narrative = `${a} and ${b} are in the same incident but no path was found.`;
      return { alert_a: a, alert_b: b, same_incident: same, edge: direct, path, narrative };
    };

    const alertView = (id) => F().alerts.find((a) => a.alert_id === id) || notFound(`alert ${id}`);

    return {
      stats: () => F().stats,
      incidents: ({ limit = 50, min_alerts = 1, tactic, source, q } = {}) => F().incidents
        .filter((i) => i.alert_count >= Number(min_alerts || 1))
        .filter((i) => !tactic || i.tactics.includes(tactic))
        .filter((i) => !source || (i.sources[source] || 0) > 0)
        .filter((i) => !q || contains(i.title, q) || contains(i.incident_id, q) || i.assets.some((x) => contains(x, q))
          || (i.top_technique && (contains(i.top_technique.technique_id, q) || contains(i.top_technique.technique_name, q))))
        .sort((x, y) => x.rank - y.rank)
        .slice(0, Number(limit))
        .map(withDisposition),
      incident: (id) => detail(id),
      bluf: (id) => F().blufs[id] || templateBluf(summary(id)),
      explain,
      alerts: ({ limit = 100, offset = 0, source, severity, q } = {}) => {
        const items = F().alerts
          .filter((a) => !source || a.source === source)
          .filter((a) => !severity || String(a.source_severity).toLowerCase() === String(severity).toLowerCase())
          .filter((a) => !q || contains(a.raw_text, q) || contains(a.alert_id, q) || (a.asset && contains(a.asset.asset_id, q))
            || a.indicators.some((x) => contains(x.value, q)))
          .sort((x, y) => y.timestamp.localeCompare(x.timestamp));
        return { total: items.length, items: items.slice(Number(offset), Number(offset) + Number(limit)) };
      },
      alert: (id) => {
        const a = alertView(id);
        const inc = a.incident_id ? F().incidents.find((i) => i.incident_id === a.incident_id) : null;
        return Object.assign({}, a, { incident_id: a.incident_id, queue_position: inc ? inc.rank : null, total_incidents: F().incidents.length });
      },
      whyDeprioritised: (id) => {
        if (F().why_deprioritised[id]) return F().why_deprioritised[id];
        const a = alertView(id);
        const inc = a.incident_id ? summary(a.incident_id) : null;
        if (!inc) notFound(`incident for alert ${id}`);
        const rules = inc.score.suppression_rules_fired.map((rid) => {
          const r = F().suppression_rules.find((x) => x.rule_id === rid) || { rule_id: rid, name: rid, rationale: '' };
          return { rule_id: r.rule_id, name: r.name, rationale: r.rationale, evidence: 'See incident score explanation.' };
        });
        return {
          alert_id: id, vendor_severity: a.source_severity, incident_id: inc.incident_id, queue_position: inc.rank, total_incidents: F().incidents.length,
          score: inc.score, rules_fired: rules,
          narrative: `${id} belongs to ${inc.incident_id}, ranked ${inc.rank} of ${F().incidents.length}. ${inc.rationale} Composite ${inc.score.composite}/100: correlation ${inc.score.correlation_confidence.toFixed(2)}, asset criticality ${inc.score.asset_criticality.toFixed(2)}, tactic severity ${inc.score.tactic_severity.toFixed(2)}, false-positive likelihood ${inc.score.false_positive_likelihood.toFixed(2)}.`,
        };
      },
      techniques: (q) => F().techniques.filter((t) => !q || contains(t.technique_id, q) || contains(t.name, q)),
      technique: (id) => {
        const t = F().techniques.find((x) => x.technique_id === id) || notFound(`technique ${id}`);
        const alertIds = F().alerts.filter((a) => a.techniques.some((m) => m.technique_id === id)).map((a) => a.alert_id);
        const incIds = new Set(F().alerts.filter((a) => alertIds.includes(a.alert_id)).map((a) => a.incident_id));
        return { technique: t, incidents: F().incidents.filter((i) => incIds.has(i.incident_id)).sort((x, y) => x.rank - y.rank), alert_ids: alertIds };
      },
      feedsRaw: () => F().feeds,
      suppressionRules: () => F().suppression_rules,
      assets: () => F().assets,
      updateAsset: (id, criticality, rationale) => {
        const a = F().assets.find((x) => x.asset_id === id) || notFound(`asset ${id}`);
        a.criticality = criticality;
        if (rationale) a.rationale = rationale;
        return a;
      },
      dispositions: () => Object.fromEntries(mockDispositions),
      setDisposition: (id, verdict, note, analyst) => {
        summary(id); // 404s if unknown
        const rec = { incident_id: id, verdict, note: note || null, analyst: analyst || null, updated_at: new Date().toISOString() };
        mockDispositions.set(id, rec);
        return rec;
      },
      clearDisposition: (id) => { summary(id); mockDispositions.delete(id); return { ok: true }; },
      ingest: (source, records) => ({
        source, submitted: records.length, ingested: records.length, errors: [],
        note: 'Mock mode: nothing is persisted. On the live API this would be picked up by the next `python -m src.pipeline.run`.',
      }),
    };
  })();

  /** The data-access layer. One function per endpoint in docs/api-contract.md; views only ever call these. */
  const api = {
    stats: endpoint(() => request('/stats'), Mock.stats),
    incidents: endpoint((params) => request('/incidents', params), Mock.incidents),
    incident: endpoint((id) => request(`/incidents/${encodeURIComponent(id)}`), Mock.incident),
    bluf: endpoint((id) => request(`/incidents/${encodeURIComponent(id)}/bluf`), Mock.bluf),
    explain: endpoint((id, a, b) => request(`/incidents/${encodeURIComponent(id)}/explain`, { a, b }), Mock.explain),
    alerts: endpoint((params) => request('/alerts', params), Mock.alerts),
    alert: endpoint((id) => request(`/alerts/${encodeURIComponent(id)}`), Mock.alert),
    whyDeprioritised: endpoint((id) => request(`/alerts/${encodeURIComponent(id)}/why-deprioritised`), Mock.whyDeprioritised),
    techniques: endpoint((q) => request('/techniques', { q }), Mock.techniques),
    technique: endpoint((id) => request(`/techniques/${encodeURIComponent(id)}`), Mock.technique),
    feedsRaw: endpoint((lines) => request('/feeds/raw', { lines }), Mock.feedsRaw),
    suppressionRules: endpoint(() => request('/suppression-rules'), Mock.suppressionRules),
    assets: endpoint(() => request('/assets'), Mock.assets),
    updateAsset: endpoint(
      (id, criticality, rationale) => mutate(`/assets/${encodeURIComponent(id)}`, 'PATCH', { criticality, rationale }),
      (id, criticality, rationale) => Mock.updateAsset(id, criticality, rationale),
    ),
    dispositions: endpoint(() => request('/dispositions'), Mock.dispositions),
    setDisposition: endpoint(
      (id, verdict, note) => mutate(`/incidents/${encodeURIComponent(id)}/disposition`, 'POST', { verdict, note }),
      (id, verdict, note) => Mock.setDisposition(id, verdict, note),
    ),
    clearDisposition: endpoint(
      (id) => mutate(`/incidents/${encodeURIComponent(id)}/disposition`, 'DELETE'),
      (id) => Mock.clearDisposition(id),
    ),
    ingest: endpoint(
      (source, records) => mutate(`/ingest?source=${encodeURIComponent(source)}`, 'POST', records),
      (source, records) => Mock.ingest(source, records),
    ),
  };
  window.aegisApi = api; // handy in the devtools console

  async function ruleNames() {
    if (!state.ruleNames) {
      try { state.ruleNames = new Map((await api.suppressionRules()).map((r) => [r.rule_id, r.name])); }
      catch (_) { state.ruleNames = new Map(); }
    }
    return state.ruleNames;
  }

  /** Asset inventory keyed by id. Criticality lives only here (joined at scoring time,
   * never on the alert record), so this is the source of truth for the drawer's editor. */
  async function assetIndex(force = false) {
    if (!state.assets || force) {
      try { state.assets = new Map((await api.assets()).map((a) => [a.asset_id, a])); }
      catch (_) { state.assets = new Map(); }
    }
    return state.assets;
  }

  // ===========================================================================
  // 3. Shell: router, header, toasts
  // ===========================================================================

  function enableMock(reason) {
    if (!state.mock) console.warn('AEGIS: API unreachable, switching to mock fixtures —', reason);
    state.mock = true;
    $('#mock-badge').hidden = false;
  }

  let toastTimer = null;
  function toast(msg, isError = false) {
    const el = $('#toast');
    el.textContent = msg;
    el.className = 'toast' + (isError ? ' err' : '');
    el.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.hidden = true; }, 2600);
  }

  const routes = [
    [/^#\/overview\/?$/, () => viewOverview()],
    [/^#\/brief\/?$/, () => viewBrief()],
    [/^#\/queue\/?$/, () => viewQueue()],
    [/^#\/incident\/([^/]+)\/?$/, (m) => viewIncident(decodeURIComponent(m[1]))],
    [/^#\/alerts(?:\/([^/]+))?(\/why)?\/?$/, (m) => viewAlerts(m[1] ? decodeURIComponent(m[1]) : null, !!m[2])],
    [/^#\/feeds\/?$/, () => viewFeeds()],
    [/^#\/attack(?:\/([^/]+))?\/?$/, (m) => viewAttack(m[1] ? decodeURIComponent(m[1]) : null)],
    [/^#\/verdicts\/?$/, () => viewVerdicts()],
    [/^#\/assets\/?$/, () => viewAssets()],
    [/^#\/rules\/?$/, () => viewRules()],
    [/^#\/iocs\/?$/, () => viewIocs()],
    [/^#\/ingest\/?$/, () => viewIngest()],
  ];

  async function route() {
    const hash = location.hash || '#/queue';
    closeDrawer();
    if (state.graph) { state.graph.destroy(); state.graph = null; }
    const view = $('#view');
    view.scrollTop = 0;
    for (const [re, handler] of routes) {
      const m = hash.match(re);
      if (m) {
        const section = hash.split('/')[1].replace(/^incident$/, 'queue');
        $$('#nav a').forEach((a) => a.classList.toggle('active', a.dataset.route === section));
        try {
          await handler(m);
        } catch (err) {
          console.error(err);
          view.innerHTML = html`<div class="panel"><div class="error">${err.message || String(err)}</div></div>`;
        }
        return;
      }
    }
    location.hash = '#/queue';
  }

  async function renderStats() {
    const el = $('#stats');
    try {
      const s = await api.stats();
      const by = s.alerts_by_source || {};
      const run = s.last_run || {};
      const runTs = run.finished_at || run.completed_at || run.started_at || run.timestamp || null;
      el.innerHTML = html`
        <span class="stat"><b>${s.alerts ?? '—'}</b> alerts
          ${SOURCE_ORDER.filter((k) => by[k] != null).map((k) => html`<span class="src" style="color:${SOURCES[k].color}">${by[k]} ${SOURCES[k].label}</span>`)}
        </span>
        <span class="stat"><b>${s.indicators ?? '—'}</b> indicators</span>
        <span class="stat stat-optional"><b>${s.attack_mappings ?? '—'}</b> ATT&amp;CK mappings</span>
        <span class="stat"><b>${s.edges ?? '—'}</b> edges</span>
        <span class="stat"><b>${s.incidents ?? '—'}</b> incidents <span class="muted">(${s.multi_alert_incidents ?? '—'} multi-alert)</span></span>
        <span class="stat stat-optional"><b>${s.bluf_reports ?? '—'}</b> BLUFs</span>
        <span class="stat stat-run"><i class="live-dot"></i>pipeline last run <b>${runTs ? fmtTs(runTs) : 'never'}</b></span>`;
    } catch (err) {
      el.innerHTML = html`<span class="stat error">stats unavailable: ${err.message}</span>`;
    }
  }

  // ===========================================================================
  // 4. Shared renderers
  // ===========================================================================

  const sourceBadge = (src, n) => html`<span class="badge ${src}">${(SOURCES[src] || { label: src }).label}${n != null ? html` <span class="n">${n}</span>` : ''}</span>`;
  const sourceBadges = (sources) => html`<div class="badges">${SOURCE_ORDER.filter((k) => sources[k]).map((k) => sourceBadge(k, sources[k]))}${Object.keys(sources).filter((k) => !SOURCE_ORDER.includes(k)).map((k) => sourceBadge(k, sources[k]))}</div>`;
  const sevChip = (s) => html`<span class="sev ${sevClass(s)}">${s || 'n/a'}</span>`;
  const techLabel = (t) => (t ? html`<span class="tid">${t.technique_id}</span> <span class="tname">${t.technique_name}</span>` : html`<span class="muted">unmapped</span>`);
  const vendorSummary = (vs) => {
    const keys = Object.keys(vs || {}).sort((a, b) => (SEV_RANK[a.toLowerCase()] ?? 9) - (SEV_RANK[b.toLowerCase()] ?? 9));
    return html`<span class="sevsum">${keys.map((k) => html`<span class="${sevClass(k)}"><b>${vs[k]}</b> ${k}</span>`)}</span>`;
  };

  /** Four-segment mini bar: three positive factors in accent, false-positive likelihood in red. */
  const segBar = (sc) => html`<span class="segbar" title="confidence ${pct(sc.correlation_confidence)}% · asset ${pct(sc.asset_criticality)}% · tactic ${pct(sc.tactic_severity)}% · FP ${pct(sc.false_positive_likelihood)}%">
    <span class="seg"><i style="width:${pct(sc.correlation_confidence)}%"></i></span>
    <span class="seg"><i style="width:${pct(sc.asset_criticality)}%"></i></span>
    <span class="seg"><i style="width:${pct(sc.tactic_severity)}%"></i></span>
    <span class="seg fp"><i style="width:${pct(sc.false_positive_likelihood)}%"></i></span></span>`;

  /** score tier drives the ring colour and the row's left accent — same thresholds as the severity legend. */
  const scoreTier = (composite) => (composite >= 80 ? 'critical' : composite >= 60 ? 'high' : composite >= 40 ? 'medium' : 'low');
  const scoreRing = (sc) => html`<span class="ring" data-tier="${scoreTier(sc.composite)}" style="--pct:${Math.max(0, Math.min(100, sc.composite))}"><span class="ring-num">${Math.round(sc.composite)}</span></span>`;

  const scoreCell = (sc) => html`<div class="score">${scoreRing(sc)}${segBar(sc)}</div>`;

  function queueCard(inc, names) {
    const sc = inc.score;
    const tier = scoreTier(sc.composite);
    return html`<div class="q-card row" data-incident="${inc.incident_id}" data-tier="${tier}">
      <div class="q-card-head">
        <span class="q-badge" data-tier="${tier}">#${inc.rank}</span>
        <div class="q-card-title">${inc.title}${inc.disposition ? html` <span class="disp-chip mini ${inc.disposition.verdict}">${icon(inc.disposition.verdict === 'confirmed' ? 'check' : 'close')}</span>` : ''}</div>
        <span class="q-pill" data-tier="${tier}">${Math.round(sc.composite)}</span>
      </div>
      <div class="rationale" title="${inc.rationale}">${inc.rationale}</div>
      <div class="segbar" title="confidence ${pct(sc.correlation_confidence)}% · asset ${pct(sc.asset_criticality)}% · tactic ${pct(sc.tactic_severity)}% · FP ${pct(sc.false_positive_likelihood)}%">
        <span class="seg"><i style="width:${pct(sc.correlation_confidence)}%"></i></span>
        <span class="seg"><i style="width:${pct(sc.asset_criticality)}%"></i></span>
        <span class="seg"><i style="width:${pct(sc.tactic_severity)}%"></i></span>
        <span class="seg fp"><i style="width:${pct(sc.false_positive_likelihood)}%"></i></span>
      </div>
      ${sc.suppression_rules_fired && sc.suppression_rules_fired.length
        ? html`<div class="chips">${sc.suppression_rules_fired.map((r) => html`<span class="chip" title="${names.get(r) || r}">${r}</span>`)}</div>` : ''}
      <div class="q-card-meta">
        <span><b>${inc.alert_count}</b> alert${inc.alert_count === 1 ? '' : 's'}</span>
        <span class="tactic">${tacticName(deepestTactic(inc.tactics)) || '—'}</span>
        <span>${techLabel(inc.top_technique)}</span>
      </div>
      <div class="q-card-foot">
        ${sourceBadges(inc.sources || {})}
        <div class="assets">${(inc.assets || []).map((a) => html`<span>${a}</span>`)}</div>
      </div>
    </div>`;
  }

  function queueTable(incidents, names) {
    if (!incidents.length) return html`<div class="empty">No incidents match.</div>`;
    return html`<div class="q-grid">${incidents.map((i) => queueCard(i, names))}</div>`;
  }

  function bindQueueRows(root) {
    $$('.q-card[data-incident]', root).forEach((card) => {
      card.addEventListener('click', () => { location.hash = `#/incident/${encodeURIComponent(card.dataset.incident)}`; });
    });
  }

  /** Score decomposition: four labelled bars with the explanation sentence under each. */
  function scoreFactors(sc, explanation, names) {
    const rows = [
      ['correlation_confidence', 'Correlation confidence', false],
      ['asset_criticality', 'Asset criticality', false],
      ['tactic_severity', 'Tactic severity', false],
      ['false_positive_likelihood', 'False-positive likelihood', true],
    ];
    return html`<div class="factors">${rows.map(([key, label, isFp]) => html`
      <div class="factor ${isFp ? 'fp' : ''}">
        <div class="row">
          <span class="lbl">${label}${isFp ? html` <span class="muted">(subtracts)</span>` : ''}</span>
          <span class="bar"><i style="width:${pct(sc[key])}%"></i></span>
          <span class="val">${(sc[key] ?? 0).toFixed(2)}</span>
        </div>
        ${explanation && explanation[key] ? html`<p class="why" title="${explanation[key]}">${explanation[key]}</p>` : ''}
      </div>`)}
    </div>
    <div class="rules">Suppression rules fired:
      ${sc.suppression_rules_fired && sc.suppression_rules_fired.length
        ? sc.suppression_rules_fired.map((r) => html`<span class="chip" title="${r}">${names && names.get(r) ? names.get(r) : r}</span>`)
        : html`<span class="chip neutral">none</span>`}
    </div>`;
  }

  // ===========================================================================
  // 5. Views
  // ===========================================================================

  /** One row of a horizontal bar chart: label, bar scaled to `max`, raw count.
   * `nav` (optional) makes the row clickable — an object {kind, key} consumed
   * by viewOverview's delegated click handler to jump into a filtered view. */
  const hbar = (label, count, max, color, nav) => html`<div class="hbar-row${nav ? ' clickable' : ''}" data-kind="${nav ? nav.kind : ''}" data-key="${nav ? nav.key : ''}">
    <span class="hbar-lbl">${label}</span>
    <span class="hbar-track"><i style="width:${max ? Math.max(2, Math.round((count / max) * 100)) : 0}%;background:${color || 'var(--accent)'}"></i></span>
    <span class="hbar-val">${count}</span>
  </div>`;

  // --- Overview (commander rollup) --------------------------------------------
  /** A one-screen situational summary — priority mix, source volume, ATT&CK tactic
   * spread, and top at-risk assets — built entirely from data the other views
   * already fetch. No new endpoints; this is a client-side rollup for commanders
   * who want the picture in seconds, not a queue to scroll. */
  const OV_ICONS = {
    queue: '<path d="M3 4h18M3 10h18M3 16h11" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>',
    warn: '<path d="M12 3 2 20h20L12 3Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M12 10v4M12 17h.01" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>',
    check: '<path d="M5 13l4 4L19 7" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>',
    x: '<path d="M6 6l12 12M18 6 6 18" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>',
    clock: '<circle cx="12" cy="12" r="8.5" stroke="currentColor" stroke-width="1.8"/><path d="M12 7.5V12l3 2" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>',
  };
  const ovIcon = (name, cls) => raw(`<svg class="nicon ${cls || ''}" viewBox="0 0 24 24" fill="none" aria-hidden="true">${OV_ICONS[name] || ''}</svg>`);

  async function viewOverview() {
    const view = $('#view');
    view.innerHTML = html`
      <div class="view-title"><h1>Overview</h1><span class="sub">situational summary for commanders — priority mix, sources, ATT&amp;CK spread, at-risk assets</span></div>
      <div class="quick-actions">
        <a href="#/brief">${ovIcon('queue')} Commander's Brief</a>
        <a href="#/iocs">${ovIcon('warn')} IOC Watchlist</a>
        <a href="#/ingest">${ovIcon('clock')} Ingest Feed</a>
      </div>
      <div id="ov-top"></div>
      <div id="ov-kpis" class="ov-kpis"><div class="loading">loading overview</div></div>
      <div class="ov-grid" id="ov-grid" hidden>
        <div class="panel">
          <div class="panel-head"><h2>Incidents by priority tier</h2><span class="hint">composite score band</span></div>
          <div id="ov-tiers"></div>
        </div>
        <div class="panel">
          <div class="panel-head"><h2>Alert volume by source</h2><span class="hint">click to filter alerts</span></div>
          <div id="ov-sources"></div>
        </div>
        <div class="panel">
          <div class="panel-head"><h2>ATT&amp;CK tactics observed</h2><span class="hint">click to filter the queue</span></div>
          <div id="ov-tactics"></div>
        </div>
        <div class="panel">
          <div class="panel-head"><h2>Top assets at risk</h2><span class="hint">click to filter alerts</span></div>
          <div id="ov-assets"></div>
        </div>
      </div>`;

    try {
      const [stats, incidents, dispositions] = await Promise.all([
        api.stats(),
        api.incidents({ limit: 500, min_alerts: 1 }),
        api.dispositions().catch(() => ({})),
      ]);

      const dispValues = Object.values(dispositions || {});
      const confirmed = dispValues.filter((d) => d.verdict === 'confirmed').length;
      const fp = dispValues.filter((d) => d.verdict === 'false_positive').length;
      const tierCounts = { critical: 0, high: 0, medium: 0, low: 0 };
      incidents.forEach((i) => { tierCounts[scoreTier(i.score.composite)]++; });
      const criticalHigh = tierCounts.critical + tierCounts.high;

      const run = stats.last_run || {};
      const runTs = run.finished_at || run.completed_at || run.started_at || run.timestamp || null;

      // -- hero: the single highest-priority incident right now ---------------
      const top1 = incidents.slice().sort((a, b) => a.rank - b.rank)[0];
      $('#ov-top').innerHTML = top1 ? html`
        <a class="ov-hero" href="#/incident/${encodeURIComponent(top1.incident_id)}">
          <span class="q-pill" data-tier="${scoreTier(top1.score.composite)}">${Math.round(top1.score.composite)}</span>
          <div class="ov-hero-main">
            <div class="ov-hero-lbl">Highest priority right now — rank #${top1.rank}</div>
            <div class="ov-hero-title">${top1.title}</div>
            <div class="ov-hero-sub">${top1.rationale}</div>
          </div>
          <span class="ov-hero-cta">Open incident ${icon('chevRight')}</span>
        </a>` : '';

      $('#ov-kpis').innerHTML = html`
        <div class="ov-kpi">${ovIcon('queue', 'kpi-icon')}<b>${incidents.length}</b><span>incidents in queue</span></div>
        <div class="ov-kpi warn">${ovIcon('warn', 'kpi-icon')}<b>${criticalHigh}</b><span>critical + high priority</span></div>
        <div class="ov-kpi ok">${ovIcon('check', 'kpi-icon')}<b>${confirmed}</b><span>confirmed intrusions</span></div>
        <div class="ov-kpi muted-kpi">${ovIcon('x', 'kpi-icon')}<b>${fp}</b><span>marked false positive</span></div>
        <div class="ov-kpi">${ovIcon('clock', 'kpi-icon')}<b>${runTs ? fmtTs(runTs) : 'never'}</b><span>pipeline last run</span></div>`;

      // -- tier donut -----------------------------------------------------------
      const TIER_COLOR = { critical: 'var(--red)', high: 'var(--orange)', medium: 'var(--yellow)', low: 'var(--muted-2)' };
      const tierOrder = ['critical', 'high', 'medium', 'low'];
      const total = Math.max(1, incidents.length);
      let acc = 0;
      const stops = tierOrder.map((t) => {
        const from = (acc / total) * 100; acc += tierCounts[t];
        const to = (acc / total) * 100;
        return `${TIER_COLOR[t]} ${from}% ${to}%`;
      }).join(', ');
      $('#ov-tiers').innerHTML = html`
        <div class="donut-row">
          <div class="donut" style="background:conic-gradient(${raw(stops)})"><div class="donut-hole"><b>${incidents.length}</b><span>total</span></div></div>
          <div class="donut-legend">${tierOrder.map((t) => html`
            <div class="donut-legend-item"><i style="background:${TIER_COLOR[t]}"></i>${t[0].toUpperCase() + t.slice(1)}<b>${tierCounts[t]}</b></div>`)}
          </div>
        </div>`;

      const by = stats.alerts_by_source || {};
      const srcMax = Math.max(1, ...SOURCE_ORDER.map((s) => by[s] || 0));
      $('#ov-sources').innerHTML = SOURCE_ORDER.filter((s) => by[s] != null)
        .map((s) => hbar(SOURCES[s].label, by[s], srcMax, SOURCES[s].color, { kind: 'source', key: s })).join('');

      const tacticCounts = new Map(TACTICS.map(([id]) => [id, 0]));
      incidents.forEach((i) => (i.tactics || []).forEach((t) => { if (tacticCounts.has(t)) tacticCounts.set(t, tacticCounts.get(t) + 1); }));
      const tacticMax = Math.max(1, ...tacticCounts.values());
      $('#ov-tactics').innerHTML = TACTICS.filter(([id]) => tacticCounts.get(id) > 0).length
        ? TACTICS.filter(([id]) => tacticCounts.get(id) > 0).map(([id, name]) => hbar(name, tacticCounts.get(id), tacticMax, 'var(--accent)', { kind: 'tactic', key: id })).join('')
        : html`<div class="empty">No ATT&amp;CK mappings yet.</div>`.s;

      const assetCounts = new Map();
      incidents.forEach((i) => (i.assets || []).forEach((a) => assetCounts.set(a, (assetCounts.get(a) || 0) + 1)));
      const topAssets = [...assetCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
      const assetMax = Math.max(1, ...topAssets.map(([, n]) => n));
      $('#ov-assets').innerHTML = topAssets.length
        ? topAssets.map(([a, n]) => hbar(a, n, assetMax, 'var(--accent-2)', { kind: 'asset', key: a })).join('')
        : html`<div class="empty">No assets involved yet.</div>`.s;

      $$('.hbar-row.clickable', view).forEach((row) => {
        row.addEventListener('click', () => {
          const { kind, key } = row.dataset;
          if (kind === 'source') { alertsState.source = key; alertsState.q = ''; alertsState.offset = 0; location.hash = '#/alerts'; }
          else if (kind === 'tactic') { queueState.tactic = key; queueState.q = ''; queueState.bucket = 'all'; location.hash = '#/queue'; }
          else if (kind === 'asset') { alertsState.q = key; alertsState.source = ''; alertsState.offset = 0; location.hash = '#/alerts'; }
        });
      });

      $('#ov-grid').hidden = false;
    } catch (err) {
      $('#ov-kpis').innerHTML = html`<div class="error">${err.message}</div>`;
    }
  }

  // --- Commander's daily brief (multi-incident BLUF roll-up) ------------------
  /** The problem statement's fourth pillar taken to its logical end: BLUF is
   * built per incident, but a commander does not read the queue one incident at
   * a time — they want the top N rolled into a single situation report. This
   * calls the existing GET /incidents/{id}/bluf for each of the top-ranked
   * genuine-threat incidents and concatenates them into one document. */
  async function viewBrief() {
    const view = $('#view');
    view.innerHTML = html`
      <div class="view-title"><h1>Commander's Brief</h1><span class="sub">rolled-up BLUF situation report — top prioritised, non-suppressed incidents</span></div>
      <div class="panel bluf-panel" id="brief-panel"><div class="loading">assembling situation report from the top incidents</div></div>`;

    const panel = $('#brief-panel');
    try {
      const candidates = await api.incidents({ limit: 40, min_alerts: 2 });
      const top = candidates.filter((i) => !isFlagged(i)).sort((a, b) => a.rank - b.rank).slice(0, 8);
      if (!top.length) { panel.innerHTML = html`<div class="empty">No genuine-threat incidents to brief.</div>`; return; }

      const blufs = await Promise.all(top.map((inc) => api.bluf(inc.incident_id).catch(() => null)));
      const now = new Date();
      const sections = top.map((inc, i) => ({ inc, bluf: blufs[i] })).filter((s) => s.bluf);

      const chainStr = (b) => (b.attack_chain || []).map((t) => `${t.technique_id} ${t.technique_name}`).join(' → ');
      const list = (items) => html`<ul>${(items || []).map((x) => html`<li>${x}</li>`)}</ul>`;

      panel.innerHTML = html`
        <div class="panel-head"><h2>Commander's Brief — ${fmtTs(now.toISOString())}</h2>
          <span class="btn-row">
            <button id="brief-copy" class="ghost">Copy to clipboard</button>
            <button id="brief-download" class="ghost">Download .txt</button>
            <button id="brief-print" class="ghost">Print / save PDF</button>
          </span>
        </div>
        <div class="rationale-line">${sections.length} incident${sections.length === 1 ? '' : 's'} briefed, ranked by consequence · flagged (suppressed) incidents excluded</div>
        ${sections.map(({ inc, bluf: b }) => html`
          <div class="brief-section">
            <div class="brief-section-head">
              <a href="#/incident/${encodeURIComponent(inc.incident_id)}" class="brief-title">#${inc.rank} · ${inc.title}</a>
              <span class="q-pill" data-tier="${scoreTier(inc.score.composite)}">${Math.round(inc.score.composite)}</span>
            </div>
            <div class="bluf">
              <div class="bluf-row"><span class="bluf-key">BOTTOM LINE:</span><span class="bluf-val">${b.bottom_line}</span></div>
              <div class="bluf-row"><span class="bluf-key">CONFIDENCE:</span><span class="bluf-val"><span class="conf">${b.confidence}</span> — ${b.confidence_rationale}</span></div>
              <div class="bluf-row"><span class="bluf-key">ATT&amp;CK:</span><span class="bluf-val">${chainStr(b) || '—'}</span></div>
              <div class="bluf-row"><span class="bluf-key">RECOMMENDED:</span><span class="bluf-val">${list(b.recommended_actions)}</span></div>
            </div>
          </div>`)}`;

      const plain = [
        `AEGIS COMMANDER'S BRIEF — ${fmtTs(now.toISOString())}`,
        `${sections.length} incidents, ranked by consequence, suppressed incidents excluded`,
        '',
        ...sections.flatMap(({ inc, bluf: b }) => [
          `#${inc.rank} ${inc.title} (${inc.incident_id}) — composite ${Math.round(inc.score.composite)}/100`,
          `  BOTTOM LINE: ${b.bottom_line}`,
          `  CONFIDENCE:  ${b.confidence} — ${b.confidence_rationale}`,
          `  ATT&CK:      ${chainStr(b) || '—'}`,
          `  RECOMMENDED: ${(b.recommended_actions || []).map((x) => `\n    - ${x}`).join('')}`,
          '',
        ]),
      ].join('\n');
      $('#brief-copy').addEventListener('click', () => copyText(plain));
      $('#brief-download').addEventListener('click', () => downloadText(`aegis-commander-brief-${now.toISOString().slice(0, 10)}.txt`, plain));
      $('#brief-print').addEventListener('click', () => { document.body.classList.add('printing-bluf'); window.print(); });
    } catch (err) {
      panel.innerHTML = html`<div class="error">${err.message}</div>`;
    }
  }

  // --- Triage queue ---------------------------------------------------------
  const queueState = { tactic: '', source: '', q: '', hideSingles: true, sort: 'score', bucket: 'all' };

  /** An incident is "flagged" when a curated suppression rule fired on it — the
   * documented false-positive-likelihood mechanism, not a guess. This is the
   * literal "separate genuine threats from false positives" split from the
   * problem statement, made a first-class filter instead of a buried score factor. */
  const isFlagged = (inc) => !!(inc.score.suppression_rules_fired && inc.score.suppression_rules_fired.length);

  async function viewQueue() {
    const view = $('#view');
    view.innerHTML = html`
      <div class="view-title"><h1>Triage queue</h1><span class="sub">incidents ranked by consequence, not vendor severity</span></div>
      <div class="seg-row" id="q-bucket">
        <button type="button" class="seg-btn ${queueState.bucket === 'all' ? 'active' : ''}" data-bucket="all">All incidents</button>
        <button type="button" class="seg-btn genuine ${queueState.bucket === 'genuine' ? 'active' : ''}" data-bucket="genuine">Genuine threats</button>
        <button type="button" class="seg-btn flagged ${queueState.bucket === 'flagged' ? 'active' : ''}" data-bucket="flagged">Likely false positive</button>
      </div>
      <div class="panel">
        <div class="toolbar">
          <span class="search-wrap">${icon('search')}<input type="search" id="q-search" placeholder="Search title, asset, technique…" value="${queueState.q}"></span>
          <select id="q-tactic"><option value="">All tactics</option>${TACTICS.map(([id, name]) => html`<option value="${id}" ${queueState.tactic === id ? 'selected' : ''}>${name}</option>`)}</select>
          <select id="q-source"><option value="">All sources</option>${SOURCE_ORDER.map((s) => html`<option value="${s}" ${queueState.source === s ? 'selected' : ''}>${SOURCES[s].label}</option>`)}</select>
          <label><input type="checkbox" id="q-hide" ${queueState.hideSingles ? 'checked' : ''}> Hide single-alert incidents</label>
          <select id="q-sort">
            <option value="score" ${queueState.sort === 'score' ? 'selected' : ''}>Sort: score</option>
            <option value="alerts" ${queueState.sort === 'alerts' ? 'selected' : ''}>Sort: alert count</option>
            <option value="first_seen" ${queueState.sort === 'first_seen' ? 'selected' : ''}>Sort: first seen</option>
          </select>
          <span class="count" id="q-count"></span>
          <button type="button" class="ghost" id="q-export-csv">Export CSV</button>
          <button type="button" class="ghost" id="q-export-xls">Export Excel</button>
        </div>
        <div id="q-table"><div class="loading">loading queue</div></div>
      </div>`;

    let lastSorted = [];
    const refresh = async () => {
      const table = $('#q-table');
      try {
        // Flagged/genuine incidents are not evenly spread across rank, so a
        // bucket filter needs the full population, not just the top page.
        const limit = queueState.bucket === 'all' ? 50 : 500;
        const [incidents, names] = await Promise.all([
          api.incidents({ limit, min_alerts: queueState.hideSingles ? 2 : 1, tactic: queueState.tactic, source: queueState.source, q: queueState.q }),
          ruleNames(),
        ]);
        const bucketed = queueState.bucket === 'all' ? incidents
          : incidents.filter((i) => (queueState.bucket === 'flagged') === isFlagged(i));
        const sorted = bucketed.slice().sort((a, b) => {
          if (queueState.sort === 'alerts') return b.alert_count - a.alert_count || a.rank - b.rank;
          if (queueState.sort === 'first_seen') return String(a.first_seen).localeCompare(String(b.first_seen));
          return a.rank - b.rank;
        });
        lastSorted = sorted;
        table.innerHTML = queueTable(sorted, names);
        bindQueueRows(table);
        $('#q-count').textContent = `${sorted.length} incident${sorted.length === 1 ? '' : 's'}`;
      } catch (err) {
        table.innerHTML = html`<div class="error">${err.message}</div>`;
      }
    };

    $$('#q-bucket .seg-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        queueState.bucket = btn.dataset.bucket;
        $$('#q-bucket .seg-btn').forEach((b) => b.classList.toggle('active', b === btn));
        refresh();
      });
    });

    let debounce;
    $('#q-search').addEventListener('input', (e) => { queueState.q = e.target.value.trim(); clearTimeout(debounce); debounce = setTimeout(refresh, 180); });
    $('#q-tactic').addEventListener('change', (e) => { queueState.tactic = e.target.value; refresh(); });
    $('#q-source').addEventListener('change', (e) => { queueState.source = e.target.value; refresh(); });
    $('#q-hide').addEventListener('change', (e) => { queueState.hideSingles = e.target.checked; refresh(); });
    $('#q-sort').addEventListener('change', (e) => { queueState.sort = e.target.value; refresh(); });
    const queueExportRows = () => {
      const cols = ['Rank', 'Incident', 'Title', 'Composite', 'Alerts', 'Top technique', 'Deepest tactic', 'Assets', 'Sources'];
      const rows = lastSorted.map((inc) => [
        inc.rank, inc.incident_id, inc.title, Math.round(inc.score.composite), inc.alert_count,
        inc.top_technique ? `${inc.top_technique.technique_id} ${inc.top_technique.technique_name}` : '',
        tacticName(deepestTactic(inc.tactics)) || '', (inc.assets || []).join('; '),
        Object.entries(inc.sources || {}).map(([k, v]) => `${k}:${v}`).join('; '),
      ]);
      return { cols, rows };
    };
    $('#q-export-csv').addEventListener('click', () => {
      if (!lastSorted.length) { toast('Nothing to export', true); return; }
      const { cols, rows } = queueExportRows();
      downloadCsv(`aegis-triage-queue-${new Date().toISOString().slice(0, 10)}.csv`, cols, rows);
      toast(`Exported ${lastSorted.length} incidents to CSV`);
    });
    $('#q-export-xls').addEventListener('click', () => {
      if (!lastSorted.length) { toast('Nothing to export', true); return; }
      const { cols, rows } = queueExportRows();
      downloadExcel(`aegis-triage-queue-${new Date().toISOString().slice(0, 10)}.xls`, cols, rows);
      toast(`Exported ${lastSorted.length} incidents to Excel`);
    });
    await refresh();
  }

  // --- Incident detail --------------------------------------------------------
  async function viewIncident(id) {
    const view = $('#view');
    view.innerHTML = html`<div class="loading">loading ${id}</div>`;
    const [inc, names] = await Promise.all([api.incident(id), ruleNames()]);
    const alerts = inc.alerts || [];
    const alertById = new Map(alerts.map((a) => [a.alert_id, a]));
    const sc = inc.score;
    const nSources = Object.keys(inc.sources || {}).length;

    // Technique ids per tactic for the kill-chain strip (attack_chain is in kill-chain order).
    const chainByTactic = new Map();
    for (const t of inc.attack_chain || []) {
      if (!chainByTactic.has(t.tactic)) chainByTactic.set(t.tactic, []);
      chainByTactic.get(t.tactic).push(t);
    }
    const observed = new Set([...(inc.tactics || []), ...chainByTactic.keys()]);
    const deepest = deepestTactic([...observed]);

    view.innerHTML = html`
      <div class="incident-head">
        <a class="back" href="#/queue">${icon('chevLeft')} QUEUE</a>
        <div style="min-width:0">
          <h1>${inc.title}</h1>
          <div class="meta">
            <span class="id">${inc.incident_id}</span>${copyBtn(inc.incident_id, 'incident id')}
            <span>rank <b>#${inc.rank}</b></span>
            <span><b>${inc.alert_count}</b> alerts across <b>${nSources}</b> source${nSources === 1 ? '' : 's'}</span>
            <span>${fmtTs(inc.first_seen)} → ${fmtTs(inc.last_seen)}</span>
            <span>assets <b>${(inc.assets || []).join(', ') || '—'}</b></span>
          </div>
        </div>
        <div class="composite">
          <span class="ring ring-lg" data-tier="${scoreTier(sc.composite)}" style="--pct:${Math.max(0, Math.min(100, sc.composite))}"><span class="ring-num">${Math.round(sc.composite)}</span></span>
          <div class="lbl">composite / 100</div>
        </div>
      </div>

      <div class="disposition-bar" id="disposition-bar"></div>

      <div class="panel">
        <div class="panel-head"><h2>ATT&amp;CK kill chain</h2><span class="hint">observed tactics lit · technique ids beneath · deepest reach drives tactic severity</span></div>
        <div class="killchain">${TACTICS.map(([tid, , short], i) => html`
          <div class="kc ${observed.has(tid) ? 'lit' : ''}" title="${tacticName(tid)}">
            <div class="n">${String(i + 1).padStart(2, '0')}</div>
            <div class="name">${short}</div>
            <div class="tids">${(chainByTactic.get(tid) || []).map((t) => html`<span title="${t.technique_name} (${t.score.toFixed(2)})">${t.technique_id}</span>`)}</div>
          </div>`)}
        </div>
        <div class="kc-legend">
          <span class="depth">deepest tactic: <b>${deepest ? tacticName(deepest) : '—'}</b></span>
          <span>${(inc.attack_chain || []).map((t) => `${t.technique_id} ${t.technique_name}`).join(' → ')}</span>
        </div>
      </div>

      <div class="incident-grid" style="margin-top:14px">
        <div class="col">
          <div class="panel">
            <div class="panel-head"><h2>Score decomposition</h2><span class="hint">four factors, kept separate on purpose</span></div>
            ${scoreFactors(sc, inc.score_explanation, names)}
            <div class="rationale-line">${inc.rationale}</div>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>Alert timeline</h2><span class="hint">${alerts.length} alerts · click to inspect and highlight in graph</span></div>
            <div class="timeline" id="timeline">${alerts.map((a) => {
              const t = topTechnique(a);
              const long = (a.raw_text || '').length > 150;
              return html`<div class="tl-item ${a.source}" data-alert="${a.alert_id}">
                <div class="tl-time"><b>${fmtTime(a.timestamp)}</b>${fmtDate(a.timestamp)}</div>
                <div>
                  <div class="tl-head">${sourceBadge(a.source)} ${sevChip(a.source_severity)} <span class="id">${a.alert_id}</span></div>
                  <div class="tl-text"><span class="short">${truncate(a.raw_text, 150)}</span><span class="full" hidden>${a.raw_text}</span>${long ? html`<span class="more" data-more>more</span>` : ''}</div>
                  <div class="tl-foot"><span>asset <span class="mono">${a.asset ? a.asset.asset_id : '—'}</span></span><span>${techLabel(t)}</span></div>
                </div>
              </div>`;
            })}</div>
          </div>
        </div>
        <div class="col">
          <div class="panel graph-panel">
            <div class="panel-head"><h2>Correlation graph</h2><span class="hint">hover an edge for the evidence trail · drag nodes · click to inspect</span></div>
            <div class="graph-wrap"><canvas id="graph"></canvas><div class="graph-tooltip" id="graph-tip" hidden></div></div>
            <div class="graph-legend">
              ${SOURCE_ORDER.map((s) => html`<span><i class="dot" style="background:${SOURCES[s].color}"></i>${SOURCES[s].label}</span>`)}
              <span class="edge-hint">edge width ∝ total_weight · ${(inc.edges || []).length} edges</span>
            </div>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>Explain correlation</h2><span class="hint">why are these two alerts the same incident?</span></div>
            <form class="explain-form" id="explain-form">
              <select id="ex-a">${alerts.map((a, i) => html`<option value="${a.alert_id}" ${i === 0 ? 'selected' : ''}>${a.alert_id}</option>`)}</select>
              <span class="arrow">↔</span>
              <select id="ex-b">${alerts.map((a, i) => html`<option value="${a.alert_id}" ${i === Math.min(1, alerts.length - 1) ? 'selected' : ''}>${a.alert_id}</option>`)}</select>
              <button type="submit" class="primary">Explain</button>
            </form>
            <div class="explain-result" id="explain-result"></div>
          </div>
        </div>
      </div>

      <div class="panel bluf-panel" id="bluf-panel">
        <div class="panel-head"><h2>BLUF — commander brief</h2><span class="loading">generating brief</span></div>
      </div>`;
    bindCopyButtons(view);
    renderDisposition(inc);

    // -- graph -------------------------------------------------------------
    const graph = new CorrelationGraph($('#graph'), $('#graph-tip'), {
      onNodeClick: (alertId) => selectAlert(alertId),
      nodeTooltip: (node) => {
        const a = node.data; const t = topTechnique(a);
        return html`<h4>${a.alert_id} · ${(SOURCES[a.source] || {}).label || a.source} · ${fmtTs(a.timestamp)}</h4>
          <div>${sevChip(a.source_severity)} <span class="mono">${a.asset ? a.asset.asset_id : 'no asset'}</span></div>
          <div style="margin-top:6px">${truncate(a.raw_text, 180)}</div>
          <div style="margin-top:6px">${techLabel(t)}</div>`.s;
      },
      edgeTooltip: (edge) => edgeEvidence(edge.data).s,
    });
    state.graph = graph;
    graph.setData({
      nodes: alerts.map((a) => ({ id: a.alert_id, label: a.alert_id, color: (SOURCES[a.source] || {}).color, data: a })),
      edges: (inc.edges || []).map((e) => ({ a: e.alert_a, b: e.alert_b, weight: e.total_weight, data: e })),
    });

    // -- timeline interaction -------------------------------------------------
    function selectAlert(alertId) {
      $$('#timeline .tl-item').forEach((el) => el.classList.toggle('selected', el.dataset.alert === alertId));
      graph.select(alertId);
      const a = alertById.get(alertId);
      if (a) openAlertDrawer(a, { incident: inc });
    }
    $$('#timeline .tl-item').forEach((el) => {
      el.addEventListener('click', (ev) => {
        if (ev.target.dataset.more !== undefined) {
          const txt = ev.target.parentElement;
          const showFull = $('.full', txt).hidden;
          $('.full', txt).hidden = !showFull; $('.short', txt).hidden = showFull;
          ev.target.textContent = showFull ? 'less' : 'more';
          ev.stopPropagation();
          return;
        }
        selectAlert(el.dataset.alert);
      });
    });

    // -- explain form ---------------------------------------------------------
    $('#explain-form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const a = $('#ex-a').value, b = $('#ex-b').value;
      const out = $('#explain-result');
      out.innerHTML = html`<div class="loading">explaining ${a} ↔ ${b}</div>`;
      try {
        const r = await api.explain(inc.incident_id, a, b);
        out.innerHTML = html`
          <div class="narrative">${r.narrative}</div>
          ${r.edge ? edgeCard(r.edge, 'direct edge') : ''}
          ${!r.edge && r.path && r.path.length ? html`<div class="path-note">No direct edge — shortest path, ${r.path.length} hop${r.path.length === 1 ? '' : 's'}:</div>${r.path.map((e, i) => edgeCard(e, `hop ${i + 1}`))}` : ''}
          ${!r.edge && !(r.path && r.path.length) ? html`<div class="path-note">${r.same_incident ? 'No path found.' : 'Not in the same incident.'}</div>` : ''}`;
      } catch (err) {
        out.innerHTML = html`<div class="error">${err.message}</div>`;
      }
    });

    // -- BLUF ------------------------------------------------------------------
    renderBluf(inc, nSources);
  }

  /** The evidence trail for one edge: every SignalContribution with its weight and rationale. */
  function edgeEvidence(e) {
    return html`<h4>${e.alert_a} ↔ ${e.alert_b}</h4>
      <div class="tt-total">total_weight ${Number(e.total_weight).toFixed(2)} · ${e.contributions.length} signal${e.contributions.length === 1 ? '' : 's'}</div>
      <div class="contrib">${e.contributions.map((c) => html`
        <span class="sig">${SIGNAL_LABEL[c.signal] || c.signal}</span>
        <span class="w">${Number(c.weight).toFixed(2)}</span>
        <span class="r">${c.rationale}</span>`)}</div>`;
  }

  function edgeCard(e, tag) {
    return html`<div class="edge-card">
      <div class="edge-title"><span class="chip neutral">${tag}</span> <span>${e.alert_a} ↔ ${e.alert_b}</span><span class="w">${Number(e.total_weight).toFixed(2)}</span></div>
      <div class="contrib">${e.contributions.map((c) => html`
        <span class="sig">${SIGNAL_LABEL[c.signal] || c.signal}</span>
        <span class="w">${Number(c.weight).toFixed(2)}</span>
        <span class="r">${c.rationale}</span>`)}</div>
    </div>`;
  }

  /** Analyst TP/FP verdict on an incident. A pure annotation — closes the loop the problem
   * statement calls out ("the cost of error is asymmetric") without feeding back into scoring. */
  function renderDisposition(inc) {
    const el = $('#disposition-bar');
    if (!el) return;
    const d = inc.disposition;
    el.innerHTML = (d
      ? html`<span class="disp-chip ${d.verdict}">${icon(d.verdict === 'confirmed' ? 'check' : 'close')}
          ${d.verdict === 'confirmed' ? 'Confirmed intrusion' : 'Marked false positive'}</span>
        <span class="muted mono">${fmtTs(d.updated_at)}</span>
        <button type="button" class="ghost" id="disp-clear">Undo</button>`
      : html`<span class="muted">Analyst verdict:</span>
        <button type="button" class="disp-btn confirm" id="disp-confirm">${icon('check')} Confirm intrusion</button>
        <button type="button" class="disp-btn fp" id="disp-fp">${icon('close')} Mark false positive</button>`).s;

    const act = async (fn) => { try { await fn(); renderDisposition(inc); } catch (err) { toast(err.message, true); } };
    const confirmBtn = $('#disp-confirm', el);
    const fpBtn = $('#disp-fp', el);
    const clearBtn = $('#disp-clear', el);
    if (confirmBtn) confirmBtn.addEventListener('click', () => act(async () => { inc.disposition = await api.setDisposition(inc.incident_id, 'confirmed'); toast('Marked as confirmed intrusion'); }));
    if (fpBtn) fpBtn.addEventListener('click', () => act(async () => { inc.disposition = await api.setDisposition(inc.incident_id, 'false_positive'); toast('Marked as false positive'); }));
    if (clearBtn) clearBtn.addEventListener('click', () => act(async () => { await api.clearDisposition(inc.incident_id); inc.disposition = null; toast('Disposition cleared'); }));
  }

  async function renderBluf(inc, nSources) {
    const panel = $('#bluf-panel');
    let b;
    try {
      b = inc.bluf || await api.bluf(inc.incident_id);
    } catch (err) {
      if (!panel.isConnected) return;
      panel.innerHTML = html`<div class="panel-head"><h2>BLUF — commander brief</h2></div><div class="error">${err.message}</div>`;
      return;
    }
    if (!panel.isConnected) return; // navigated away while generating
    const list = (items) => html`<ul>${(items || []).map((x) => html`<li>${x}</li>`)}</ul>`;
    const chain = (b.attack_chain || []).map((t) => `${t.technique_id} ${t.technique_name}`).join(' → ');
    const rows = [
      ['BOTTOM LINE', html`${b.bottom_line}`],
      ['CONFIDENCE', html`<span class="conf">${b.confidence}</span> — ${b.confidence_rationale}`],
      ['ASSESSMENT', html`${b.assessment}`],
      ['ATT&CK', html`${chain || '—'}`],
      ['EVIDENCE', list(b.evidence)],
      ['RECOMMENDED', list(b.recommended_actions)],
      ['GAPS', list(b.gaps)],
    ];
    const plain = [
      `BOTTOM LINE: ${b.bottom_line}`,
      `CONFIDENCE:  ${b.confidence} — ${b.confidence_rationale}`,
      `ASSESSMENT:  ${b.assessment}`,
      `ATT&CK:      ${chain}`,
      `EVIDENCE:    ${(b.evidence || []).map((x) => `\n  - ${x}`).join('')}`,
      `RECOMMENDED: ${(b.recommended_actions || []).map((x) => `\n  - ${x}`).join('')}`,
      `GAPS:        ${(b.gaps || []).map((x) => `\n  - ${x}`).join('')}`,
      '',
      `Generated by ${b.generated_by} from ${inc.alert_count} alerts across ${nSources} sources (${inc.incident_id}).`,
    ].join('\n');
    panel.innerHTML = html`
      <div class="panel-head"><h2>BLUF — commander brief</h2>
        <span class="btn-row">
          <button id="bluf-copy" class="ghost">Copy to clipboard</button>
          <button id="bluf-download" class="ghost">Download .txt</button>
          <button id="bluf-print" class="ghost">Print / save PDF</button>
        </span>
      </div>
      <div class="bluf">${rows.map(([k, v]) => html`<div class="bluf-row"><span class="bluf-key">${k}:</span><span class="bluf-val">${v}</span></div>`)}</div>
      <div class="provenance">Generated by <span class="gen ${b.generated_by}">${b.generated_by}</span> from <b>${inc.alert_count}</b> alerts across <b>${nSources}</b> source${nSources === 1 ? '' : 's'} · ${inc.incident_id}</div>`;
    $('#bluf-copy').addEventListener('click', () => copyText(plain));
    $('#bluf-download').addEventListener('click', () => downloadText(`${inc.incident_id}-bluf.txt`, plain));
    $('#bluf-print').addEventListener('click', () => { document.body.classList.add('printing-bluf'); window.print(); });
  }

  /** Saves a blob to disk via a throwaway object URL. */
  function downloadBlob(filename, content, mime) {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  const downloadText = (filename, text) => downloadBlob(filename, text, 'text/plain;charset=utf-8');

  const csvEscape = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  /** headers: string[]; rows: array of arrays (raw cell values, escaped here). */
  const toCsv = (headers, rows) => [headers, ...rows].map((r) => r.map(csvEscape).join(',')).join('\n');
  const downloadCsv = (filename, headers, rows) => downloadBlob(filename, toCsv(headers, rows), 'text/csv;charset=utf-8');

  /** Spreadsheet export with no external library: an HTML `<table>` saved with a
   * .xls extension. Excel, Google Sheets and Numbers all open this natively —
   * the same zero-dependency trick the rest of the console uses to stay
   * offline and build-step-free (see the file header). */
  const downloadExcel = (filename, headers, rows) => {
    const esc = (v) => String(v ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const html = `<html><head><meta charset="utf-8"></head><body><table border="1">`
      + `<thead><tr>${headers.map((h) => `<th>${esc(h)}</th>`).join('')}</tr></thead>`
      + `<tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${esc(c)}</td>`).join('')}</tr>`).join('')}</tbody></table></body></html>`;
    downloadBlob(filename, html, 'application/vnd.ms-excel;charset=utf-8');
  };

  async function copyText(text, announce = true) {
    try {
      if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(text);
      else {
        const ta = document.createElement('textarea');
        ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
        document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove();
      }
      if (announce) toast('Copied to clipboard');
    } catch (_) {
      toast('Copy failed — select the text manually', true);
    }
  }

  // --- Alerts -------------------------------------------------------------------
  const alertsState = { source: '', severity: '', q: '', offset: 0, limit: 25 };
  const KNOWN_SEVERITIES = ['critical', 'high', 'medium', 'low', 'crit', 'err', 'warning', 'notice', 'P1', 'P2', 'P3', 'P4'];

  /** Alerts table. `inspectId` deep-links to an alert drawer; `why` also expands the why-deprioritised closer. */
  async function viewAlerts(inspectId = null, why = false) {
    const view = $('#view');
    view.innerHTML = html`
      <div class="view-title"><h1>Alerts</h1><span class="sub">every normalised alert, newest first · click one to see where it landed and why</span></div>
      <div class="panel">
        <div class="toolbar">
          <span class="search-wrap">${icon('search')}<input type="search" id="a-q" placeholder="Search text, id, asset, indicator…" value="${alertsState.q}"></span>
          <select id="a-source"><option value="">All sources</option>${SOURCE_ORDER.map((s) => html`<option value="${s}" ${alertsState.source === s ? 'selected' : ''}>${SOURCES[s].label}</option>`)}</select>
          <input type="text" id="a-sev" list="sev-list" placeholder="Vendor severity" value="${alertsState.severity}" style="min-width:150px">
          <datalist id="sev-list">${KNOWN_SEVERITIES.map((s) => html`<option value="${s}">`)}</datalist>
          <span class="count" id="a-count"></span>
          <button type="button" class="ghost" id="a-export-csv">Export CSV</button>
          <button type="button" class="ghost" id="a-export-xls">Export Excel</button>
        </div>
        <div id="a-table" class="table-scroll"><div class="loading">loading alerts</div></div>
        <div class="pager" id="a-pager"></div>
      </div>`;

    const refresh = async () => {
      const table = $('#a-table');
      try {
        const r = await api.alerts({ limit: alertsState.limit, offset: alertsState.offset, source: alertsState.source, severity: alertsState.severity, q: alertsState.q });
        const items = r.items || [];
        table.innerHTML = items.length ? html`<div class="a-list">${items.map((a) => html`<div class="a-row row" data-alert="${a.alert_id}">
            <span class="a-dot" style="background:${(SOURCES[a.source] || {}).color || 'var(--muted-2)'}"></span>
            <div class="a-main">
              <div class="a-line1">
                <span class="id">${a.alert_id}</span>
                ${sourceBadge(a.source)}
                ${sevChip(a.source_severity)}
                <span class="ts">${fmtTs(a.timestamp)}</span>
              </div>
              <div class="a-summary">${truncate(a.raw_text, 130)}</div>
              <div class="a-line3">
                <span class="mono muted">${a.asset ? a.asset.asset_id : 'no asset'}</span>
                ${techLabel(topTechnique(a))}
              </div>
            </div>
            <div class="a-side">${a.incident_id ? html`<a href="#/incident/${encodeURIComponent(a.incident_id)}" class="mono">${a.incident_id}</a>` : html`<span class="muted">uncorrelated</span>`}</div>
          </div>`)}</div>` : html`<div class="empty">No alerts match.</div>`;
        $$('.a-row[data-alert]', table).forEach((tr) => {
          tr.addEventListener('click', (ev) => {
            if (ev.target.tagName === 'A') return;
            const a = items.find((x) => x.alert_id === tr.dataset.alert);
            history.replaceState(null, '', `#/alerts/${encodeURIComponent(a.alert_id)}`);
            openAlertDrawer(a, { showWhy: true });
          });
        });
        const from = r.total ? alertsState.offset + 1 : 0, to = Math.min(alertsState.offset + items.length, r.total);
        $('#a-count').textContent = `${r.total} alert${r.total === 1 ? '' : 's'}`;
        $('#a-pager').innerHTML = html`<span>showing ${from}–${to} of ${r.total}</span><span class="spacer"></span>
          <button id="a-prev" class="pager-btn" ${alertsState.offset === 0 ? 'disabled' : ''}>${icon('chevLeft')} prev</button>
          <button id="a-next" class="pager-btn" ${to >= r.total ? 'disabled' : ''}>next ${icon('chevRight')}</button>`;
        $('#a-prev').addEventListener('click', () => { alertsState.offset = Math.max(0, alertsState.offset - alertsState.limit); refresh(); });
        $('#a-next').addEventListener('click', () => { alertsState.offset += alertsState.limit; refresh(); });
      } catch (err) {
        table.innerHTML = html`<div class="error">${err.message}</div>`;
      }
    };
    let debounce;
    const onFilter = () => { alertsState.offset = 0; clearTimeout(debounce); debounce = setTimeout(refresh, 180); };
    $('#a-q').addEventListener('input', (e) => { alertsState.q = e.target.value.trim(); onFilter(); });
    $('#a-sev').addEventListener('input', (e) => { alertsState.severity = e.target.value.trim(); onFilter(); });
    $('#a-source').addEventListener('change', (e) => { alertsState.source = e.target.value; onFilter(); });

    /** Exports every alert matching the current filters, not just the visible page. */
    const exportAlerts = async () => {
      try {
        const r = await api.alerts({ limit: 1000, source: alertsState.source, severity: alertsState.severity, q: alertsState.q });
        const items = r.items || [];
        if (!items.length) { toast('Nothing to export', true); return null; }
        const cols = ['Time', 'Alert', 'Source', 'Vendor severity', 'Asset', 'Top technique', 'Summary', 'Incident'];
        const rows = items.map((a) => [
          fmtTs(a.timestamp), a.alert_id, a.source, a.source_severity || '', a.asset ? a.asset.asset_id : '',
          (() => { const t = topTechnique(a); return t ? `${t.technique_id} ${t.technique_name}` : ''; })(),
          truncate(a.raw_text, 200), a.incident_id || '',
        ]);
        return { cols, rows, count: items.length };
      } catch (err) {
        toast(err.message, true);
        return null;
      }
    };
    $('#a-export-csv').addEventListener('click', async () => {
      const data = await exportAlerts();
      if (!data) return;
      downloadCsv(`aegis-alerts-${new Date().toISOString().slice(0, 10)}.csv`, data.cols, data.rows);
      toast(`Exported ${data.count} alerts to CSV`);
    });
    $('#a-export-xls').addEventListener('click', async () => {
      const data = await exportAlerts();
      if (!data) return;
      downloadExcel(`aegis-alerts-${new Date().toISOString().slice(0, 10)}.xls`, data.cols, data.rows);
      toast(`Exported ${data.count} alerts to Excel`);
    });

    await refresh();

    if (inspectId) {
      try {
        const a = await api.alert(inspectId);
        openAlertDrawer(a, { showWhy: true });
        if (why) { const btn = $('#why-btn'); if (btn) renderWhy(a, btn); }
      } catch (err) { toast(err.message, true); }
    }
  }

  // --- Raw feeds --------------------------------------------------------------------
  async function viewFeeds() {
    const view = $('#view');
    view.innerHTML = html`
      <div class="view-title"><h1>Raw feeds</h1><span class="sub">four consoles that do not talk to each other — what the analyst sees before AEGIS</span></div>
      <div id="feeds"><div class="loading">loading feeds</div></div>`;
    const feeds = await api.feedsRaw(40);
    const panes = [
      ['siem', 'SIEM', 'JSON · one event per line'],
      ['syslog', 'Network sensor', 'syslog · RFC 5424'],
      ['geo', 'Geospatial', 'CSV · flow records'],
      ['intel', 'Intelligence reports', 'prose · TLP-marked'],
    ];
    $('#feeds').innerHTML = html`<div class="feeds">${panes.map(([key, title, fmt]) => html`
      <div class="feed ${key}">
        <div class="feed-head">${sourceBadge(key)} <b>${title}</b><span class="fmt">${fmt}</span></div>
        <pre>${feeds[key] || '(empty)'}</pre>
      </div>`)}</div>
      <div class="feeds-note">Each pane is the feed exactly as it arrives. Severity fields are not comparable across them (Suricata "critical", syslog "warning", geo "P2", intel "high"), which is why AEGIS scores by consequence instead.</div>`;
  }

  // --- ATT&CK --------------------------------------------------------------------------
  async function viewAttack(selectedId) {
    const view = $('#view');
    view.innerHTML = html`
      <div class="view-title"><h1>ATT&amp;CK techniques</h1><span class="sub">search the mapped technique catalogue · click one to see the incidents touching it</span></div>
      <div class="attack-grid">
        <div class="panel">
          <div class="toolbar" style="margin-bottom:8px"><span class="search-wrap" style="flex:1;min-width:0">${icon('search')}<input type="search" id="t-q" placeholder="e.g. powershell, T1059, credential…"></span></div>
          <div class="tech-list" id="t-list"><div class="loading">loading techniques</div></div>
        </div>
        <div class="panel" id="t-detail"><div class="empty">Select a technique to see incidents that touch it.</div></div>
      </div>`;

    const list = $('#t-list');
    const refresh = async () => {
      const q = $('#t-q').value.trim();
      try {
        const techs = await api.techniques(q);
        list.innerHTML = techs.length ? techs.map((t) => html`<div class="tech-item ${t.technique_id === selectedId ? 'active' : ''}" data-tid="${t.technique_id}">
          <span class="counts">${t.incident_count ?? 0} inc · ${t.alert_count ?? 0} alerts</span>
          <span class="tid">${t.technique_id}</span>
          <span class="tname">${t.name}</span>
          <span class="tmeta">${(t.tactics || []).map(tacticName).join(' · ')}</span>
        </div>`).join('') : html`<div class="empty">No techniques match.</div>`.s;
        $$('.tech-item', list).forEach((el) => el.addEventListener('click', () => { location.hash = `#/attack/${encodeURIComponent(el.dataset.tid)}`; }));
      } catch (err) {
        list.innerHTML = html`<div class="error">${err.message}</div>`;
      }
    };
    let debounce;
    $('#t-q').addEventListener('input', () => { clearTimeout(debounce); debounce = setTimeout(refresh, 180); });
    await refresh();

    if (selectedId) {
      const detail = $('#t-detail');
      detail.innerHTML = html`<div class="loading">loading ${selectedId}</div>`;
      try {
        const [r, names] = await Promise.all([api.technique(selectedId), ruleNames()]);
        const t = r.technique || {};
        detail.innerHTML = html`
          <div class="panel-head">
            <div><h1><span class="tid" style="font-size:18px">${t.technique_id || selectedId}</span> ${t.name || ''}</h1>
              <div class="tactic" style="margin-top:4px">${(t.tactics || []).map(tacticName).join(' · ')}</div></div>
            <span class="hint">${(r.incidents || []).length} incident${(r.incidents || []).length === 1 ? '' : 's'} · ${(r.alert_ids || []).length} alert${(r.alert_ids || []).length === 1 ? '' : 's'}</span>
          </div>
          ${queueTable(r.incidents || [], names)}
          ${(r.alert_ids || []).length ? html`<div class="muted" style="margin-top:10px;font-size:11px">Alerts: <span class="mono">${r.alert_ids.join(', ')}</span></div>` : ''}`;
        bindQueueRows(detail);
      } catch (err) {
        detail.innerHTML = html`<div class="error">${err.message}</div>`;
      }
    }
  }

  // --- Verdicts (analyst audit log) ------------------------------------------
  /** Every analyst TP/FP call across all incidents — the audit trail behind the
   * disposition buttons on the incident page. Read-only, sourced from GET /dispositions. */
  async function viewVerdicts() {
    const view = $('#view');
    view.innerHTML = html`
      <div class="view-title"><h1>Verdicts</h1><span class="sub">every analyst TP / FP call, most recent first</span></div>
      <div id="v-summary"></div>
      <div class="panel"><div id="v-list"><div class="loading">loading verdicts</div></div></div>`;

    const list = $('#v-list');
    try {
      const [dispositions, incidents] = await Promise.all([
        api.dispositions(),
        api.incidents({ limit: 500, min_alerts: 1 }),
      ]);
      const incidentById = new Map(incidents.map((i) => [i.incident_id, i]));
      const entries = Object.values(dispositions || {}).sort((a, b) => String(b.updated_at).localeCompare(String(a.updated_at)));

      const confirmed = entries.filter((d) => d.verdict === 'confirmed').length;
      const fp = entries.filter((d) => d.verdict === 'false_positive').length;
      $('#v-summary').innerHTML = html`<div class="v-summary">
        <div class="v-stat"><b>${entries.length}</b> verdict${entries.length === 1 ? '' : 's'} recorded</div>
        <div class="v-stat confirmed"><b>${confirmed}</b> confirmed intrusion${confirmed === 1 ? '' : 's'}</div>
        <div class="v-stat fp"><b>${fp}</b> false positive${fp === 1 ? '' : 's'}</div>
        <span class="btn-row" style="margin-left:auto">
          <button type="button" class="ghost" id="v-export-csv">Export CSV</button>
          <button type="button" class="ghost" id="v-export-xls">Export Excel</button>
        </span>
      </div>`;

      const exportCols = ['Verdict', 'Incident', 'Title', 'Note', 'Analyst', 'Updated at'];
      const exportRows = entries.map((d) => [
        d.verdict, d.incident_id, (incidentById.get(d.incident_id) || {}).title || '', d.note || '', d.analyst || '', fmtTs(d.updated_at),
      ]);
      $('#v-export-csv').addEventListener('click', () => downloadCsv(`aegis-verdicts-${new Date().toISOString().slice(0, 10)}.csv`, exportCols, exportRows));
      $('#v-export-xls').addEventListener('click', () => downloadExcel(`aegis-verdicts-${new Date().toISOString().slice(0, 10)}.xls`, exportCols, exportRows));

      if (!entries.length) {
        list.innerHTML = html`<div class="empty">No analyst verdicts yet — confirm or dismiss an incident from its detail page.</div>`;
        return;
      }
      list.innerHTML = html`<div class="v-list">${entries.map((d) => {
        const inc = incidentById.get(d.incident_id);
        return html`<div class="v-row">
          <span class="disp-chip ${d.verdict}">${icon(d.verdict === 'confirmed' ? 'check' : 'close')} ${d.verdict === 'confirmed' ? 'Confirmed' : 'False positive'}</span>
          <div class="v-main">
            <a href="#/incident/${encodeURIComponent(d.incident_id)}" class="v-title">${inc ? inc.title : d.incident_id}</a>
            ${d.note ? html`<div class="v-note">${d.note}</div>` : ''}
          </div>
          <span class="v-meta mono">${d.analyst || 'analyst'} · ${fmtTs(d.updated_at)}</span>
        </div>`;
      })}</div>`;
    } catch (err) {
      list.innerHTML = html`<div class="error">${err.message}</div>`;
    }
  }

  // --- Assets (criticality inventory) -----------------------------------------
  /** Full asset inventory — the criticality weights that drive the "asset criticality"
   * score factor. Editable here directly, same PATCH /assets/{id} the drawer uses. */
  async function viewAssets() {
    const view = $('#view');
    view.innerHTML = html`
      <div class="view-title"><h1>Assets</h1><span class="sub">criticality inventory · edits apply to the next pipeline run, not retroactively</span></div>
      <div class="panel">
        <div class="toolbar">
          <span class="count" id="as-count"></span>
          <button type="button" class="ghost" id="as-export-csv">Export CSV</button>
          <button type="button" class="ghost" id="as-export-xls">Export Excel</button>
        </div>
        <div id="as-list"><div class="loading">loading assets</div></div>
      </div>`;
    const list = $('#as-list');
    try {
      const assets = await api.assets();
      $('#as-count').textContent = `${assets.length} asset${assets.length === 1 ? '' : 's'}`;
      const exportCols = ['Asset', 'Criticality', 'Role', 'Hostname', 'IP', 'Subnet', 'Rationale'];
      const exportRows = assets.map((a) => [a.asset_id, a.criticality, a.role || '', a.hostname || '', a.ip || '', a.subnet || '', a.rationale || '']);
      $('#as-export-csv').addEventListener('click', () => downloadCsv(`aegis-assets-${new Date().toISOString().slice(0, 10)}.csv`, exportCols, exportRows));
      $('#as-export-xls').addEventListener('click', () => downloadExcel(`aegis-assets-${new Date().toISOString().slice(0, 10)}.xls`, exportCols, exportRows));
      if (!assets.length) { list.innerHTML = html`<div class="empty">No assets in inventory.</div>`; return; }
      list.innerHTML = html`<div class="as-list">${assets.map((a) => html`<div class="as-row" data-asset="${a.asset_id}">
        <span class="as-crit" data-level="${a.criticality}">${a.criticality}</span>
        <div class="as-main">
          <div class="as-line1"><span class="id">${a.asset_id}</span><span class="muted">${a.role || ''}</span></div>
          <div class="as-line2 mono muted">${[a.hostname, a.ip, a.subnet].filter(Boolean).join(' · ')}</div>
          <div class="as-rationale">${a.rationale || ''}</div>
        </div>
        <span class="crit-edit">
          <select data-crit-select>${[1, 2, 3, 4, 5].map((n) => html`<option value="${n}" ${n === a.criticality ? 'selected' : ''}>${n}</option>`)}</select>/5
          <button type="button" class="icon-btn" data-crit-save title="Save criticality override">${icon('check')}</button>
        </span>
      </div>`)}</div>`;
      $$('.as-row', list).forEach((row) => {
        const id = row.dataset.asset;
        $('[data-crit-save]', row).addEventListener('click', async () => {
          const val = Number($('[data-crit-select]', row).value);
          try {
            await api.updateAsset(id, val);
            await assetIndex(true);
            row.querySelector('.as-crit').textContent = val;
            row.querySelector('.as-crit').dataset.level = val;
            toast(`${id} criticality set to ${val}/5`);
          } catch (err) { toast(err.message, true); }
        });
      });
    } catch (err) {
      list.innerHTML = html`<div class="error">${err.message}</div>`;
    }
  }

  // --- Suppression rules (reference) ------------------------------------------
  /** The false-positive-likelihood rule catalogue — read-only reference for what
   * can drag a composite score down, and why. */
  async function viewRules() {
    const view = $('#view');
    view.innerHTML = html`
      <div class="view-title"><h1>Suppression rules</h1><span class="sub">what feeds the false-positive-likelihood factor, and why</span></div>
      <div class="panel"><div id="r-list"><div class="loading">loading rules</div></div></div>`;
    const list = $('#r-list');
    try {
      const rules = await api.suppressionRules();
      if (!rules.length) { list.innerHTML = html`<div class="empty">No suppression rules configured.</div>`; return; }
      list.innerHTML = html`<div class="r-list">${rules.map((r) => html`<div class="rule-card">
        <div class="rname">${r.name}<span class="rid">${r.rule_id}</span></div>
        <div class="rrat">${r.rationale}</div>
      </div>`)}</div>`;
    } catch (err) {
      list.innerHTML = html`<div class="error">${err.message}</div>`;
    }
  }

  // --- IOC watchlist (cross-alert indicator search) ---------------------------
  /** Every indicator extracted across every alert, aggregated by (type, value) with
   * a reappearance count and the alerts it showed up in. Answers the analyst
   * question "have I seen this IP/hash/domain anywhere else?" without hand-grepping
   * the raw feeds. Built client-side from GET /alerts — no new endpoint needed. */
  const iocState = { q: '', sort: 'count' };

  async function viewIocs() {
    const view = $('#view');
    view.innerHTML = html`
      <div class="view-title"><h1>IOC Watchlist</h1><span class="sub">every indicator seen across all alerts, ranked by reappearance</span></div>
      <div class="panel">
        <div class="toolbar">
          <span class="search-wrap">${icon('search')}<input type="search" id="ioc-q" placeholder="Search IP, hash, domain, user, host…"></span>
          <select id="ioc-sort">
            <option value="count">Sort: reappearances</option>
            <option value="value">Sort: value (A–Z)</option>
            <option value="type">Sort: type</option>
          </select>
          <span class="count" id="ioc-count"></span>
          <button type="button" class="ghost" id="ioc-export-csv">Export CSV</button>
          <button type="button" class="ghost" id="ioc-export-xls">Export Excel</button>
        </div>
        <div id="ioc-list"><div class="loading">loading indicators from all alerts</div></div>
      </div>`;

    const list = $('#ioc-list');
    let rows = [];
    let lastFiltered = [];
    try {
      const r = await api.alerts({ limit: 1000 });
      const items = r.items || [];
      const byKey = new Map();
      for (const a of items) {
        for (const ind of a.indicators || []) {
          const key = `${ind.type}|${ind.value}`;
          if (!byKey.has(key)) byKey.set(key, { type: ind.type, value: ind.value, count: 0, alerts: [] });
          const row = byKey.get(key);
          row.count++;
          row.alerts.push({ id: a.alert_id, source: a.source, incident_id: a.incident_id });
        }
      }
      rows = [...byKey.values()];
    } catch (err) {
      list.innerHTML = html`<div class="error">${err.message}</div>`;
      return;
    }

    const render = () => {
      const q = iocState.q.toLowerCase();
      let filtered = q ? rows.filter((r) => r.value.toLowerCase().includes(q) || r.type.toLowerCase().includes(q)) : rows;
      filtered = filtered.slice().sort((a, b) => {
        if (iocState.sort === 'value') return a.value.localeCompare(b.value);
        if (iocState.sort === 'type') return a.type.localeCompare(b.type) || b.count - a.count;
        return b.count - a.count;
      });
      lastFiltered = filtered;
      $('#ioc-count').textContent = `${filtered.length} of ${rows.length} indicators`;
      list.innerHTML = filtered.length ? html`<div class="ioc-list">${filtered.slice(0, 300).map((r) => {
        const shown = r.alerts.slice(0, 4);
        const rest = r.alerts.length - shown.length;
        return html`<div class="ioc-row">
          <span class="chip neutral ioc-type">${r.type}</span>
          <span class="ioc-value mono">${r.value}</span>
          <span class="ioc-count" data-hot="${r.count >= 3 ? '1' : '0'}">${r.count}×</span>
          <div class="ioc-alerts">${shown.map((a) => html`<a class="mono" href="#/alerts/${encodeURIComponent(a.id)}">${a.id}</a>`)}${rest > 0 ? html`<span class="muted">+${rest} more</span>` : ''}</div>
        </div>`;
      })}</div>` : html`<div class="empty">No indicators match.</div>`;
    };

    $('#ioc-q').addEventListener('input', (e) => { iocState.q = e.target.value.trim(); render(); });
    $('#ioc-sort').addEventListener('change', (e) => { iocState.sort = e.target.value; render(); });
    const iocExportRows = () => ({
      cols: ['Type', 'Value', 'Reappearances', 'Seen in alerts'],
      rows: lastFiltered.map((r) => [r.type, r.value, r.count, r.alerts.map((a) => a.id).join('; ')]),
    });
    $('#ioc-export-csv').addEventListener('click', () => {
      if (!lastFiltered.length) { toast('Nothing to export', true); return; }
      const { cols, rows: r } = iocExportRows();
      downloadCsv(`aegis-ioc-watchlist-${new Date().toISOString().slice(0, 10)}.csv`, cols, r);
      toast(`Exported ${lastFiltered.length} indicators to CSV`);
    });
    $('#ioc-export-xls').addEventListener('click', () => {
      if (!lastFiltered.length) { toast('Nothing to export', true); return; }
      const { cols, rows: r } = iocExportRows();
      downloadExcel(`aegis-ioc-watchlist-${new Date().toISOString().slice(0, 10)}.xls`, cols, r);
      toast(`Exported ${lastFiltered.length} indicators to Excel`);
    });
    render();
  }

  // --- Ingest feed (multi-source intake) ---------------------------------------
  /** POST /ingest, exposed directly — the first pillar of the problem statement
   * ("ingests multi-source threat feeds") demonstrated live instead of only via
   * the offline corpus loader. Persists immediately; correlation, scoring and
   * BLUF generation happen on the next pipeline run, same as the asset-criticality
   * override — the console says so rather than implying a live recompute. */
  const INGEST_SAMPLES = {
    siem: [{
      event_id: 'SIEM-DEMO-001', '@timestamp': '2026-09-17T12:00:00Z',
      rule: { id: 'EDR-9001', name: 'PowerShell download cradle retrieved executable content' },
      severity: 'high', category: 'endpoint',
      host: { name: 'ENG-WS-201', ip: '10.20.30.201' },
      message: 'powershell.exe (encoded command) used Net.WebClient to fetch http://cdn-update.northrelay.net/payload.bin; wrote helpersvc.dll (SHA256 7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e).',
      user: { name: 'CORP\\a.reyes' }, destination: { ip: '91.219.237.44' },
      file: { name: 'helpersvc.dll', hash: { sha256: '7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e' } },
      url: { full: 'http://cdn-update.northrelay.net/payload.bin' },
    }],
    syslog: [{
      alert_id: 'SYS-DEMO-001',
      line: '<134>1 2026-09-17T12:00:00Z eng-ws-201 sshd - - [aegis@32473 severity="warning" user="CORP\\a.reyes"] Failed password for invalid user admin from 91.219.237.44 port 51422 ssh2',
    }],
    geo: [{
      alert_id: 'GEO-DEMO-001', track_id: 'TRK-DEMO-001', timestamp_utc: '2026-09-17T12:00:00Z',
      sensor_id: 'RADAR-N1', site_id: 'SITE-CHARLIE', lat: '64.49', lon: '21.01',
      object_class: 'uas', alert_type: 'track_entered_zone', confidence: '0.8', priority: 'P2',
      speed_kts: '22', heading_deg: '180', notes: 'Unidentified small UAS near perimeter',
    }],
    intel: [{
      id: 'INTEL-DEMO-001',
      header: 'DATE: 2026-09-17T12:00:00Z\nSOURCE: Partner ISAC feed\nCLASSIFICATION: UNCLASSIFIED // SYNTHETIC EXERCISE DATA\nPRIORITY: HIGH\nSUBJECT: New C2 infrastructure linked to NORTHRELAY campaign',
      body: 'Partner ISAC reports new command-and-control infrastructure at cdn-update.northrelay.net (91.219.237.44) actively serving second-stage payloads via PowerShell download cradles. Recommend blocking and hunting for helpersvc.dll (SHA-256 7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e).',
    }],
  };
  const INGEST_HINT = {
    siem: 'JSON array of SIEM events — nested host/user/rule/message, same shape as a SIEM export.',
    syslog: 'JSON array of {"line": "<RFC 5424 syslog line>"} — one raw line per record.',
    geo: 'JSON array of CSV-row objects — same columns as a geospatial sensor export.',
    intel: 'JSON array of {"id","header","body"} — a human-authored intelligence report.',
  };

  async function viewIngest() {
    const view = $('#view');
    view.innerHTML = html`
      <div class="view-title"><h1>Ingest feed</h1><span class="sub">push raw records from any source into AEGIS — the entry point for every alert in the queue</span></div>
      <div class="panel">
        <div class="toolbar">
          <select id="ing-source">
            <option value="siem">SIEM (JSON events)</option>
            <option value="syslog">Network sensor (syslog)</option>
            <option value="geo">Geospatial (CSV rows)</option>
            <option value="intel">Intelligence report (prose)</option>
          </select>
          <button type="button" class="ghost" id="ing-sample">Load sample</button>
          <span class="count" id="ing-hint"></span>
        </div>
        <textarea id="ing-body" class="ing-textarea" spellcheck="false" placeholder="Paste a JSON array of raw records…"></textarea>
        <div class="ing-actions">
          <button type="button" class="primary" id="ing-submit">Ingest</button>
          <span class="muted" style="font-size:11px">Persists immediately. Correlation, scoring and BLUFs update on the next pipeline run.</span>
        </div>
        <div id="ing-result"></div>
      </div>`;

    const src = $('#ing-source');
    const body = $('#ing-body');
    const hint = $('#ing-hint');
    const loadSample = () => {
      body.value = JSON.stringify(INGEST_SAMPLES[src.value], null, 2);
      hint.textContent = INGEST_HINT[src.value];
    };
    src.addEventListener('change', loadSample);
    $('#ing-sample').addEventListener('click', loadSample);
    loadSample();

    $('#ing-submit').addEventListener('click', async () => {
      const result = $('#ing-result');
      let records;
      try {
        records = JSON.parse(body.value);
        if (!Array.isArray(records)) throw new Error('Body must be a JSON array of records.');
      } catch (err) {
        result.innerHTML = html`<div class="error">Invalid JSON: ${err.message}</div>`;
        return;
      }
      result.innerHTML = html`<div class="loading">ingesting ${records.length} record${records.length === 1 ? '' : 's'}</div>`;
      try {
        const r = await api.ingest(src.value, records);
        result.innerHTML = html`
          <div class="ing-summary">
            <div class="ov-kpi ok"><b>${r.ingested}</b><span>ingested</span></div>
            <div class="ov-kpi"><b>${r.submitted}</b><span>submitted</span></div>
            <div class="ov-kpi ${r.errors.length ? 'warn' : ''}"><b>${r.errors.length}</b><span>errors</span></div>
          </div>
          ${r.errors.length ? html`<div class="ing-errors">${r.errors.map((e) => html`<div class="error">record ${e.index}: ${e.error}</div>`)}</div>` : ''}
          <div class="rationale-line">${r.note}</div>`;
        toast(`Ingested ${r.ingested} of ${r.submitted} record${r.submitted === 1 ? '' : 's'} from ${src.value}`);
      } catch (err) {
        result.innerHTML = html`<div class="error">${err.message}</div>`;
      }
    });
  }

  // ===========================================================================
  // 6. Alert drawer
  // ===========================================================================

  function closeDrawer() { $('#drawer').hidden = true; }

  /** Opens the side drawer for an AlertView. opts.incident: the IncidentDetail it came from; opts.showWhy: show the closer button. */
  function openAlertDrawer(a, opts = {}) {
    const drawer = $('#drawer');
    const t = topTechnique(a);
    const asset = a.asset;
    drawer.innerHTML = html`
      <div class="drawer-head">${sourceBadge(a.source)} <span class="id">${a.alert_id}</span>${copyBtn(a.alert_id, 'alert id')} ${sevChip(a.source_severity)}<button class="icon-btn close" id="drawer-close" title="Close (Esc)" aria-label="Close">${icon('close')}</button></div>
      <div class="drawer-body">
        <dl class="kv">
          <dt>Timestamp</dt><dd class="mono">${fmtTs(a.timestamp)}</dd>
          <dt>Vendor severity</dt><dd>${sevChip(a.source_severity)} <span class="muted">verbatim, not normalised</span></dd>
          <dt>Asset</dt><dd class="mono">${asset ? html`${asset.asset_id}${asset.hostname ? ` · ${asset.hostname}` : ''}${asset.ip ? ` · ${asset.ip}` : ''}${asset.user_principal ? ` · ${asset.user_principal}` : ''} <span id="crit-slot" class="loading">criticality</span>` : '—'}</dd>
          <dt>Incident</dt><dd>${a.incident_id ? html`<a href="#/incident/${encodeURIComponent(a.incident_id)}" class="mono">${a.incident_id}</a>` : html`<span class="muted">not correlated</span>`}</dd>
          <dt>Queue position</dt><dd class="queue-pos" id="drawer-pos"><span class="loading">looking up</span></dd>
        </dl>
        ${opts.showWhy !== false ? html`<button class="primary why-btn" id="why-btn">Why is this ranked here?</button>` : ''}
        <div id="why-panel"></div>
        <div class="section"><h2>Alert text</h2><div class="raw-text">${a.raw_text}</div></div>
        <div class="section"><h2>ATT&amp;CK mappings</h2>
          ${(a.techniques || []).length ? html`<table class="mini">${a.techniques.map((m) => html`<tr><td>${m.score.toFixed(2)}</td><td class="v">${techLabel(m)}</td><td class="ctx">${tacticName(m.tactic)} · ${m.method}</td></tr>`)}</table>` : html`<div class="muted">unmapped</div>`}
        </div>
        <div class="section"><h2>Indicators (${(a.indicators || []).length})</h2>
          ${(a.indicators || []).length ? html`<table class="mini">${a.indicators.map((i) => html`<tr><td>${i.type}</td><td class="v">${i.value}</td><td class="ctx">${i.context || ''}</td></tr>`)}</table>` : html`<div class="muted">none extracted</div>`}
        </div>
        <div class="section"><h2>Raw payload</h2><pre>${JSON.stringify(a.raw_payload || {}, null, 2)}</pre></div>
      </div>`;
    drawer.hidden = false;
    $('#drawer-close').addEventListener('click', closeDrawer);
    bindCopyButtons(drawer);
    if (asset) loadAssetCriticality(asset.asset_id, drawer);

    // Queue position comes from GET /alerts/{id}; fill it in when it arrives.
    api.alert(a.alert_id).then((full) => {
      const el = $('#drawer-pos');
      if (!el) return;
      el.innerHTML = full.queue_position != null
        ? html`<b>${full.queue_position}</b> of ${full.total_incidents} <span class="muted">(incident rank)</span>`
        : html`<span class="muted">not in queue</span>`;
    }).catch((err) => { const el = $('#drawer-pos'); if (el) el.innerHTML = html`<span class="muted">${err.message}</span>`; });

    const whyBtn = $('#why-btn');
    if (whyBtn) whyBtn.addEventListener('click', () => renderWhy(a, whyBtn));
  }

  /** Fills in the drawer's criticality slot once the asset inventory (GET /assets) resolves,
   * and wires the save button that lets an analyst override it. */
  async function loadAssetCriticality(assetId, drawer) {
    const slot = $('#crit-slot', drawer);
    if (!slot) return;
    const idx = await assetIndex();
    const rec = idx.get(assetId);
    if (!slot.isConnected) return; // drawer closed or reopened for another alert while this was in flight
    slot.classList.remove('loading');
    if (!rec) { slot.innerHTML = html`<span class="muted">not in asset inventory</span>`.s; return; }
    slot.innerHTML = html`<span class="crit-edit">crit
        <select id="crit-select" title="Override this asset's criticality">${[1, 2, 3, 4, 5].map((n) => html`<option value="${n}" ${n === rec.criticality ? 'selected' : ''}>${n}</option>`)}</select>/5
        <button type="button" class="icon-btn" id="crit-save" title="Save criticality override">${icon('check')}</button>
      </span>`.s;
    $('#crit-save', slot).addEventListener('click', async () => {
      const val = Number($('#crit-select', slot).value);
      try {
        await api.updateAsset(assetId, val);
        await assetIndex(true); // refresh the cache so the next drawer open shows the new value
        toast(`${assetId} criticality set to ${val}/5 — applies on the next pipeline run`);
      } catch (err) { toast(err.message, true); }
    });
  }

  /** The demo closer: vendor severity vs AEGIS queue position, with the rules and evidence that explain the gap. */
  async function renderWhy(a, btn) {
    const panel = $('#why-panel');
    btn.disabled = true;
    panel.innerHTML = html`<div class="loading" style="margin-top:12px">asking AEGIS why ${a.alert_id} is ranked where it is</div>`;
    try {
      const [w, names] = await Promise.all([api.whyDeprioritised(a.alert_id), ruleNames()]);
      const rules = w.rules_fired || [];
      panel.innerHTML = html`<div class="whyd">
        <div class="whyd-head"><h2>Why is this ranked here?</h2></div>
        <div class="versus">
          <div class="side vendor"><div class="lbl">Vendor says</div><div class="big">${String(w.vendor_severity || 'n/a').toUpperCase()}</div><div class="sub">${(SOURCES[a.source] || {}).label || a.source} severity, verbatim</div></div>
          <div class="vs">vs</div>
          <div class="side aegis"><div class="lbl">AEGIS ranks it</div><div class="big">${w.queue_position != null ? `${w.queue_position} of ${w.total_incidents}` : '—'}</div><div class="sub">${w.incident_id || 'uncorrelated'} · composite ${Math.round(w.score.composite)}/100</div></div>
        </div>
        <div class="whyd-body">
          <h2>${rules.length ? `${rules.length} suppression rule${rules.length === 1 ? '' : 's'} fired` : 'No suppression rule fired'}</h2>
          ${rules.map((r) => html`<div class="rule-card">
            <div class="rname">${r.name || names.get(r.rule_id) || r.rule_id}<span class="rid">${r.rule_id}</span></div>
            <div class="rrat">${r.rationale}</div>
            ${r.evidence ? html`<div class="rev">${r.evidence}</div>` : ''}
          </div>`)}
          <div class="section"><h2>Score breakdown</h2>${scoreFactors(w.score, null, names)}</div>
          <div class="section"><h2>Narrative</h2><div class="narrative">${w.narrative}</div></div>
        </div>
      </div>`;
      btn.hidden = true;
    } catch (err) {
      panel.innerHTML = html`<div class="error">${err.message}</div>`;
      btn.disabled = false;
    }
  }

  // ===========================================================================
  // 7. Command palette (⌘K quick jump)
  // ===========================================================================

  /** Global fuzzy-ish jump across incidents, alerts, ATT&CK techniques, and assets —
   * the console has seven sections now, and an analyst mid-investigation should
   * not have to click through nav to find one alert id. */
  function initCmdPalette() {
    const overlay = $('#cmdk');
    const input = $('#cmdk-input');
    const results = $('#cmdk-results');

    const open = () => {
      overlay.hidden = false;
      input.value = '';
      results.innerHTML = html`<div class="cmdk-hint">Type to search incidents, alerts, ATT&amp;CK techniques, and assets.</div>`.s;
      setTimeout(() => input.focus(), 0);
    };
    const close = () => { overlay.hidden = true; };

    $('#cmdk-trigger').addEventListener('click', open);
    overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
    document.addEventListener('keydown', (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); overlay.hidden ? open() : close(); return; }
      if (e.key === 'Escape' && !overlay.hidden) close();
    });

    const runSearch = async (query) => {
      if (!query) { results.innerHTML = html`<div class="cmdk-hint">Type to search incidents, alerts, ATT&amp;CK techniques, and assets.</div>`.s; return; }
      try {
        const [incidents, alertsRes, techs, assets] = await Promise.all([
          api.incidents({ limit: 6, min_alerts: 1, q: query }),
          api.alerts({ limit: 6, q: query }),
          api.techniques(query),
          assetIndex(),
        ]);
        const ql = query.toLowerCase();
        const assetMatches = [...assets.values()]
          .filter((a) => `${a.asset_id} ${a.hostname || ''} ${a.role || ''}`.toLowerCase().includes(ql))
          .slice(0, 6);

        const groups = [
          ['Incidents', incidents.map((i) => ({ label: i.title, sub: `${i.incident_id} · rank #${i.rank} · ${Math.round(i.score.composite)}/100`, go: () => { location.hash = `#/incident/${encodeURIComponent(i.incident_id)}`; } }))],
          ['Alerts', (alertsRes.items || []).map((a) => ({ label: a.alert_id, sub: truncate(a.raw_text, 70), go: () => { location.hash = `#/alerts/${encodeURIComponent(a.alert_id)}`; } }))],
          ['ATT&CK techniques', techs.slice(0, 6).map((t) => ({ label: `${t.technique_id} ${t.name}`, sub: (t.tactics || []).map(tacticName).join(' · '), go: () => { location.hash = `#/attack/${encodeURIComponent(t.technique_id)}`; } }))],
          ['Assets', assetMatches.map((a) => ({ label: a.asset_id, sub: a.role || a.hostname || '', go: () => { alertsState.q = a.asset_id; alertsState.offset = 0; location.hash = '#/alerts'; } }))],
        ].filter(([, items]) => items.length);

        if (!groups.length) { results.innerHTML = html`<div class="cmdk-hint">No matches for "${query}".</div>`; return; }

        results.innerHTML = groups.map(([label, items]) => html`
          <div class="cmdk-group">
            <div class="cmdk-group-lbl">${label}</div>
            ${items.map((it) => html`<button type="button" class="cmdk-item">
              <span class="cmdk-item-label">${it.label}</span>
              <span class="cmdk-item-sub">${it.sub}</span>
            </button>`)}
          </div>`).join('');

        const flat = groups.flatMap(([, items]) => items);
        $$('.cmdk-item', results).forEach((btn, i) => btn.addEventListener('click', () => { flat[i].go(); close(); }));
      } catch (err) {
        results.innerHTML = html`<div class="cmdk-hint">${err.message}</div>`;
      }
    };

    let debounce;
    input.addEventListener('input', () => { clearTimeout(debounce); debounce = setTimeout(() => runSearch(input.value.trim()), 160); });
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { const first = $('.cmdk-item', results); if (first) first.click(); }
    });
  }

  // ===========================================================================
  // Boot
  // ===========================================================================

  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeDrawer(); });
  document.addEventListener('click', (e) => {
    // Click outside the drawer closes it (but not clicks that navigate or sit inside it).
    const drawer = $('#drawer');
    if (drawer.hidden || drawer.contains(e.target)) return;
    if (e.target.closest('.tl-item, canvas, tr.row, .a-row, .q-card')) return; // those re-open it with new content
    closeDrawer();
  });
  window.addEventListener('hashchange', route);
  window.addEventListener('afterprint', () => document.body.classList.remove('printing-bluf'));

  if (state.mock) $('#mock-badge').hidden = false;
  initCmdPalette();
  renderStats();
  route();
})();
