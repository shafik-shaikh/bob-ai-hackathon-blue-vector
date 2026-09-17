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
    [/^#\/queue\/?$/, () => viewQueue()],
    [/^#\/incident\/([^/]+)\/?$/, (m) => viewIncident(decodeURIComponent(m[1]))],
    [/^#\/alerts(?:\/([^/]+))?(\/why)?\/?$/, (m) => viewAlerts(m[1] ? decodeURIComponent(m[1]) : null, !!m[2])],
    [/^#\/feeds\/?$/, () => viewFeeds()],
    [/^#\/attack(?:\/([^/]+))?\/?$/, (m) => viewAttack(m[1] ? decodeURIComponent(m[1]) : null)],
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
      <div class="rationale">${inc.rationale}</div>
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
        ${explanation && explanation[key] ? html`<p class="why">${explanation[key]}</p>` : ''}
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

  // --- Triage queue ---------------------------------------------------------
  const queueState = { tactic: '', source: '', q: '', hideSingles: true, sort: 'score' };

  async function viewQueue() {
    const view = $('#view');
    view.innerHTML = html`
      <div class="view-title"><h1>Triage queue</h1><span class="sub">incidents ranked by consequence, not vendor severity</span></div>
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
        </div>
        <div id="q-table"><div class="loading">loading queue</div></div>
      </div>`;

    const refresh = async () => {
      const table = $('#q-table');
      try {
        const [incidents, names] = await Promise.all([
          api.incidents({ limit: 50, min_alerts: queueState.hideSingles ? 2 : 1, tactic: queueState.tactic, source: queueState.source, q: queueState.q }),
          ruleNames(),
        ]);
        const sorted = incidents.slice().sort((a, b) => {
          if (queueState.sort === 'alerts') return b.alert_count - a.alert_count || a.rank - b.rank;
          if (queueState.sort === 'first_seen') return String(a.first_seen).localeCompare(String(b.first_seen));
          return a.rank - b.rank;
        });
        table.innerHTML = queueTable(sorted, names);
        bindQueueRows(table);
        $('#q-count').textContent = `${sorted.length} incident${sorted.length === 1 ? '' : 's'}`;
      } catch (err) {
        table.innerHTML = html`<div class="error">${err.message}</div>`;
      }
    };

    let debounce;
    $('#q-search').addEventListener('input', (e) => { queueState.q = e.target.value.trim(); clearTimeout(debounce); debounce = setTimeout(refresh, 180); });
    $('#q-tactic').addEventListener('change', (e) => { queueState.tactic = e.target.value; refresh(); });
    $('#q-source').addEventListener('change', (e) => { queueState.source = e.target.value; refresh(); });
    $('#q-hide').addEventListener('change', (e) => { queueState.hideSingles = e.target.checked; refresh(); });
    $('#q-sort').addEventListener('change', (e) => { queueState.sort = e.target.value; refresh(); });
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
        </span>
      </div>
      <div class="bluf">${rows.map(([k, v]) => html`<div class="bluf-row"><span class="bluf-key">${k}:</span><span class="bluf-val">${v}</span></div>`)}</div>
      <div class="provenance">Generated by <span class="gen ${b.generated_by}">${b.generated_by}</span> from <b>${inc.alert_count}</b> alerts across <b>${nSources}</b> source${nSources === 1 ? '' : 's'} · ${inc.incident_id}</div>`;
    $('#bluf-copy').addEventListener('click', () => copyText(plain));
    $('#bluf-download').addEventListener('click', () => downloadText(`${inc.incident_id}-bluf.txt`, plain));
  }

  /** Saves a text blob to disk via a throwaway object URL — used for the BLUF commander brief. */
  function downloadText(filename, text) {
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

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

  if (state.mock) $('#mock-badge').hidden = false;
  renderStats();
  route();
})();
