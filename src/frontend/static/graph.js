/* AEGIS analyst console — correlation graph.
 *
 * A small self-contained force-directed layout on a <canvas>. Nodes are alerts,
 * edges are CorrelationEdges; edge thickness is proportional to total_weight.
 * No framework, no library: the layout is a Fruchterman–Reingold style
 * simulation (pairwise repulsion + spring attraction along edges + a weak pull
 * to the centre) run for ~200 iterations up-front and then allowed to settle
 * over a few animation frames. Dragging a node re-heats the simulation so the
 * neighbours follow.
 *
 * The graph is deliberately UI-agnostic: it knows nothing about incidents or
 * alerts. app.js supplies colours, tooltip HTML and click handling.
 *
 *   const g = new CorrelationGraph(canvas, tooltipEl, {
 *     onNodeClick: (id) => {},
 *     nodeTooltip: (node) => '<html>',
 *     edgeTooltip: (edge) => '<html>',
 *   });
 *   g.setData({ nodes: [{ id, label, color, data }], edges: [{ a, b, weight, data }] });
 *   g.select(id);
 */
(function () {
  'use strict';

  const NODE_R = 15;
  const ITERATIONS = 200;
  const SETTLE_FRAMES = 70;

  class CorrelationGraph {
    constructor(canvas, tooltipEl, opts = {}) {
      this.canvas = canvas;
      this.ctx = canvas.getContext('2d');
      this.tooltip = tooltipEl;
      this.opts = opts;
      this.nodes = [];
      this.edges = [];
      this.byId = new Map();
      this.hover = null;      // { type: 'node'|'edge', item }
      this.selected = null;   // node id
      this.drag = null;       // node being dragged
      this.alpha = 0;         // simulation temperature; 0 = frozen
      this.raf = null;
      this.width = 0;
      this.height = 0;

      this._onMove = this._onMove.bind(this);
      this._onDown = this._onDown.bind(this);
      this._onUp = this._onUp.bind(this);
      this._onLeave = this._onLeave.bind(this);
      canvas.addEventListener('pointermove', this._onMove);
      canvas.addEventListener('pointerdown', this._onDown);
      window.addEventListener('pointerup', this._onUp);
      canvas.addEventListener('pointerleave', this._onLeave);

      this.ro = new ResizeObserver(() => this._resize());
      this.ro.observe(canvas.parentElement);
      this._resize();
    }

    destroy() {
      this.ro.disconnect();
      cancelAnimationFrame(this.raf);
      this.canvas.removeEventListener('pointermove', this._onMove);
      this.canvas.removeEventListener('pointerdown', this._onDown);
      window.removeEventListener('pointerup', this._onUp);
      this.canvas.removeEventListener('pointerleave', this._onLeave);
    }

    // ------------------------------------------------------------ data
    setData({ nodes, edges }) {
      const w = this.width || 600, h = this.height || 400;
      this.nodes = nodes.map((n, i) => {
        // Start on a circle so the initial state is symmetric and the
        // simulation does not have to untangle a random blob.
        const ang = (i / nodes.length) * Math.PI * 2 - Math.PI / 2;
        const r = Math.min(w, h) * 0.32;
        return Object.assign({}, n, { x: w / 2 + Math.cos(ang) * r, y: h / 2 + Math.sin(ang) * r, vx: 0, vy: 0, fixed: false });
      });
      this.byId = new Map(this.nodes.map((n) => [n.id, n]));
      this.edges = edges
        .filter((e) => this.byId.has(e.a) && this.byId.has(e.b))
        .map((e) => Object.assign({}, e, { na: this.byId.get(e.a), nb: this.byId.get(e.b) }));
      this.selected = null;
      this.hover = null;

      // Up-front layout: run the simulation to convergence synchronously, then
      // animate a short low-temperature settle so the first paint is calm.
      let a = 1;
      for (let i = 0; i < ITERATIONS; i++) { this._tick(a); a *= 0.975; }
      this.alpha = 0.06;
      this._settleFrames = SETTLE_FRAMES;
      this._loop();
    }

    select(id) {
      this.selected = id;
      this._draw();
    }

    // ------------------------------------------------------------ physics
    _tick(alpha) {
      const nodes = this.nodes, W = this.width, H = this.height;
      const n = nodes.length;
      if (!n) return;
      const k = Math.sqrt((W * H) / (n + 1)) * 0.55;   // ideal edge length
      const temp = alpha * Math.max(W, H) * 0.08;      // max displacement this tick

      for (const v of nodes) { v.vx = 0; v.vy = 0; }

      // Repulsion between every pair (n is small: an incident has a handful of alerts).
      for (let i = 0; i < n; i++) {
        for (let j = i + 1; j < n; j++) {
          const a = nodes[i], b = nodes[j];
          let dx = a.x - b.x, dy = a.y - b.y;
          let d2 = dx * dx + dy * dy;
          if (d2 < 1) { dx = (Math.random() - 0.5); dy = (Math.random() - 0.5); d2 = 1; }
          const d = Math.sqrt(d2);
          const f = (k * k) / d;
          const fx = (dx / d) * f, fy = (dy / d) * f;
          a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
        }
      }
      // Springs along edges. Heavier edges pull harder and settle shorter, so the
      // strongest evidence reads as the tightest cluster.
      for (const e of this.edges) {
        const a = e.na, b = e.nb;
        const dx = a.x - b.x, dy = a.y - b.y;
        const d = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
        const strength = 0.6 + Math.min(e.weight, 1) * 0.9;
        const f = ((d * d) / k) * strength;
        const fx = (dx / d) * f, fy = (dy / d) * f;
        a.vx -= fx; a.vy -= fy; b.vx += fx; b.vy += fy;
      }
      // Weak gravity toward the centre keeps disconnected pieces on screen.
      for (const v of nodes) {
        v.vx += (W / 2 - v.x) * 0.9;
        v.vy += (H / 2 - v.y) * 0.9;
      }
      // Apply, capped by temperature, then clamp inside the canvas.
      const pad = NODE_R + 26;
      for (const v of nodes) {
        if (v.fixed) continue;
        const len = Math.sqrt(v.vx * v.vx + v.vy * v.vy) || 1;
        const step = Math.min(len, temp);
        v.x += (v.vx / len) * step;
        v.y += (v.vy / len) * step;
        v.x = Math.max(pad, Math.min(W - pad, v.x));
        v.y = Math.max(pad, Math.min(H - pad, v.y));
      }
    }

    _loop() {
      cancelAnimationFrame(this.raf);
      this.running = true;
      const step = () => {
        if (this.alpha > 0.001) {
          this._tick(this.alpha);
          if (!this.drag) {
            this.alpha *= 0.94;
            if (--this._settleFrames <= 0) this.alpha = 0;
          }
          this._draw();
          this.raf = requestAnimationFrame(step);
        } else {
          this.alpha = 0;
          this.running = false;
          this._draw();
        }
      };
      this.raf = requestAnimationFrame(step);
    }

    // ------------------------------------------------------------ sizing
    _resize() {
      const parent = this.canvas.parentElement;
      const w = parent.clientWidth, h = parent.clientHeight;
      if (!w || !h) return;
      const dpr = window.devicePixelRatio || 1;
      const sx = this.width ? w / this.width : 1, sy = this.height ? h / this.height : 1;
      this.width = w; this.height = h;
      this.canvas.width = Math.round(w * dpr);
      this.canvas.height = Math.round(h * dpr);
      this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      for (const v of this.nodes) { v.x *= sx; v.y *= sy; }
      this._draw();
    }

    // ------------------------------------------------------------ drawing
    _draw() {
      const ctx = this.ctx, W = this.width, H = this.height;
      ctx.clearRect(0, 0, W, H);
      if (!this.nodes.length) {
        ctx.fillStyle = '#56616e';
        ctx.font = '12px monospace';
        ctx.textAlign = 'center';
        ctx.fillText('no correlation edges — single-alert incident', W / 2, H / 2);
        return;
      }
      const sel = this.selected;
      const hov = this.hover;

      // Edges first so nodes sit on top.
      for (const e of this.edges) {
        const isHov = hov && hov.type === 'edge' && hov.item === e;
        const touchesSel = sel && (e.a === sel || e.b === sel);
        const w = 1.2 + Math.min(e.weight, 1.2) * 7;
        ctx.beginPath();
        ctx.moveTo(e.na.x, e.na.y);
        ctx.lineTo(e.nb.x, e.nb.y);
        ctx.lineWidth = isHov ? w + 2 : w;
        ctx.strokeStyle = isHov ? 'rgba(61,219,184,0.95)'
          : touchesSel ? 'rgba(61,219,184,0.75)'
          : `rgba(61,219,184,${0.22 + Math.min(e.weight, 1) * 0.4})`;
        ctx.lineCap = 'round';
        ctx.stroke();
        // Weight label at the midpoint.
        const mx = (e.na.x + e.nb.x) / 2, my = (e.na.y + e.nb.y) / 2;
        const label = e.weight.toFixed(2);
        ctx.font = '10px "JetBrains Mono", Consolas, monospace';
        const tw = ctx.measureText(label).width + 8;
        ctx.fillStyle = isHov ? '#3ddbb8' : '#161c25';
        ctx.fillRect(mx - tw / 2, my - 8, tw, 15);
        ctx.fillStyle = isHov ? '#06231c' : '#9fb0bf';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(label, mx, my);
      }

      for (const v of this.nodes) {
        const isSel = v.id === sel;
        const isHov = hov && hov.type === 'node' && hov.item === v;
        if (isSel) {
          ctx.beginPath();
          ctx.arc(v.x, v.y, NODE_R + 6, 0, Math.PI * 2);
          ctx.strokeStyle = 'rgba(61,219,184,0.9)';
          ctx.lineWidth = 2;
          ctx.stroke();
        }
        ctx.beginPath();
        ctx.arc(v.x, v.y, NODE_R, 0, Math.PI * 2);
        ctx.fillStyle = v.color || '#7f8b99';
        ctx.fill();
        ctx.lineWidth = isHov ? 3 : 2;
        ctx.strokeStyle = isHov ? '#f2f5f8' : '#0b0f15';
        ctx.stroke();
        // Label below the node.
        ctx.font = '11px "JetBrains Mono", Consolas, monospace';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        ctx.fillStyle = isSel || isHov ? '#f2f5f8' : '#c3ccd6';
        ctx.fillText(v.label || v.id, v.x, v.y + NODE_R + 5);
      }
    }

    // ------------------------------------------------------------ hit testing
    _pos(ev) {
      const r = this.canvas.getBoundingClientRect();
      return { x: ev.clientX - r.left, y: ev.clientY - r.top };
    }

    _hit(p) {
      for (let i = this.nodes.length - 1; i >= 0; i--) {
        const v = this.nodes[i];
        const dx = v.x - p.x, dy = v.y - p.y;
        if (dx * dx + dy * dy <= (NODE_R + 4) * (NODE_R + 4)) return { type: 'node', item: v };
      }
      let best = null, bestD = Infinity;
      for (const e of this.edges) {
        const d = segDist(p, e.na, e.nb);
        const tol = Math.max(7, 1.2 + Math.min(e.weight, 1.2) * 7);
        if (d <= tol && d < bestD) { best = e; bestD = d; }
      }
      return best ? { type: 'edge', item: best } : null;
    }

    // ------------------------------------------------------------ events
    _onMove(ev) {
      const p = this._pos(ev);
      if (this.drag) {
        this.drag.x = p.x; this.drag.y = p.y;
        this.alpha = Math.max(this.alpha, 0.05);
        this._settleFrames = 40;
        if (!this.running) this._loop();
        this._draw();
        this._hideTip();
        return;
      }
      const hit = this._hit(p);
      const changed = (hit && hit.item) !== (this.hover && this.hover.item);
      this.hover = hit;
      this.canvas.style.cursor = hit ? (hit.type === 'node' ? 'grab' : 'help') : 'default';
      if (changed) this._draw();
      if (hit) this._showTip(hit, p); else this._hideTip();
    }

    _onDown(ev) {
      const hit = this._hit(this._pos(ev));
      if (hit && hit.type === 'node') {
        this.drag = hit.item;
        this.drag.fixed = true;
        this._dragStart = this._pos(ev);
        this.canvas.classList.add('dragging');
        this.canvas.setPointerCapture(ev.pointerId);
      }
    }

    _onUp(ev) {
      if (!this.drag) return;
      const node = this.drag;
      node.fixed = false;
      this.drag = null;
      this.canvas.classList.remove('dragging');
      // A click (no meaningful movement) selects the node.
      const p = this._pos(ev);
      const moved = Math.hypot(p.x - this._dragStart.x, p.y - this._dragStart.y) > 4;
      if (!moved && this.opts.onNodeClick) this.opts.onNodeClick(node.id);
      this.alpha = 0.04;
      this._settleFrames = 30;
      this._loop();
    }

    _onLeave() {
      this.hover = null;
      this._hideTip();
      this._draw();
    }

    // ------------------------------------------------------------ tooltip
    _showTip(hit, p) {
      const html = hit.type === 'node'
        ? (this.opts.nodeTooltip ? this.opts.nodeTooltip(hit.item) : hit.item.id)
        : (this.opts.edgeTooltip ? this.opts.edgeTooltip(hit.item) : `${hit.item.a} — ${hit.item.b}`);
      const tip = this.tooltip;
      tip.innerHTML = html;
      tip.hidden = false;
      // Place beside the cursor; flip when it would overflow the canvas.
      const pad = 14;
      let left = p.x + pad, top = p.y + pad;
      const tw = tip.offsetWidth, th = tip.offsetHeight;
      if (left + tw > this.width - 6) left = Math.max(6, p.x - tw - pad);
      if (top + th > this.height - 6) top = Math.max(6, p.y - th - pad);
      tip.style.left = left + 'px';
      tip.style.top = top + 'px';
    }

    _hideTip() { this.tooltip.hidden = true; }
  }

  function segDist(p, a, b) {
    const dx = b.x - a.x, dy = b.y - a.y;
    const l2 = dx * dx + dy * dy;
    if (l2 === 0) return Math.hypot(p.x - a.x, p.y - a.y);
    let t = ((p.x - a.x) * dx + (p.y - a.y) * dy) / l2;
    t = Math.max(0, Math.min(1, t));
    return Math.hypot(p.x - (a.x + t * dx), p.y - (a.y + t * dy));
  }

  window.CorrelationGraph = CorrelationGraph;
})();
