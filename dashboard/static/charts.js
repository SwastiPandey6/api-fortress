/* Lightweight SVG charts (no external dependencies, works offline). */
(function () {
  "use strict";
  const NS = "http://www.w3.org/2000/svg";
  const tip = () => document.getElementById("tooltip");

  function el(name, attrs, parent) {
    const node = document.createElementNS(NS, name);
    for (const k in attrs) node.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(node);
    return node;
  }

  function esc(s) {
    return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  function showTip(evt, title, rows) {
    const t = tip();
    t.innerHTML = `<div class="tt-title">${esc(title)}</div>` +
      rows.map((r) => `<div class="tt-row"><i style="background:${r.color}"></i><span>${esc(r.label)}</span><b>${esc(r.value)}</b></div>`).join("");
    t.hidden = false;
    const pad = 14;
    const w = t.offsetWidth, h = t.offsetHeight;
    let x = evt.clientX + pad, y = evt.clientY - h - pad;
    if (x + w > window.innerWidth - 8) x = evt.clientX - w - pad;
    if (y < 8) y = evt.clientY + pad;
    t.style.left = x + "px";
    t.style.top = y + "px";
  }
  function hideTip() { tip().hidden = true; }

  function niceMax(v) {
    if (v <= 4) return 4;
    const p = Math.pow(10, Math.floor(Math.log10(v)));
    for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
    return 10 * p;
  }

  /**
   * Stacked column chart.
   * series: [{key, label, color}] ordered bottom -> top
   */
  function stackedBars(container, buckets, series, opts = {}) {
    const width = Math.max(container.clientWidth, 280);
    const height = opts.height || 240;
    const m = { top: 8, right: 4, bottom: 26, left: 34 };
    const iw = width - m.left - m.right, ih = height - m.top - m.bottom;
    container.innerHTML = "";
    const svg = el("svg", { viewBox: `0 0 ${width} ${height}`, height, role: "img", "aria-label": opts.label || "Chart" }, container);

    const totals = buckets.map((b) => series.reduce((s, x) => s + (b[x.key] || 0), 0));
    const max = niceMax(Math.max(1, ...totals));
    const y = (v) => m.top + ih - (v / max) * ih;

    for (let i = 0; i <= 4; i++) {
      const v = (max / 4) * i, yy = y(v);
      el("line", { x1: m.left, x2: width - m.right, y1: yy, y2: yy, class: i === 0 ? "axis-line" : "grid-line" }, svg);
      const t = el("text", { x: m.left - 8, y: yy + 3.5, "text-anchor": "end" }, svg);
      t.textContent = Number.isInteger(v) ? v : v.toFixed(1);
    }

    const n = buckets.length;
    const slot = iw / n;
    const bw = Math.max(2, Math.min(22, slot * 0.62));
    const labelEvery = Math.ceil(n / Math.max(1, Math.floor(iw / 64)));
    const r = Math.min(3, bw / 2);

    buckets.forEach((b, i) => {
      const cx = m.left + slot * i + slot / 2;
      const x0 = cx - bw / 2;
      let acc = 0;
      const segs = series.map((s) => ({ s, v: b[s.key] || 0 })).filter((d) => d.v > 0);
      segs.forEach((d, j) => {
        const top = y(acc + d.v), bottom = y(acc);
        const gap = j > 0 ? 1 : 0; // 2px surface gap between stacked segments (1px each side)
        const h = Math.max(0, bottom - top - gap * 2);
        const isTop = j === segs.length - 1;
        if (isTop && h > r) {
          const yy = top + gap;
          el("path", {
            d: `M${x0},${yy + h} V${yy + r} Q${x0},${yy} ${x0 + r},${yy} H${x0 + bw - r} Q${x0 + bw},${yy} ${x0 + bw},${yy + r} V${yy + h} Z`,
            fill: d.s.color,
          }, svg);
        } else {
          el("rect", { x: x0, y: top + gap, width: bw, height: Math.max(h, 1), fill: d.s.color }, svg);
        }
        acc += d.v;
      });
      if (i % labelEvery === 0) {
        const t = el("text", { x: cx, y: height - 8, "text-anchor": "middle" }, svg);
        t.textContent = b.label;
      }
      const hit = el("rect", { x: m.left + slot * i, y: m.top, width: slot, height: ih, fill: "transparent" }, svg);
      hit.addEventListener("mousemove", (e) => {
        hit.setAttribute("fill", "rgba(255,255,255,0.035)");
        showTip(e, b.label + (opts.tipSuffix || ""), series.map((s) => ({ label: s.label, value: b[s.key] || 0, color: s.color })));
      });
      hit.addEventListener("mouseleave", () => { hit.setAttribute("fill", "transparent"); hideTip(); });
    });
  }

  /** Donut chart. segments: [{label, value, color}] */
  function donut(container, segments, center) {
    const size = 160, stroke = 18, r = (size - stroke) / 2, c = 2 * Math.PI * r;
    container.innerHTML = "";
    const svg = el("svg", { viewBox: `0 0 ${size} ${size}`, width: size, height: size, role: "img", "aria-label": center.label }, container);
    el("circle", { cx: size / 2, cy: size / 2, r, fill: "none", stroke: "var(--surface-2)", "stroke-width": stroke }, svg);
    const total = segments.reduce((s, d) => s + d.value, 0);
    let offset = 0;
    const visible = segments.filter((d) => d.value > 0);
    const gap = visible.length > 1 ? 2 : 0;
    visible.forEach((d) => {
      const len = (d.value / total) * c;
      const arc = el("circle", {
        cx: size / 2, cy: size / 2, r, fill: "none", stroke: d.color, "stroke-width": stroke,
        "stroke-dasharray": `${Math.max(len - gap, 0.5)} ${c}`, "stroke-dashoffset": -offset,
        transform: `rotate(-90 ${size / 2} ${size / 2})`,
      }, svg);
      arc.style.cursor = "default";
      arc.addEventListener("mousemove", (e) => showTip(e, d.label, [{ label: "Requests", value: `${d.value} (${((100 * d.value) / total).toFixed(1)}%)`, color: d.color }]));
      arc.addEventListener("mouseleave", hideTip);
      offset += len;
    });
    const t1 = el("text", { x: size / 2, y: size / 2 + 2, "text-anchor": "middle", style: "fill:var(--text);font:600 24px var(--font)" }, svg);
    t1.textContent = center.value;
    const t2 = el("text", { x: size / 2, y: size / 2 + 20, "text-anchor": "middle", style: "fill:var(--muted);font:12px var(--font)" }, svg);
    t2.textContent = center.label;
  }

  window.Charts = { stackedBars, donut, showTip, hideTip };
})();
