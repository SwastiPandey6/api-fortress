/* API Fortress — Security Console (vanilla JS single-page app). */
(function () {
  "use strict";

  // ------------------------------------------------------------------ utils
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const fmt = (n) => (n == null ? "—" : Number(n).toLocaleString());
  const cap = (s) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : "");
  const human = (s) => (s || "").replace(/_/g, " ");
  const SEV = ["info", "low", "medium", "high", "critical"];
  const COLORS = {
    allowed: "var(--ok)", flagged: "var(--warn)", blocked: "var(--bad)", errors: "var(--neutral)",
    sev: ["var(--sev-0)", "var(--sev-1)", "var(--sev-2)", "var(--sev-3)", "var(--sev-4)"],
  };
  const debounce = (fn, ms = 300) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };

  function parseDate(iso) { return iso ? new Date(iso) : null; }
  function timeAgo(iso) {
    const d = parseDate(iso); if (!d) return "—";
    const s = Math.round((Date.now() - d.getTime()) / 1000);
    if (s < 5) return "just now";
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    return d.toLocaleDateString(undefined, { day: "numeric", month: "short" });
  }
  function fullTime(iso) {
    const d = parseDate(iso); if (!d) return "—";
    return d.toLocaleString(undefined, { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }
  function shortTime(iso) {
    const d = parseDate(iso); if (!d) return "—";
    return d.toLocaleString(undefined, { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }

  const LABELS = { api_probing: "API probing", auth_failure: "Authentication failure", modsecurity: "ModSecurity", wazuh: "Wazuh", suricata: "Suricata", api_gateway: "Gateway", mixed: "Mixed" };
  const label = (s) => LABELS[s] || cap(human(s));
  const badge = (decision, variant) => `<span class="badge b-${esc(variant || decision)}">${esc(cap(decision))}</span>`;
  const sevTag = (n) => `<span class="sev" data-s="${n}"><i><b></b><b></b><b></b><b></b></i>${SEV[n] || "info"}</span>`;
  const statusTag = (c) => (c ? `<span class="status s${String(c)[0]}">${c}</span>` : `<span class="muted">—</span>`);
  const srcTag = (s) => `<span class="src src-${esc(s)}">${esc(label(s))}</span>`;
  const emptyRow = (cols, title, text) => `<tr><td colspan="${cols}"><div class="empty"><strong>${esc(title)}</strong>${esc(text)}</div></td></tr>`;

  // ------------------------------------------------------------------ api
  async function api(path, opts = {}) {
    const init = { credentials: "same-origin", headers: {}, ...opts };
    if (opts.json !== undefined) {
      init.body = JSON.stringify(opts.json);
      init.headers["Content-Type"] = "application/json";
      delete init.json;
    }
    const res = await fetch(path, init);
    if (res.status === 401 && !path.endsWith("/login")) {
      showLogin();
      throw new Error("Session expired");
    }
    const type = res.headers.get("content-type") || "";
    const body = type.includes("application/json") ? await res.json() : await res.text();
    if (!res.ok) {
      const msg = body && body.detail ? (typeof body.detail === "string" ? body.detail : body.detail.map((d) => d.msg).join(", ")) : `HTTP ${res.status}`;
      throw new Error(msg);
    }
    return body;
  }

  function toast(message, kind = "ok") {
    const t = document.createElement("div");
    t.className = `toast ${kind}`;
    t.textContent = message;
    $("#toasts").appendChild(t);
    setTimeout(() => t.remove(), 4200);
  }

  function confirmModal(title, text, okLabel = "Confirm") {
    return new Promise((resolve) => {
      $("#modal-title").textContent = title;
      $("#modal-text").textContent = text;
      $("#modal-ok").textContent = okLabel;
      $("#modal").hidden = false;
      $("#modal-ok").focus();
      const done = (v) => { $("#modal").hidden = true; ok.removeEventListener("click", yes); cancel.removeEventListener("click", no); resolve(v); };
      const ok = $("#modal-ok"), cancel = $("#modal-cancel");
      const yes = () => done(true), no = () => done(false);
      ok.addEventListener("click", yes); cancel.addEventListener("click", no);
    });
  }

  // ------------------------------------------------------------------ state
  const state = { user: null, mode: "enforce", timer: null, route: null, ctx: {} };

  function setMode(mode) {
    state.mode = mode;
    $("#mode-chip").dataset.mode = mode;
    $("#mode-label").textContent = cap(mode);
  }

  async function refreshHealth() {
    try {
      const h = await api("/admin/api/health");
      setMode(h.mode);
      const ok = h.backend.reachable;
      $("#health").innerHTML = `<span class="dot ${ok ? "ok" : "bad"}"></span><span>Protected API ${ok ? "reachable" : "unreachable"}</span>`;
    } catch (_) { /* handled by api() */ }
  }

  // ------------------------------------------------------------------ auth
  function showLogin() {
    stopPolling();
    $("#app-view").hidden = true;
    $("#login-view").hidden = false;
    setTimeout(() => $("#login-form [name=username]").focus(), 0);
  }

  function showApp() {
    $("#login-view").hidden = true;
    $("#app-view").hidden = false;
    $("#user-name").textContent = state.user.username;
    $("#avatar").textContent = state.user.username.charAt(0).toUpperCase();
    $("#user-env").textContent = state.user.environment;
    refreshHealth();
    route();
  }

  $("#login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    const btn = e.target.querySelector("button");
    btn.disabled = true;
    $("#login-error").hidden = true;
    try {
      await api("/admin/api/login", { method: "POST", json: { username: f.get("username"), password: f.get("password") } });
      state.user = await api("/admin/api/me");
      e.target.reset();
      if (!location.hash) location.hash = "#/overview";
      showApp();
    } catch (err) {
      $("#login-error").textContent = err.message;
      $("#login-error").hidden = false;
    } finally {
      btn.disabled = false;
    }
  });

  $("#logout").addEventListener("click", async () => {
    await api("/admin/api/logout", { method: "POST" }).catch(() => {});
    state.user = null;
    showLogin();
  });

  // ------------------------------------------------------------------ polling
  function startPolling(fn, ms = 5000) {
    stopPolling();
    $("#live").classList.remove("paused");
    state.timer = setInterval(() => { if (!document.hidden && !$("#drawer").classList.contains("open")) fn(); }, ms);
  }
  function stopPolling() {
    if (state.timer) clearInterval(state.timer);
    state.timer = null;
    $("#live").classList.add("paused");
  }

  // ------------------------------------------------------------------ drawer
  function openDrawer(eyebrow, title, html) {
    $("#drawer-eyebrow").textContent = eyebrow;
    $("#drawer-title").textContent = title;
    $("#drawer-body").innerHTML = html;
    $("#drawer-backdrop").hidden = false;
    $("#drawer").classList.add("open");
    $("#drawer").setAttribute("aria-hidden", "false");
  }
  function closeDrawer() {
    $("#drawer").classList.remove("open");
    $("#drawer").setAttribute("aria-hidden", "true");
    $("#drawer-backdrop").hidden = true;
  }
  $("#drawer-close").addEventListener("click", closeDrawer);
  $("#drawer-backdrop").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") { closeDrawer(); $("#modal").hidden = true; } });

  async function showEvent(id) {
    openDrawer("Event", `#${id}`, `<div class="skeleton" style="height:240px"></div>`);
    try {
      const e = await api(`/admin/api/events/${id}`);
      const isGw = e.origin === "gateway";
      const rows = isGw
        ? [
            ["Decision", badge(e.decision)], ["Time", fullTime(e.created_at)], ["Mode", cap(e.mode)],
            ["Request", `<span class="method">${esc(e.method)}</span> <code>${esc(e.path)}</code>`],
            ["Response", statusTag(e.status_code)], ["User", esc(e.username || "anonymous")],
            ["Client IP", `<code>${esc(e.client_ip)}</code>`], ["Latency", e.latency_ms != null ? `${e.latency_ms} ms` : "—"],
            ["Request ID", `<code>${esc(e.request_id)}</code>`], ["Severity", sevTag(e.severity)],
          ]
        : [
            ["Decision", badge(e.decision)], ["Source", srcTag(e.source)], ["Event time", fullTime(e.event_time)],
            ["Imported", fullTime(e.created_at)], ["Source rule", `<code>${esc(e.rule_id || "—")}</code>`],
            ["Description", esc(e.rule_name || "—")], ["Classification", esc(label(e.classification))],
            ["Severity", sevTag(e.severity)], ["Source IP", `<code>${esc(e.client_ip || "—")}</code>`],
            ["Destination", `<code>${esc(e.dest_ip || "—")}</code>`],
            ...(e.path ? [["Request", `${e.method ? `<span class="method">${esc(e.method)}</span> ` : ""}<code>${esc(e.path)}</code>`]] : []),
            ...(e.status_code ? [["HTTP status", statusTag(e.status_code)]] : []),
            ["Import batch", e.batch_id ? `#${e.batch_id}` : "—"],
          ];
      const matches = e.matches || [];
      const matchHtml = matches.length
        ? matches.map((m) => `<div class="match"><div class="match-head"><span class="rule">${esc(m.rule_id)}</span><strong>${esc(m.name)}</strong><span class="spacer"></span>${sevTag(m.severity)}</div><p>${esc(m.reason)}</p></div>`).join("")
        : `<p class="muted small">No rule matched this ${isGw ? "request" : "event"}.</p>`;
      const note = isGw
        ? ""
        : `<div class="note">Imported from ${esc(e.source)}. This is a historical detection used for analysis; API Fortress did not process or block the original request.</div>`;
      $("#drawer-title").textContent = isGw ? `${e.method} ${e.path}`.slice(0, 64) : (e.rule_name || `Event #${id}`).slice(0, 64);
      $("#drawer-eyebrow").textContent = isGw ? "Gateway decision" : "Imported security event";
      $("#drawer-body").innerHTML = `${note}
        <dl class="kv">${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl>
        <div class="section-title">${isGw ? "Rule evaluation" : "Detection matches"}</div>${matchHtml}
        <div class="section-title" style="margin-top:22px">Raw record</div>
        <pre class="code">${esc(JSON.stringify(e.raw, null, 2))}</pre>`;
    } catch (err) {
      $("#drawer-body").innerHTML = `<div class="form-error">${esc(err.message)}</div>`;
    }
  }

  // ------------------------------------------------------------------ views
  const views = {};

  // ---------- Overview
  views.overview = {
    title: "Overview",
    sub: "Live gateway decisions and imported security events",
    mount(root) {
      state.ctx.range = state.ctx.range || "60m";
      root.innerHTML = `
        <div class="grid kpis" id="kpis">${'<div class="card kpi"><div class="skeleton" style="height:58px"></div></div>'.repeat(6)}</div>
        <div class="grid cols-3-2 mt">
          <div class="card">
            <div class="card-head">
              <div><h3>Gateway traffic</h3><div class="sub">Requests by decision</div></div>
              <span class="spacer"></span>
              <div class="seg" id="range">
                <button data-r="60m">1h</button><button data-r="6h">6h</button><button data-r="24h">24h</button>
              </div>
            </div>
            <div class="card-body">
              <div class="legend" style="margin-bottom:12px">
                <span><i style="background:var(--ok)"></i>Allowed</span>
                <span><i style="background:var(--warn)"></i>Flagged / observed</span>
                <span><i style="background:var(--bad)"></i>Blocked</span>
                <span><i style="background:var(--neutral)"></i>Upstream error</span>
              </div>
              <div class="chart" id="timeline"></div>
            </div>
          </div>
          <div class="card">
            <div class="card-head"><div><h3>Decision mix</h3><div class="sub">All gateway requests</div></div></div>
            <div class="card-body"><div class="donut-wrap"><div id="donut"></div><div class="donut-legend" id="donut-legend"></div></div></div>
          </div>
        </div>
        <div class="grid cols-3 mt">
          <div class="card"><div class="card-head"><div><h3>Top triggered rules</h3><div class="sub">Gateway rule violations</div></div></div><div class="card-body"><div class="rank" id="top-rules"></div></div></div>
          <div class="card"><div class="card-head"><div><h3>Imported threat severity</h3><div class="sub" id="imp-sub">Wazuh, Suricata, ModSecurity</div></div></div><div class="card-body"><div id="sev"></div><div class="rank mt" id="classes"></div></div></div>
          <div class="card"><div class="card-head"><div><h3>Top offending sources</h3><div class="sub">Blocked, flagged and alert events by IP</div></div></div><div class="card-body"><div class="rank" id="top-ips"></div></div></div>
        </div>
        <div class="card mt">
          <div class="card-head"><div><h3>Recent security decisions</h3><div class="sub">Blocked and flagged requests at the gateway</div></div><span class="spacer"></span><a class="btn btn-ghost" href="#/traffic">View all traffic</a></div>
          <div class="card-body flush"><div class="table-wrap"><table>
            <thead><tr><th>Time</th><th>Decision</th><th>Request</th><th>Status</th><th>Rule</th><th>Reason</th><th>User</th></tr></thead>
            <tbody id="recent"></tbody></table></div></div>
        </div>`;
      $$("#range button").forEach((b) => {
        b.classList.toggle("on", b.dataset.r === state.ctx.range);
        b.addEventListener("click", () => {
          state.ctx.range = b.dataset.r;
          $$("#range button").forEach((x) => x.classList.toggle("on", x === b));
          this.loadTimeline();
        });
      });
      $("#recent").addEventListener("click", (e) => { const tr = e.target.closest("tr[data-id]"); if (tr) showEvent(tr.dataset.id); });
      this._resize = debounce(() => this.loadTimeline(), 150);
      window.addEventListener("resize", this._resize);
      this.refresh();
    },
    unmount() { window.removeEventListener("resize", this._resize); },
    async loadTimeline() {
      const tl = await api(`/admin/api/timeline?range=${state.ctx.range}`);
      const box = $("#timeline"); if (!box) return;
      Charts.stackedBars(box, tl.buckets, [
        { key: "allowed", label: "Allowed", color: COLORS.allowed },
        { key: "flagged", label: "Flagged / observed", color: COLORS.flagged },
        { key: "blocked", label: "Blocked", color: COLORS.blocked },
        { key: "errors", label: "Upstream error", color: COLORS.errors },
      ], { height: 236, label: "Gateway requests over time", tipSuffix: " UTC" });
    },
    async refresh() {
      const [ov, recent] = await Promise.all([
        api("/admin/api/overview"),
        api("/admin/api/events?origin=gateway&decision=blocked,flagged,observed&limit=8"),
      ]);
      if (!$("#kpis")) return;
      setMode(ov.policy.mode);
      const g = ov.gateway, i = ov.imported;
      const kpi = (cls, label, value, foot) => `<div class="card kpi ${cls}"><span class="bar"></span><div class="kpi-label">${label}</div><div class="kpi-value">${value}</div><div class="kpi-foot">${foot}</div></div>`;
      $("#kpis").innerHTML = [
        kpi("info", "Requests inspected", fmt(g.total), `${fmt(g.last_24h)} in the last 24h`),
        kpi("ok", "Allowed", fmt(g.allowed), g.avg_latency_ms != null ? `Avg. gateway latency ${g.avg_latency_ms} ms` : "No traffic yet"),
        kpi("bad", "Blocked", fmt(g.blocked), `${g.block_rate}% block rate`),
        kpi("warn", "Flagged / observed", fmt(g.flagged + g.observed), "Allowed with a policy violation"),
        kpi("info", "Imported events", fmt(i.total), `${fmt(i.batches)} import${i.batches === 1 ? "" : "s"}`),
        kpi("bad", "High / critical alerts", fmt(i.high_or_critical), `${fmt(i.alerts)} alerts from imported logs`),
      ].join("");

      const segs = [
        { label: "Allowed", value: g.allowed, color: COLORS.allowed },
        { label: "Flagged / observed", value: g.flagged + g.observed, color: COLORS.flagged },
        { label: "Blocked", value: g.blocked, color: COLORS.blocked },
        { label: "Upstream error", value: g.errors, color: COLORS.errors },
      ];
      Charts.donut($("#donut"), segs, { value: fmt(g.total), label: "requests" });
      $("#donut-legend").innerHTML = segs.map((s) => `<div class="item"><i style="background:${s.color}"></i><span>${s.label}</span><span class="v">${fmt(s.value)}${g.total ? ` · ${((100 * s.value) / g.total).toFixed(0)}%` : ""}</span></div>`).join("");

      const rank = (items, labelFn, empty, color) => {
        if (!items.length) return `<div class="empty" style="padding:24px 0"><strong>No data yet</strong>${esc(empty)}</div>`;
        const max = Math.max(...items.map((x) => x.count));
        return items.map((x) => `<div class="rank-row"><div class="label">${labelFn(x)}</div><div class="val">${fmt(x.count)}</div><div class="track"><div class="fill" style="width:${(100 * x.count) / max}%;${color ? `background:${color}` : ""}"></div></div></div>`).join("");
      };
      $("#top-rules").innerHTML = rank(g.top_rules, (r) => `<span class="rule">${esc(r.rule_id)}</span>${esc(r.rule_name)}`, "Run a scenario in the Attack lab.");
      $("#top-ips").innerHTML = rank(ov.top_sources.map((s) => ({ ...s })), (s) => `<code>${esc(s.ip)}</code>`, "No suspicious sources recorded.", "var(--sev-3)");

      const sevTotal = SEV.reduce((s, k) => s + (i.by_severity[k] || 0), 0);
      $("#sev").innerHTML = sevTotal
        ? `<div class="sevstrip">${SEV.map((k, n) => i.by_severity[k] ? `<span style="width:${(100 * i.by_severity[k]) / sevTotal}%;background:${COLORS.sev[n]}" title="${k}: ${i.by_severity[k]}"></span>` : "").join("")}</div>
           <div class="sevlegend">${SEV.map((k, n) => `<div><b>${fmt(i.by_severity[k])}</b><i style="background:${COLORS.sev[n]}"></i>${cap(k)}</div>`).join("")}</div>`
        : `<div class="empty" style="padding:24px 0"><strong>No imported logs</strong>Upload Wazuh, Suricata or ModSecurity logs.</div>`;
      $("#classes").innerHTML = i.by_classification.length ? rank(i.by_classification.slice(0, 5), (c) => esc(label(c.classification)), "", "var(--sev-2)") : "";
      $("#imp-sub").textContent = Object.keys(i.by_source).length ? Object.entries(i.by_source).map(([k, v]) => `${label(k)} ${fmt(v)}`).join(" · ") : "Wazuh, Suricata, ModSecurity";

      $("#recent").innerHTML = recent.items.length
        ? recent.items.map((e) => `<tr class="clickable" data-id="${e.id}">
            <td class="time" title="${esc(fullTime(e.created_at))}">${timeAgo(e.created_at)}</td>
            <td>${badge(e.decision)}</td>
            <td class="path"><span class="method">${esc(e.method)}</span> ${esc(e.path)}</td>
            <td>${statusTag(e.status_code)}</td>
            <td><span class="rule">${esc(e.rule_id || "—")}</span></td>
            <td class="reason">${esc(e.reason || "")}</td>
            <td>${esc(e.username || "—")}</td></tr>`).join("")
        : emptyRow(7, "No blocked or flagged requests yet", "Open the Attack lab to send controlled test traffic through the gateway.");
      await this.loadTimeline();
    },
  };

  // ---------- generic event table view (used by Live traffic and Threat logs)
  function eventTableView(cfg) {
    return {
      title: cfg.title,
      sub: cfg.sub,
      mount(root) {
        this.filters = { ...(cfg.defaults || {}), ...(state.ctx.prefilter || {}) };
        state.ctx.prefilter = null;
        this.offset = 0;
        this.limit = 25;
        root.innerHTML = `
          ${cfg.note ? `<div class="note">${cfg.note}</div>` : ""}
          <div class="card">
            <div class="toolbar">
              <div class="search"><svg><use href="#i-search"/></svg><input id="f-q" placeholder="${cfg.searchPlaceholder}" value="${esc(this.filters.q || "")}"></div>
              ${cfg.filters.map((f) => `<select id="f-${f.key}" aria-label="${f.label}">${f.options.map(([v, l]) => `<option value="${v}" ${String(this.filters[f.key] ?? "") === v ? "selected" : ""}>${l}</option>`).join("")}</select>`).join("")}
              <span class="spacer"></span>
              <button class="btn" id="export"><svg><use href="#i-download"/></svg>Export CSV</button>
              <button class="btn btn-danger" id="clear"><svg><use href="#i-trash"/></svg>Clear</button>
            </div>
            <div class="table-wrap"><table><thead><tr>${cfg.columns.map((c) => `<th>${c}</th>`).join("")}</tr></thead><tbody id="rows"><tr><td colspan="${cfg.columns.length}"><div class="skeleton" style="height:120px"></div></td></tr></tbody></table></div>
            <div class="pager"><span id="count"></span><span class="spacer"></span><button class="btn btn-ghost" id="prev">Previous</button><button class="btn btn-ghost" id="next">Next</button></div>
          </div>`;
        const reload = () => { this.offset = 0; this.refresh(); };
        $("#f-q").addEventListener("input", debounce((e) => { this.filters.q = e.target.value; reload(); }));
        cfg.filters.forEach((f) => $(`#f-${f.key}`).addEventListener("change", (e) => { this.filters[f.key] = e.target.value; reload(); }));
        $("#prev").addEventListener("click", () => { this.offset = Math.max(0, this.offset - this.limit); this.refresh(); });
        $("#next").addEventListener("click", () => { this.offset += this.limit; this.refresh(); });
        $("#rows").addEventListener("click", (e) => { const tr = e.target.closest("tr[data-id]"); if (tr) showEvent(tr.dataset.id); });
        $("#export").addEventListener("click", () => { location.href = `/admin/api/events/export.csv?${this.query(false)}`; });
        $("#clear").addEventListener("click", async () => {
          if (!(await confirmModal(`Clear ${cfg.origin === "gateway" ? "gateway events" : "imported events"}?`, cfg.clearText, "Clear events"))) return;
          const r = await api(`/admin/api/events?origin=${cfg.origin}`, { method: "DELETE" });
          toast(`Deleted ${fmt(r.deleted)} events`);
          reload();
        });
        this.refresh();
      },
      query(paged = true) {
        const p = new URLSearchParams({ origin: cfg.origin });
        for (const [k, v] of Object.entries(this.filters)) if (v !== "" && v != null) p.set(k, v);
        if (paged) { p.set("limit", this.limit); p.set("offset", this.offset); }
        return p.toString();
      },
      async refresh() {
        const data = await api(`/admin/api/events?${this.query()}`);
        if (!$("#rows")) return;
        $("#rows").innerHTML = data.items.length
          ? data.items.map((e) => `<tr class="clickable" data-id="${e.id}">${cfg.row(e)}</tr>`).join("")
          : emptyRow(cfg.columns.length, cfg.emptyTitle, cfg.emptyText);
        const end = Math.min(data.offset + data.items.length, data.total);
        $("#count").textContent = data.total ? `${fmt(data.offset + 1)}–${fmt(end)} of ${fmt(data.total)} events` : "0 events";
        $("#prev").disabled = data.offset === 0;
        $("#next").disabled = end >= data.total;
      },
    };
  }

  views.traffic = eventTableView({
    title: "Live traffic",
    sub: "Every request evaluated by the gateway, newest first",
    origin: "gateway",
    searchPlaceholder: "Search path, user, IP, rule or reason",
    filters: [
      { key: "decision", label: "Decision", options: [["", "All decisions"], ["allowed", "Allowed"], ["blocked", "Blocked"], ["flagged", "Flagged"], ["observed", "Observed"], ["error", "Upstream error"]] },
      { key: "rule_id", label: "Rule", options: [["", "All rules"], ["AUTH-001", "AUTH-001 Missing token"], ["AUTH-002", "AUTH-002 Invalid token"], ["AUTH-003", "AUTH-003 Expired token"], ["AUTH-004", "AUTH-004 Invalid claims"], ["AUTHZ-001", "AUTHZ-001 Ownership"], ["RATE-001", "RATE-001 Rate limit"], ["REQ-001", "REQ-001 Suspicious input"], ["REQ-002", "REQ-002 Payload size"]] },
    ],
    columns: ["Time", "Decision", "Request", "Status", "Rule", "User", "Client IP", "Latency"],
    row: (e) => `
      <td class="time" title="${esc(fullTime(e.created_at))}">${shortTime(e.created_at)}</td>
      <td>${badge(e.decision)}</td>
      <td class="path"><span class="method">${esc(e.method)}</span> ${esc(e.path)}</td>
      <td>${statusTag(e.status_code)}</td>
      <td>${e.rule_id ? `<span class="rule">${esc(e.rule_id)}</span>` : '<span class="muted">—</span>'}</td>
      <td>${esc(e.username || "—")}</td>
      <td><code>${esc(e.client_ip)}</code></td>
      <td class="num muted">${e.latency_ms != null ? e.latency_ms.toFixed(1) + " ms" : "—"}</td>`,
    emptyTitle: "No gateway traffic recorded",
    emptyText: "Send requests to the gateway or run a scenario in the Attack lab.",
    clearText: "This permanently removes all recorded gateway decisions and learned endpoint profiles.",
  });

  views.threats = eventTableView({
    title: "Threat logs",
    sub: "Security events imported from Wazuh, Suricata and ModSecurity",
    origin: "imported",
    note: "Imported events are historical detections from external tools. A match means a detection rule fired; it does not by itself prove an attack succeeded, and these requests were not processed by API Fortress.",
    searchPlaceholder: "Search description, rule, IP or URL",
    filters: [
      { key: "source", label: "Source", options: [["", "All sources"], ["wazuh", "Wazuh"], ["suricata", "Suricata"], ["modsecurity", "ModSecurity"]] },
      { key: "classification", label: "Classification", options: [["", "All classifications"], ["web_attack", "Web attack"], ["host_integrity", "Host integrity"], ["auth_failure", "Authentication failure"], ["reconnaissance", "Reconnaissance"], ["api_probing", "API probing"], ["repeated_source", "Repeated source"], ["high_severity", "High severity"], ["upstream_block", "Upstream block"], ["informational", "Informational"]] },
      { key: "min_severity", label: "Severity", options: [["", "Any severity"], ["1", "Low and above"], ["2", "Medium and above"], ["3", "High and above"], ["4", "Critical only"]] },
      { key: "decision", label: "Decision", options: [["", "Alerts and observations"], ["alert", "Alerts only"], ["observed", "Observations only"]] },
    ],
    columns: ["Event time", "Source", "Severity", "Classification", "Description", "Source IP", "Result"],
    row: (e) => `
      <td class="time" title="Imported ${esc(fullTime(e.created_at))}">${shortTime(e.event_time || e.created_at)}</td>
      <td>${srcTag(e.source)}</td>
      <td>${sevTag(e.severity)}</td>
      <td>${esc(label(e.classification))}</td>
      <td class="reason" style="color:var(--text)">${esc(e.rule_name || "—")}</td>
      <td><code>${esc(e.client_ip || "—")}</code></td>
      <td>${badge(e.decision, e.decision === "observed" ? "neutral" : null)}</td>`,
    emptyTitle: "No imported events",
    emptyText: "Use Log ingestion to import Wazuh, Suricata or ModSecurity logs.",
    clearText: "This permanently removes all imported security events and the import history.",
  });

  // ---------- Log ingestion
  views.ingest = {
    title: "Log ingestion",
    sub: "Import real security logs for detection and analysis",
    mount(root) {
      root.innerHTML = `
        <div class="grid cols-2">
          <div class="card">
            <div class="card-head"><div><h3>Upload a log file</h3><div class="sub">NDJSON or JSON, up to 25 MB. The format is detected per record.</div></div></div>
            <div class="card-body">
              <label class="dropzone" id="drop">
                <svg><use href="#i-upload"/></svg>
                <strong>Drop a log file here or click to browse</strong>
                <span class="muted small">alerts.json · eve.json · modsec_audit.json</span>
                <input type="file" id="file" accept=".json,.log,.ndjson,.txt,application/json" hidden>
              </label>
              <div class="row mt" id="chosen" hidden></div>
              <div class="inline-form mt">
                <label class="field"><span>Source format</span>
                  <select id="source"><option value="auto">Detect automatically</option><option value="wazuh">Wazuh alerts</option><option value="suricata">Suricata EVE JSON</option><option value="modsecurity">ModSecurity JSON audit</option></select>
                </label>
                <button class="btn btn-primary" id="upload" disabled><svg><use href="#i-upload"/></svg>Import and analyse</button>
              </div>
              <div id="result"></div>
            </div>
          </div>
          <div class="card">
            <div class="card-head"><div><h3>Collecting real logs</h3><div class="sub">Export from your lab, then import here</div></div><span class="spacer"></span>
              <div class="seg" id="howto"><button data-k="wazuh" class="on">Wazuh</button><button data-k="suricata">Suricata</button><button data-k="modsec">ModSecurity</button><button data-k="push">Push API</button></div></div>
            <div class="card-body" id="howto-body"></div>
          </div>
        </div>
        <div class="card mt">
          <div class="card-head"><div><h3>Import history</h3><div class="sub">Select an import to inspect its events</div></div></div>
          <div class="card-body flush"><div class="table-wrap"><table>
            <thead><tr><th>Imported</th><th>File</th><th>Source</th><th>Channel</th><th class="num">Records</th><th class="num">Parsed</th><th class="num">Skipped</th><th class="num">Failed</th><th class="num">Alerts</th></tr></thead>
            <tbody id="batches"></tbody></table></div></div>
        </div>`;
      const howto = {
        wazuh: `<ol class="steps-list">
            <li>On the Wazuh manager, alerts are written to <code>/var/ossec/logs/alerts/alerts.json</code>.</li>
            <li>Export a recent sample:<pre class="code">sudo tail -n 5000 /var/ossec/logs/alerts/alerts.json &gt; wazuh_alerts.json</pre></li>
            <li>Or export from the Wazuh dashboard (Discover → Share → CSV/JSON). OpenSearch <code>hits.hits[]._source</code> exports are supported.</li>
            <li>Copy the file to this machine and upload it here.</li></ol>`,
        suricata: `<ol class="steps-list">
            <li>Suricata writes EVE JSON to <code>/var/log/suricata/eve.json</code>.</li>
            <li>Keep only security-relevant records:<pre class="code">jq -c 'select(.event_type=="alert" or .event_type=="http" or .event_type=="anomaly")' \\
  /var/log/suricata/eve.json | tail -n 5000 &gt; suricata_eve.json</pre></li>
            <li><code>stats</code> and <code>flow</code> records are skipped automatically if included.</li></ol>`,
        modsec: `<ol class="steps-list">
            <li>Enable JSON audit logging in <code>modsecurity.conf</code>:<pre class="code">SecAuditEngine RelevantOnly
SecAuditLogFormat JSON
SecAuditLogType Serial
SecAuditLog /var/log/modsec_audit.json</pre></li>
            <li>Reload the web server, generate traffic, then upload <code>/var/log/modsec_audit.json</code>.</li></ol>`,
        push: `<ol class="steps-list">
            <li>Set <code>INGEST_TOKEN</code> in the gateway <code>.env</code> and restart.</li>
            <li>Ship a file continuously from the sensor host:<pre class="code">python scripts/ship_logs.py --file /var/ossec/logs/alerts/alerts.json \\
  --url ${esc(location.origin)} --token $INGEST_TOKEN --follow</pre></li>
            <li>Or push once with curl:<pre class="code">curl -X POST "${esc(location.origin)}/admin/api/ingest/push?source=suricata" \\
  -H "X-Ingest-Token: $INGEST_TOKEN" --data-binary @eve.json</pre></li></ol>`,
      };
      const setHow = (k) => { $("#howto-body").innerHTML = howto[k]; $$("#howto button").forEach((b) => b.classList.toggle("on", b.dataset.k === k)); };
      $$("#howto button").forEach((b) => b.addEventListener("click", () => setHow(b.dataset.k)));
      setHow("wazuh");

      let file = null;
      const choose = (f) => {
        file = f;
        $("#chosen").hidden = !f;
        $("#chosen").innerHTML = f ? `<span class="file-pill"><svg><use href="#i-file"/></svg>${esc(f.name)} <span class="muted">· ${(f.size / 1024).toFixed(1)} KB</span></span>` : "";
        $("#upload").disabled = !f;
      };
      $("#file").addEventListener("change", (e) => choose(e.target.files[0]));
      const drop = $("#drop");
      ["dragenter", "dragover"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add("drag"); }));
      ["dragleave", "drop"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove("drag"); }));
      drop.addEventListener("drop", (e) => choose(e.dataTransfer.files[0]));

      $("#upload").addEventListener("click", async () => {
        if (!file) return;
        const btn = $("#upload");
        btn.disabled = true;
        btn.lastChild.textContent = "Analysing…";
        const fd = new FormData();
        fd.append("file", file);
        fd.append("source", $("#source").value);
        try {
          const r = await api("/admin/api/ingest/upload", { method: "POST", body: fd });
          const cls = Object.entries(r.classifications || {}).sort((a, b) => b[1] - a[1]);
          $("#result").innerHTML = `
            <div class="section-title mt" style="margin-top:22px">Import #${r.id} · ${esc(label(r.source))}</div>
            <div class="result-grid">
              <div><b>${fmt(r.records_parsed)}</b><span>Parsed of ${fmt(r.records_total)}</span></div>
              <div><b>${fmt(r.alerts)}</b><span>Alerts</span></div>
              <div><b>${fmt(r.records_skipped)}</b><span>Skipped (noise)</span></div>
              <div><b>${fmt(r.records_failed)}</b><span>Failed</span></div>
            </div>
            ${cls.length ? `<div class="legend mt">${cls.map(([k, v]) => `<span>${esc(label(k))} <b>${v}</b></span>`).join("")}</div>` : ""}
            ${r.errors.length ? `<details class="mt"><summary class="muted small">${r.records_failed} record(s) could not be parsed</summary><pre class="code mt">${esc(r.errors.map((x) => `line ${x.line}: ${x.error}`).join("\n"))}</pre></details>` : ""}
            <div class="row mt"><button class="btn" id="view-batch" data-id="${r.id}">View events</button></div>`;
          $("#view-batch").addEventListener("click", () => { state.ctx.prefilter = { batch_id: r.id }; location.hash = "#/threats"; });
          toast(`Imported ${r.records_parsed} events · ${r.alerts} alerts`);
          choose(null);
          $("#file").value = "";
          this.refresh();
        } catch (err) {
          toast(err.message, "bad");
        } finally {
          btn.lastChild.textContent = "Import and analyse";
          btn.disabled = !file;
        }
      });
      $("#batches").addEventListener("click", (e) => {
        const tr = e.target.closest("tr[data-id]");
        if (tr) { state.ctx.prefilter = { batch_id: Number(tr.dataset.id) }; location.hash = "#/threats"; }
      });
      this.refresh();
    },
    async refresh() {
      const data = await api("/admin/api/ingest/batches");
      if (!$("#batches")) return;
      $("#batches").innerHTML = data.items.length
        ? data.items.map((b) => `<tr class="clickable" data-id="${b.id}">
            <td class="time" title="${esc(fullTime(b.created_at))}">${timeAgo(b.created_at)}</td>
            <td><code>${esc(b.filename)}</code></td><td>${srcTag(b.source)}</td><td>${esc(cap(b.channel))}</td>
            <td class="num">${fmt(b.records_total)}</td><td class="num">${fmt(b.records_parsed)}</td>
            <td class="num muted">${fmt(b.records_skipped)}</td><td class="num ${b.records_failed ? "" : "muted"}">${fmt(b.records_failed)}</td>
            <td class="num"><b>${fmt(b.alerts)}</b></td></tr>`).join("")
        : emptyRow(9, "No imports yet", "Sample files are in data/sample_logs/ if you want to try the pipeline first.");
    },
  };

  // ---------- Attack lab
  views.lab = {
    title: "Attack lab",
    sub: "Send controlled, authorised test traffic through the gateway",
    async mount(root) {
      const data = await api("/admin/api/simulate");
      setMode(data.mode);
      this.results = this.results || {};
      root.innerHTML = `
        <div class="note" id="lab-note"></div>
        <div class="row" style="margin-bottom:16px">
          <button class="btn btn-primary" id="run-all"><svg><use href="#i-play"/></svg>Run all scenarios</button>
          <button class="btn" id="reset-demo"><svg><use href="#i-refresh"/></svg>Reset demo data</button>
          <span class="spacer"></span><span class="muted small" id="lab-summary"></span>
        </div>
        <div class="grid cols-3" id="scenarios">
          ${data.items.map((s) => `
            <div class="card scenario" data-id="${s.id}">
              <h3>${esc(s.title)}</h3>
              <p>${esc(s.description)}</p>
              <div class="rules">${s.rules.length ? s.rules.map((r) => `<span class="badge plain b-info">${esc(r)}</span>`).join("") : '<span class="badge plain b-allowed">Expected: allowed</span>'}</div>
              <div class="scenario-foot"><button class="btn run" data-id="${s.id}"><svg><use href="#i-play"/></svg>Run</button><span class="spacer"></span><span class="verdict" data-v="${s.id}"></span></div>
            </div>`).join("")}
        </div>
        <div class="card mt">
          <div class="card-head"><div><h3 id="result-title">Results</h3><div class="sub" id="result-sub">Run a scenario to see each request and the gateway's decision</div></div></div>
          <div class="card-body"><div class="steps" id="steps"><div class="empty"><strong>No scenario run yet</strong>Each step shows the expected and actual HTTP status.</div></div></div>
        </div>`;
      this.updateNote();
      $("#scenarios").addEventListener("click", (e) => { const b = e.target.closest("button.run"); if (b) this.run(b.dataset.id, true); });
      $("#run-all").addEventListener("click", async () => {
        const btn = $("#run-all"); btn.disabled = true;
        let passed = 0;
        for (const s of data.items) { const r = await this.run(s.id, s.id === data.items[data.items.length - 1].id); if (r && r.passed) passed++; }
        $("#lab-summary").textContent = `${passed} of ${data.items.length} scenarios behaved as expected in ${state.mode} mode`;
        btn.disabled = false;
      });
      $("#reset-demo").addEventListener("click", async () => {
        if (!(await confirmModal("Reset demo data?", "Restores the demo API's users and records and clears rate-limit counters. Recorded events are kept.", "Reset"))) return;
        try { await api("/admin/api/demo/reset", { method: "POST" }); toast("Demo data restored"); } catch (err) { toast(err.message, "bad"); }
      });
      Object.values(this.results).forEach((r) => this.paintVerdict(r));
    },
    updateNote() {
      const m = state.mode;
      const text = {
        enforce: "Enforce mode: policy violations are rejected before reaching the protected API.",
        monitor: "Monitor mode: ownership, rate-limit and input violations are flagged but forwarded, so the backend's BOLA flaw is reachable. Authentication failures are still blocked.",
        learning: "Learning mode: violations are recorded as observations and endpoint profiles are built. Authentication failures are still blocked.",
      }[m];
      if ($("#lab-note")) $("#lab-note").textContent = `${text} Expected results adapt to the current mode.`;
    },
    paintVerdict(r) {
      const v = $(`.verdict[data-v="${r.scenario}"]`);
      if (v) v.innerHTML = r.passed ? `<span class="verdict pass"><svg><use href="#i-check"/></svg>As expected</span>` : `<span class="verdict fail"><svg><use href="#i-x"/></svg>Unexpected result</span>`;
    },
    async run(id, show) {
      const btn = $(`button.run[data-id="${id}"]`);
      if (btn) { btn.disabled = true; btn.lastChild.textContent = "Running…"; }
      try {
        const r = await api(`/admin/api/simulate/${id}`, { method: "POST" });
        this.results[id] = r;
        this.paintVerdict(r);
        if (show) this.show(r);
        return r;
      } catch (err) {
        toast(err.message, "bad");
      } finally {
        if (btn) { btn.disabled = false; btn.lastChild.textContent = "Run"; }
      }
    },
    show(r) {
      $("#result-title").textContent = r.title;
      $("#result-sub").textContent = `${cap(r.mode)} mode · ${r.steps.length} request group(s) · ${r.duration_ms} ms`;
      $("#steps").innerHTML = r.steps.map((s) => `
        <div class="step">
          <div class="step-icon ${s.passed ? "" : "fail"}"><svg><use href="#i-${s.passed ? "check" : "x"}"/></svg></div>
          <div>
            <div class="step-title">${esc(s.label)}</div>
            <div class="step-meta"><span class="method">${esc(s.method)}</span><code>${esc(s.path)}</code>${s.decision ? badge(s.decision) : ""}${s.rule ? `<span class="rule">${esc(s.rule)}</span>` : ""}</div>
            ${s.message ? `<div class="step-meta">${esc(s.message)}</div>` : ""}
          </div>
          <div class="step-code">${statusTag(s.status)}expected ${s.expected.join(" / ") || "—"}</div>
        </div>`).join("");
    },
  };

  // ---------- Policy
  views.policy = {
    title: "Policy",
    sub: "Gateway mode, limits and the rules that protect the API",
    async mount(root) {
      const [s, prof] = await Promise.all([api("/admin/api/settings"), api("/admin/api/profiles")]);
      setMode(s.policy.mode);
      root.innerHTML = `
        <div class="card">
          <div class="card-head"><div><h3>Gateway mode</h3><div class="sub">Applies immediately to all new requests and is persisted across restarts</div></div></div>
          <div class="card-body"><div class="modes" id="modes">
            ${s.modes.map((m) => `<button class="mode-card ${m.id === s.policy.mode ? "on" : ""}" data-mode="${m.id}"><h4><span class="radio"></span>${m.id}</h4><p>${esc(m.description)}</p></button>`).join("")}
          </div></div>
        </div>
        <div class="grid cols-2 mt">
          <div class="card">
            <div class="card-head"><div><h3>Rate limiting</h3><div class="sub">Sliding window per authenticated user, or per IP for anonymous requests</div></div></div>
            <div class="card-body">
              <form class="inline-form" id="rate-form">
                <label class="field"><span>Requests</span><input type="number" min="1" max="100000" name="rate_limit_requests" value="${s.policy.rate_limit_requests}"></label>
                <label class="field"><span>Window (seconds)</span><input type="number" min="1" max="86400" name="rate_limit_window" value="${s.policy.rate_limit_window}"></label>
                <button class="btn btn-primary" type="submit">Save limits</button>
              </form>
              <p class="muted small" style="margin:14px 0 0">Counters are held in memory and reset when the limit changes or the gateway restarts.</p>
            </div>
          </div>
          <div class="card">
            <div class="card-head"><div><h3>Routing</h3><div class="sub">Upstream and access configuration</div></div></div>
            <div class="card-body"><dl class="kv" style="margin:0">
              <dt>Protected API</dt><dd><code>${esc(s.backend_url)}</code></dd>
              <dt>Public paths</dt><dd>${s.public_paths.map((p) => `<code>${esc(p)}</code>`).join(", ")}</dd>
              <dt>Ownership checks</dt><dd>${s.protected_resources.map((r) => `<code>${esc(r.methods.join("|"))} ${esc(r.pattern)}</code>`).join("<br>")}</dd>
              <dt>Max body size</dt><dd>${fmt(s.max_body_bytes)} bytes</dd>
              <dt>Push ingestion</dt><dd>${s.ingest_push_enabled ? '<span class="badge b-allowed">Enabled</span>' : '<span class="badge b-neutral">Disabled</span>'}</dd>
            </dl></div>
          </div>
        </div>
        <div class="grid cols-2 mt">
          <div class="card">
            <div class="card-head"><div><h3>Gateway rules</h3><div class="sub">Mandatory rules block in every mode</div></div></div>
            <div class="card-body flush"><div class="table-wrap"><table><thead><tr><th>Rule</th><th>Name</th><th>Category</th><th>Status</th><th>Enforcement</th></tr></thead><tbody>
              ${s.gateway_rules.map((r) => `<tr><td><span class="rule">${r.rule_id}</span></td><td>${esc(r.name)}</td><td class="muted">${esc(human(r.category))}</td><td>${statusTag(r.status)}</td><td>${r.mandatory ? '<span class="badge b-blocked">Always</span>' : '<span class="badge b-info">Per mode</span>'}</td></tr>`).join("")}
            </tbody></table></div></div>
          </div>
          <div class="card">
            <div class="card-head"><div><h3>Detection rules</h3><div class="sub">Applied to imported Wazuh, Suricata and ModSecurity events</div></div></div>
            <div class="card-body flush"><div class="table-wrap"><table><thead><tr><th>Rule</th><th>Name</th><th>Classification</th><th>Severity</th></tr></thead><tbody>
              ${s.detection_rules.sort((a, b) => a.rule_id.localeCompare(b.rule_id)).map((r) => `<tr><td><span class="rule">${r.rule_id}</span></td><td>${esc(r.name)}</td><td class="muted">${esc(label(r.classification))}</td><td>${sevTag(r.severity)}</td></tr>`).join("")}
            </tbody></table></div></div>
          </div>
        </div>
        <div class="card mt">
          <div class="card-head"><div><h3>Learned endpoints</h3><div class="sub">Profiles collected while the gateway runs in Learning mode</div></div></div>
          <div class="card-body flush"><div class="table-wrap"><table><thead><tr><th>Method</th><th>Path template</th><th class="num">Hits</th><th class="num">Users</th><th>Status codes</th><th class="num">Max body</th><th>Last seen</th></tr></thead><tbody>
            ${prof.items.length ? prof.items.map((p) => `<tr><td><span class="method">${esc(p.method)}</span></td><td><code>${esc(p.path_template)}</code></td><td class="num">${fmt(p.hits)}</td><td class="num">${fmt(p.distinct_users)}</td><td>${Object.entries(p.status_codes).map(([c, n]) => `${statusTag(Number(c))}<span class="muted small"> ×${n}</span>`).join(" &nbsp;")}</td><td class="num muted">${fmt(p.max_body_bytes)} B</td><td class="time">${timeAgo(p.last_seen)}</td></tr>`).join("") : emptyRow(7, "No profiles yet", "Switch to Learning mode and send traffic to build endpoint profiles.")}
          </tbody></table></div></div>
        </div>`;
      $("#modes").addEventListener("click", async (e) => {
        const b = e.target.closest(".mode-card"); if (!b || b.classList.contains("on")) return;
        try {
          const r = await api("/admin/api/settings", { method: "PUT", json: { mode: b.dataset.mode } });
          setMode(r.policy.mode);
          $$(".mode-card").forEach((x) => x.classList.toggle("on", x === b));
          toast(`Gateway switched to ${r.policy.mode} mode`);
        } catch (err) { toast(err.message, "bad"); }
      });
      $("#rate-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        const f = new FormData(e.target);
        try {
          const r = await api("/admin/api/settings", { method: "PUT", json: { rate_limit_requests: Number(f.get("rate_limit_requests")), rate_limit_window: Number(f.get("rate_limit_window")) } });
          toast(`Limit set to ${r.policy.rate_limit_requests} requests per ${r.policy.rate_limit_window}s`);
        } catch (err) { toast(err.message, "bad"); }
      });
    },
  };

  // ------------------------------------------------------------------ router
  const POLLING = { overview: 5000, traffic: 4000, threats: 15000, ingest: 15000 };

  async function route() {
    if (!state.user) return;
    const name = (location.hash.replace(/^#\//, "") || "overview").split("?")[0];
    const view = views[name] || views.overview;
    const key = views[name] ? name : "overview";
    if (state.route && views[state.route] && views[state.route].unmount) views[state.route].unmount();
    state.route = key;
    closeDrawer();
    $("#sidebar").classList.remove("open");
    $$(".nav a").forEach((a) => a.classList.toggle("active", a.dataset.route === key));
    $("#page-title").textContent = view.title;
    $("#page-sub").textContent = view.sub;
    document.title = `${view.title} · API Fortress`;
    const root = $("#view");
    root.innerHTML = "";
    stopPolling();
    try {
      await view.mount(root);
    } catch (err) {
      root.innerHTML = `<div class="form-error">${esc(err.message)}</div>`;
    }
    if (POLLING[key] && view.refresh) startPolling(() => view.refresh().catch(() => {}), POLLING[key]);
    if (!state.healthTimer) state.healthTimer = setInterval(refreshHealth, 15000);
  }

  window.addEventListener("hashchange", route);
  $("#menu-btn").addEventListener("click", () => $("#sidebar").classList.toggle("open"));

  // ------------------------------------------------------------------ boot
  (async function boot() {
    try {
      const res = await fetch("/admin/api/me", { credentials: "same-origin" });
      if (res.ok) {
        state.user = await res.json();
        if (!location.hash) location.hash = "#/overview";
        showApp();
      } else {
        showLogin();
      }
    } catch (_) {
      showLogin();
    }
  })();
})();
