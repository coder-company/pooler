//! Static, read-only management control surface.
//!
//! The first UI intentionally has no build step or third-party runtime. It is
//! served by the authenticated management listener and reads the redacted
//! JSON endpoints exposed by [`super::ManagementApi`]. Keeping the assets in
//! the server binary makes the control surface available in release bundles
//! without a separate web deployment.

/// Return one embedded UI asset by its management-relative path.
pub(crate) fn asset(path: &str) -> Option<(&'static str, &'static str)> {
    match path {
        "/ui" | "/ui/" => Some(("text/html; charset=utf-8", INDEX_HTML)),
        "/ui.css" => Some(("text/css; charset=utf-8", STYLE_CSS)),
        "/ui.js" => Some(("application/javascript; charset=utf-8", APP_JS)),
        _ => None,
    }
}

const INDEX_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark light">
  <title>Pooler Control</title>
  <link rel="stylesheet" href="/management/ui.css">
</head>
<body>
  <header class="topbar">
    <div>
      <p class="eyebrow">POOLER CONTROL</p>
      <h1>Runtime overview</h1>
      <p class="lede">A read-only view of the active proxy plan and bounded runtime signals.</p>
    </div>
    <div class="session" aria-label="Management session">
      <label for="token">Bearer token</label>
      <input id="token" type="password" autocomplete="off" spellcheck="false" placeholder="Optional for local auth">
      <button id="refresh" type="button">Refresh</button>
    </div>
  </header>

  <main>
    <p id="notice" class="notice" role="status">Loading management data…</p>

    <section class="summary" aria-labelledby="summary-heading">
      <div class="section-heading">
        <div>
          <p class="eyebrow">AT A GLANCE</p>
          <h2 id="summary-heading">System status</h2>
        </div>
        <span id="generation" class="badge">Generation —</span>
      </div>
      <div class="cards">
        <article class="card"><span>Health</span><strong id="health-status">—</strong><small id="health-detail">Waiting for the management API</small></article>
        <article class="card"><span>Listeners</span><strong id="listener-count">—</strong><small>Configured inference sockets</small></article>
        <article class="card"><span>Routes</span><strong id="route-count">—</strong><small>Compiled match plan</small></article>
        <article class="card"><span>Providers</span><strong id="provider-count">—</strong><small>Configured upstreams</small></article>
        <article class="card"><span>Accounts</span><strong id="account-count">—</strong><small>Redacted account state</small></article>
        <article class="card"><span>Active requests</span><strong id="active-count">—</strong><small>Across all listeners</small></article>
      </div>
    </section>

    <div class="columns">
      <section class="panel" aria-labelledby="listeners-heading">
        <div class="section-heading compact"><h2 id="listeners-heading">Listeners</h2><a href="/management/listeners">JSON</a></div>
        <div id="listeners" class="table-wrap"><p class="muted">Loading…</p></div>
      </section>
      <section class="panel" aria-labelledby="providers-heading">
        <div class="section-heading compact"><h2 id="providers-heading">Providers</h2><a href="/management/health/providers">JSON</a></div>
        <div id="providers" class="table-wrap"><p class="muted">Loading…</p></div>
      </section>
    </div>

    <div class="columns">
      <section class="panel" aria-labelledby="routes-heading">
        <div class="section-heading compact"><h2 id="routes-heading">Routes</h2><a href="/management/routes">JSON</a></div>
        <div id="routes" class="table-wrap"><p class="muted">Loading…</p></div>
      </section>
      <section class="panel" aria-labelledby="models-heading">
        <div class="section-heading compact"><h2 id="models-heading">Models</h2><a href="/management/models">JSON</a></div>
        <div id="models" class="table-wrap"><p class="muted">Loading…</p></div>
      </section>
    </div>

    <div class="columns">
      <section class="panel" aria-labelledby="accounts-heading">
        <div class="section-heading compact"><h2 id="accounts-heading">Accounts</h2><a href="/management/accounts">JSON</a></div>
        <div id="accounts" class="table-wrap"><p class="muted">Loading…</p></div>
      </section>
      <section class="panel" aria-labelledby="quota-heading">
        <div class="section-heading compact"><h2 id="quota-heading">Quota &amp; cooldowns</h2><a href="/management/quota">JSON</a></div>
        <div id="quota" class="table-wrap"><p class="muted">Loading…</p></div>
      </section>
    </div>

    <section class="panel" aria-labelledby="metrics-heading">
      <div class="section-heading compact"><h2 id="metrics-heading">Metrics</h2><a href="/management/metrics">JSON</a></div>
      <div id="metrics" class="metrics-grid"><p class="muted">Loading…</p></div>
    </section>
  </main>

  <footer>Pooler management UI · read-only · values are redacted at the API boundary</footer>
  <script src="/management/ui.js" defer></script>
</body>
</html>
"##;

const STYLE_CSS: &str = r##":root {
  --bg: #0b1020;
  --surface: #121a2c;
  --surface-raised: #18233a;
  --line: #263454;
  --text: #e7edf8;
  --muted: #98a7c3;
  --accent: #7dd3fc;
  --good: #86efac;
  --warn: #fcd34d;
  --bad: #fda4af;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  color: var(--text);
  background: var(--bg);
}

* { box-sizing: border-box; }
body { margin: 0; min-width: 320px; background: radial-gradient(circle at top right, #182442 0, var(--bg) 42rem); }
.topbar, main, footer { width: min(1440px, calc(100% - 40px)); margin: 0 auto; }
.topbar { display: flex; justify-content: space-between; gap: 32px; align-items: flex-end; padding: 52px 0 36px; }
.eyebrow { margin: 0 0 8px; color: var(--accent); font-size: 11px; font-weight: 750; letter-spacing: .16em; }
h1, h2, p { margin-top: 0; }
h1 { margin-bottom: 10px; font-size: clamp(30px, 4vw, 48px); letter-spacing: -.04em; }
h2 { margin-bottom: 0; font-size: 20px; letter-spacing: -.02em; }
.lede { max-width: 560px; margin-bottom: 0; color: var(--muted); }
.session { display: grid; grid-template-columns: auto minmax(180px, 240px) auto; gap: 8px; align-items: center; color: var(--muted); font-size: 12px; }
input, button { border: 1px solid var(--line); border-radius: 8px; font: inherit; }
input { width: 100%; padding: 10px 12px; color: var(--text); background: var(--surface); }
button { padding: 10px 15px; color: #04111d; background: var(--accent); cursor: pointer; font-weight: 700; }
button:hover { filter: brightness(1.08); }
.notice { min-height: 22px; margin: 0 0 20px; color: var(--muted); font-size: 13px; }
.notice.error { color: var(--bad); }
.summary, .panel { border: 1px solid var(--line); border-radius: 14px; background: color-mix(in srgb, var(--surface) 92%, transparent); }
.summary { padding: 22px; margin-bottom: 20px; }
.section-heading { display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 18px; }
.section-heading.compact { margin-bottom: 14px; }
.badge { border: 1px solid var(--line); border-radius: 999px; padding: 6px 10px; color: var(--muted); font-size: 12px; }
.cards { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 10px; }
.card { display: grid; gap: 9px; min-height: 110px; padding: 16px; border-radius: 10px; background: var(--surface-raised); }
.card span, .card small, .muted { color: var(--muted); }
.card span { font-size: 12px; }
.card strong { font-size: 25px; letter-spacing: -.04em; }
.card small { font-size: 11px; line-height: 1.35; }
.columns { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 20px; margin-bottom: 20px; }
.panel { min-width: 0; padding: 22px; }
.panel a { color: var(--accent); font-size: 12px; text-decoration: none; }
.panel a:hover { text-decoration: underline; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { padding: 10px 8px; border-bottom: 1px solid var(--line); text-align: left; white-space: nowrap; }
th { color: var(--muted); font-size: 11px; font-weight: 650; text-transform: uppercase; letter-spacing: .08em; }
tr:last-child td { border-bottom: 0; }
.status-good { color: var(--good); }
.status-warn { color: var(--warn); }
.status-bad { color: var(--bad); }
.metrics-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; }
.metric { padding: 14px; border-radius: 9px; background: var(--surface-raised); }
.metric span { display: block; color: var(--muted); font-size: 12px; }
.metric strong { display: block; margin-top: 6px; font-size: 22px; }
footer { padding: 28px 0 44px; color: var(--muted); font-size: 11px; }
@media (max-width: 1080px) { .cards { grid-template-columns: repeat(3, minmax(0, 1fr)); } }
@media (max-width: 760px) { .topbar { display: block; padding-top: 32px; } .session { margin-top: 24px; grid-template-columns: 1fr; } .columns { grid-template-columns: 1fr; } .cards, .metrics-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } .topbar, main, footer { width: min(100% - 24px, 640px); } }
@media (max-width: 420px) { .cards, .metrics-grid { grid-template-columns: 1fr; } }
"##;

const APP_JS: &str = r##"(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const notice = $("notice");
  const token = $("token");
  const endpoints = {
    health: "/management/health",
    listeners: "/management/listeners",
    routes: "/management/routes",
    providers: "/management/health/providers",
    models: "/management/models",
    accounts: "/management/accounts",
    quota: "/management/quota",
    metrics: "/management/metrics"
  };

  function requestHeaders() {
    const value = token.value.trim();
    return value ? { Authorization: `Bearer ${value}` } : {};
  }

  async function readJson(path) {
    const response = await fetch(path, { headers: requestHeaders(), cache: "no-store" });
    if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
    return response.json();
  }

  function text(value) {
    return value === null || value === undefined || value === "" ? "—" : String(value);
  }

  function statusClass(value) {
    return value === "healthy" || value === "ok" ? "status-good" : value === "cooling_down" ? "status-warn" : "status-bad";
  }

  function table(target, columns, rows) {
    const root = $(target);
    if (!rows.length) { root.replaceChildren(Object.assign(document.createElement("p"), { className: "muted", textContent: "No entries" })); return; }
    const tableNode = document.createElement("table");
    const head = document.createElement("tr");
    columns.forEach((column) => { const cell = document.createElement("th"); cell.textContent = column.label; head.append(cell); });
    const thead = document.createElement("thead"); thead.append(head); tableNode.append(thead);
    const body = document.createElement("tbody");
    rows.forEach((row) => { const line = document.createElement("tr"); columns.forEach((column) => { const cell = document.createElement("td"); const value = column.value(row); cell.textContent = text(value); if (column.status) cell.className = statusClass(value); line.append(cell); }); body.append(line); });
    tableNode.append(body); root.replaceChildren(tableNode);
  }

  function render(data) {
    const generation = data.health.configuration_generation ?? data.routes.configuration_generation;
    $("generation").textContent = `Generation ${text(generation)}`;
    $("health-status").textContent = text(data.health.status);
    $("health-status").className = statusClass(data.health.status);
    $("health-detail").textContent = `${text(data.health.active)} active · ${text(data.health.credential_health_entries)} health entries`;
    $("listener-count").textContent = text(data.listeners.listeners?.length);
    $("route-count").textContent = text(data.routes.routes?.length);
    $("provider-count").textContent = text(data.providers.providers?.length);
    $("account-count").textContent = text(data.accounts.accounts?.length);
    $("active-count").textContent = text(data.health.active);

    table("listeners", [{ label: "ID", value: (row) => row.id }, { label: "Bind", value: (row) => row.bind }, { label: "Protocol", value: (row) => row.protocol }, { label: "Routes", value: (row) => row.route_count }], data.listeners.listeners || []);
    table("providers", [{ label: "ID", value: (row) => row.id }, { label: "Transport", value: (row) => row.transport }, { label: "Native", value: (row) => row.native }, { label: "Status", value: (row) => row.status, status: true }], data.providers.providers || []);
    table("routes", [{ label: "ID", value: (row) => row.id }, { label: "Listener", value: (row) => row.listener }, { label: "Path", value: (row) => row.path }, { label: "Target", value: (row) => row.target?.upstream }], data.routes.routes || []);
    table("models", [{ label: "ID", value: (row) => row.id }, { label: "Targets", value: (row) => row.targets?.length }, { label: "Capabilities", value: (row) => (row.targets || []).flatMap((target) => target.capabilities || []).join(", ") }], data.models.models || []);
    table("accounts", [{ label: "ID", value: (row) => row.id }, { label: "Provider", value: (row) => row.provider }, { label: "Enabled", value: (row) => row.enabled ? "yes" : "no" }, { label: "Status", value: (row) => row.status, status: true }], data.accounts.accounts || []);
    table("quota", [{ label: "Scope", value: (row) => row.scope }, { label: "Key", value: (row) => row.key }, { label: "Until", value: (row) => row.until }, { label: "Reason", value: (row) => row.reason }], data.quota.entries || []);

    const snapshot = data.metrics.metrics || {};
    const metricValues = [["Tracked routes", (snapshot.routes || []).length], ["Attempts", (snapshot.attempts || []).reduce((sum, row) => sum + row.count, 0)], ["Completions", (snapshot.completions || []).reduce((sum, row) => sum + row.count, 0)], ["Dropped series", snapshot.dropped_series || 0]];
    const metricsRoot = $("metrics");
    metricsRoot.replaceChildren(...metricValues.map(([label, value]) => { const item = document.createElement("div"); item.className = "metric"; const name = document.createElement("span"); name.textContent = label; const count = document.createElement("strong"); count.textContent = text(value); item.append(name, count); return item; }));
    notice.className = "notice";
    notice.textContent = `Updated ${new Date().toLocaleTimeString()}`;
  }

  async function refresh() {
    notice.className = "notice";
    notice.textContent = "Loading management data…";
    try {
      const values = await Promise.all(Object.entries(endpoints).map(async ([key, path]) => [key, await readJson(path)]));
      render(Object.fromEntries(values));
    } catch (error) {
      notice.className = "notice error";
      notice.textContent = `Management data unavailable: ${error.message}`;
    }
  }

  $("refresh").addEventListener("click", refresh);
  token.addEventListener("change", refresh);
  refresh();
})();
"##;
