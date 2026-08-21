/*
 * Pooler management dashboard.
 *
 * Reads the redacted management JSON endpoints exposed by the pooler-server
 * management listener. The bearer token is held in memory only: it is never
 * persisted, never put in a URL, and only sent as the Authorization header
 * to this same listener. Mutations are body-free POSTs.
 */
(() => {
  "use strict";

  const BASE = "/management";
  const POLL_MS = 10_000;

  /* ---------------- State ---------------- */

  const state = {
    token: "",
    route: "overview",
    data: {},
    errors: {},
    loading: false,
    pollTimer: null,
    expanded: new Set(),
    filter: "",
  };

  /* ---------------- Small helpers ---------------- */

  const $ = (selector, root) => (root || document).querySelector(selector);

  function esc(value) {
    return String(value ?? "").replace(/[&<>"']/g, (ch) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    })[ch]);
  }

  function text(value) {
    return value === null || value === undefined || value === "" ? "—" : String(value);
  }

  function fmtInt(value) {
    if (value === null || value === undefined || Number.isNaN(Number(value))) return "—";
    return Number(value).toLocaleString("en-US");
  }

  function fmtCompact(value) {
    if (value === null || value === undefined || Number.isNaN(Number(value))) return "—";
    return new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 }).format(Number(value));
  }

  function pad2(n) { return String(n).padStart(2, "0"); }

  function fmtTime(unixMs) {
    if (!unixMs) return "—";
    const d = new Date(Number(unixMs));
    if (Number.isNaN(d.getTime())) return "—";
    return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
  }

  function relTime(unixMs) {
    if (!unixMs) return "—";
    const delta = Number(unixMs) - Date.now();
    const abs = Math.abs(delta);
    const future = delta > 0;
    let label;
    if (abs < 45_000) label = "now";
    else if (abs < 3_600_000) label = `${Math.round(abs / 60_000)}m`;
    else if (abs < 86_400_000) label = `${Math.round(abs / 3_600_000)}h`;
    else label = `${Math.round(abs / 86_400_000)}d`;
    if (label === "now") return future ? "soon" : "just now";
    return future ? `in ${label}` : `${label} ago`;
  }

  function shortId(value, head = 8) {
    const s = String(value ?? "");
    if (!s) return "—";
    return s.length <= head + 1 ? s : `${s.slice(0, head)}…`;
  }

  /* ---------------- API ---------------- */

  function requestHeaders() {
    return state.token ? { Authorization: `Bearer ${state.token}` } : {};
  }

  async function readJson(path) {
    const response = await fetch(`${BASE}${path}`, { headers: requestHeaders(), cache: "no-store" });
    if (!response.ok) {
      const detail = await response.json().catch(() => null);
      const message = detail && detail.error ? detail.error : `${response.status} ${response.statusText}`;
      const error = new Error(message);
      error.status = response.status;
      throw error;
    }
    return response.json();
  }

  async function mutate(path) {
    const response = await fetch(`${BASE}${path}`, { method: "POST", headers: requestHeaders(), cache: "no-store" });
    const detail = await response.json().catch(() => null);
    if (!response.ok) {
      const message = detail && detail.error ? detail.error : `${response.status} ${response.statusText}`;
      const error = new Error(message);
      error.status = response.status;
      throw error;
    }
    return detail || {};
  }

  async function downloadExport() {
    const response = await fetch(`${BASE}/export`, { headers: requestHeaders(), cache: "no-store" });
    if (!response.ok) {
      const detail = await response.json().catch(() => null);
      throw new Error(detail && detail.error ? detail.error : `${response.status} ${response.statusText}`);
    }
    const url = URL.createObjectURL(await response.blob());
    const link = document.createElement("a");
    link.href = url;
    link.download = `pooler-management-export-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
    link.hidden = true;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  function modelPath(id) {
    return String(id).split("/").map(encodeURIComponent).join("/");
  }

  /* ---------------- Icons ---------------- */

  function ic(name, size = 16) {
    return typeof iconSvg === "function" ? iconSvg(name, size) : "";
  }

  /* ---------------- Banners ---------------- */

  function notify(kind, message, options = {}) {
    const area = $("#banner-area");
    const banner = document.createElement("div");
    banner.className = `banner banner-${kind}`;
    banner.setAttribute("role", kind === "error" ? "alert" : "status");
    const iconName = { success: "check-circle", error: "cancel", warning: "warning-triangle", info: "info-empty" }[kind] || "info-empty";
    banner.innerHTML = `
      <span class="banner-icon">${ic(iconName, 16)}</span>
      <div class="banner-body">${message}</div>
      <button class="banner-dismiss" type="button" aria-label="Dismiss">${ic("cancel", 14)}</button>`;
    $(".banner-dismiss", banner).addEventListener("click", () => banner.remove());
    area.append(banner);
    if (options.sticky !== true && kind !== "error") {
      setTimeout(() => banner.remove(), 8000);
    }
    while (area.children.length > 3) area.firstElementChild.remove();
  }

  function authRequired() {
    notify("warning", `This listener requires the management bearer token. <button class="btn btn-outline btn-xs" type="button" data-open-session>Connect</button>`, { sticky: true });
    openSessionDialog();
  }

  /* ---------------- Dialogs ---------------- */

  function openSessionDialog() {
    const dialog = $("#session-dialog");
    $("#token-input").value = state.token;
    if (!dialog.open) dialog.showModal();
    setTimeout(() => $("#token-input").focus(), 50);
  }

  function confirmAction({ title, copy, acceptLabel = "Confirm", destructive = false }) {
    return new Promise((resolve) => {
      const dialog = $("#confirm-dialog");
      $("#confirm-title").textContent = title;
      $("#confirm-copy").innerHTML = copy;
      const accept = $("#confirm-accept");
      accept.textContent = acceptLabel;
      accept.className = destructive ? "btn btn-destructive" : "btn btn-primary";
      const settle = (value) => {
        dialog.removeEventListener("close", onClose);
        resolve(value);
      };
      const onClose = () => settle(false);
      dialog.addEventListener("close", onClose);
      $("#confirm-accept").onclick = () => { dialog.close(); settle(true); };
      $("#confirm-cancel").onclick = () => { dialog.close(); settle(false); };
      if (!dialog.open) dialog.showModal();
    });
  }

  /* ---------------- Components ---------------- */

  function statCard(label, value, hint = "") {
    return `
      <div class="stat-card">
        <span class="stat-label">${esc(label)}</span>
        <span class="stat-value">${value}</span>
        ${hint ? `<span class="stat-hint">${hint}</span>` : ""}
      </div>`;
  }

  const TONE_BADGE = { success: "badge-success", warning: "badge-warning", error: "badge-error", accent: "badge-accent", muted: "badge-neutral" };

  function toneForStatus(status) {
    const s = String(status ?? "").toLowerCase();
    if (["ok", "healthy", "succeeded", "success", "available", "enabled", "accepted"].includes(s)) return "success";
    if (["cooling_down", "degraded", "stale", "queued", "warning"].includes(s)) return "warning";
    if (["failed", "error", "unauthorized", "exhausted", "rejected_body", "rejected_origin", "not_found", "disabled"].includes(s)) return "error";
    if (["active", "running", "requested", "reload_requested"].includes(s)) return "accent";
    return "muted";
  }

  function statusBadge(status, tone) {
    const t = tone || toneForStatus(status);
    return `<span class="badge ${TONE_BADGE[t]}">${esc(text(status))}</span>`;
  }

  function enabledBadge(enabled) {
    return enabled
      ? `<span class="badge badge-success">enabled</span>`
      : `<span class="badge badge-neutral">disabled</span>`;
  }

  function brand(name, size = 16) {
    return typeof providerBadge === "function" ? providerBadge(name, size) : "";
  }

  function providerCell(name, mono = true) {
    if (name === null || name === undefined || name === "") return `<span class="muted">—</span>`;
    const label = String(name);
    return `<span class="provider-cell" title="${esc(label)}">${brand(label)}<span class="${mono ? "mono " : ""}cell-ellipsis">${esc(label)}</span></span>`;
  }

  function tableWrap(columns, rows, options = {}) {
    const head = columns.map((c) => `<th class="${c.align === "right" ? "cell-right" : ""}">${esc(c.label)}</th>`).join("");
    let body;
    if (options.loading) {
      body = Array.from({ length: 4 }, () =>
        `<tr class="skeleton-row">${columns.map(() => `<td><div class="skeleton-bar"></div></td>`).join("")}</tr>`).join("");
    } else if (options.error) {
      body = `<tr><td class="error-cell" colspan="${columns.length}">${esc(options.error)}</td></tr>`;
    } else if (!rows || rows.length === 0) {
      body = `<tr><td colspan="${columns.length}">
        <div class="empty-state">
          <p class="empty-title">${esc(options.emptyTitle || "Nothing here yet")}</p>
          ${options.emptyDescription ? `<p class="empty-description">${esc(options.emptyDescription)}</p>` : ""}
        </div></td></tr>`;
    } else {
      body = rows.map((row, i) => {
        const cells = columns.map((c) => {
          const cls = [c.align === "right" ? "cell-right" : "", c.mono ? "cell-mono" : "", c.nowrap === false ? "" : "cell-nowrap", c.className || ""].filter(Boolean).join(" ");
          return `<td class="${cls}">${c.render(row, i)}</td>`;
        }).join("");
        const key = options.rowKey ? options.rowKey(row, i) : i;
        const expandable = options.expandable ? ` data-expand="${esc(key)}" style="cursor:pointer"` : "";
        let detail = "";
        if (options.expandable && state.expanded.has(String(key))) {
          detail = `<tr class="detail-row"><td colspan="${columns.length}">${options.expandable(row)}</td></tr>`;
        }
        return `<tr${expandable}>${cells}</tr>${detail}`;
      }).join("");
    }
    return `<div class="table-wrap"><table class="data-table"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
  }

  function section(title, inner, hint = "") {
    return `
      <section class="section">
        <div class="toolbar">
          <h2 class="section-title">${esc(title)}</h2>
          ${hint ? `<span class="section-hint">${esc(hint)}</span>` : ""}
        </div>
        ${inner}
      </section>`;
  }

  function viewHeader(title, subtitle, actions = "") {
    return `
      <header class="view-header">
        <div>
          <h1 class="view-title">${esc(title)}</h1>
          ${subtitle ? `<p class="view-subtitle">${esc(subtitle)}</p>` : ""}
        </div>
        <div class="view-actions">${actions}</div>
      </header>`;
  }

  function endpointError(key) {
    return state.errors[key] ? state.errors[key].message : "";
  }

  /* ---------------- Data loading ---------------- */

  async function loadEndpoints(keys) {
    state.loading = true;
    await Promise.all(keys.map(async (key) => {
      const spec = ENDPOINTS[key];
      try {
        state.data[key] = await readJson(spec.path);
        state.errors[key] = null;
      } catch (error) {
        state.errors[key] = error;
        if (error.status === 401) authRequired();
      }
    }));
    state.loading = false;
    updateHeader();
  }

  const ENDPOINTS = {
    health: { path: "/health" },
    active: { path: "/active" },
    listeners: { path: "/listeners" },
    routes: { path: "/routes" },
    models: { path: "/models" },
    catalog: { path: "/catalog" },
    providers: { path: "/health/providers" },
    accounts: { path: "/accounts" },
    quota: { path: "/quota" },
    metrics: { path: "/metrics" },
    decisions: { path: "/decisions?limit=50" },
    traces: { path: "/traces" },
    audit: { path: "/audit" },
  };

  /* ---------------- Header ---------------- */

  function updateHeader() {
    const health = state.data.health;
    const generation = health?.configuration_generation
      ?? state.data.routes?.configuration_generation
      ?? state.data.models?.configuration_generation;
    $("#generation-badge").textContent = `gen ${text(generation)}`;
    $("#footer-updated").textContent = state.loading ? "Refreshing…" : `Updated ${fmtTime(Date.now())}`;
    $("#session-button").textContent = state.token ? "Session" : "Connect";
  }

  function updateThemeIcon() {
    const dark = document.documentElement.classList.contains("dark")
      || (!document.documentElement.classList.contains("light")
        && window.matchMedia("(prefers-color-scheme: dark)").matches);
    $("#theme-toggle").innerHTML = ic(dark ? "sun-light" : "half-moon", 18);
  }

  /* ---------------- Views ---------------- */

  const views = {
    overview: {
      title: "Overview",
      subtitle: "Runtime health, providers, accounts, and quota at a glance.",
      endpoints: ["health", "active", "providers", "accounts", "quota", "models", "listeners", "routes"],
      render: renderOverview,
    },
    models: {
      title: "Models",
      subtitle: "Published model view: configured entries, discovered catalog, aliases, and exposure.",
      endpoints: ["models", "catalog"],
      render: renderModels,
    },
    accounts: {
      title: "Accounts",
      subtitle: "Redacted account state and operator controls.",
      endpoints: ["accounts"],
      render: renderAccounts,
    },
    usage: {
      title: "Usage",
      subtitle: "Token usage, provider-reported cost, rate-limit windows, and latency.",
      endpoints: ["metrics", "quota"],
      render: renderUsage,
    },
    operations: {
      title: "Operations",
      subtitle: "Configuration reloads, routing decisions, traces, and the management audit log.",
      endpoints: ["decisions", "traces", "audit"],
      render: renderOperations,
    },
    diagnostics: {
      title: "Diagnostics",
      subtitle: "Redacted export and configuration state for support bundles.",
      endpoints: ["health", "catalog", "listeners", "routes"],
      render: renderDiagnostics,
    },
  };

  /* ---------------- Overview ---------------- */

  function renderOverview(root) {
    const health = state.data.health || {};
    const providers = state.data.providers?.providers || [];
    const accounts = state.data.accounts?.accounts || [];
    const quota = state.data.quota || {};
    const models = state.data.models?.models || [];
    const listeners = state.data.listeners?.listeners || [];
    const routes = state.data.routes?.routes || [];
    const active = state.data.active || {};

    const healthyProviders = providers.filter((p) => p.status === "healthy").length;
    const enabledAccounts = accounts.filter((a) => a.enabled).length;
    const cooldowns = quota.cooldowns || [];
    const windows = quota.windows || [];

    const stats = [
      statCard("Status", statusBadge(health.status || (endpointError("health") ? "error" : "unknown")),
        endpointError("health") ? esc(endpointError("health")) : `${fmtInt(health.credential_health_entries)} health entries`),
      statCard("Active requests", `<span class="num">${fmtInt(active.active ?? health.active)}</span>`, "Across all listeners"),
      statCard("Providers", `<span class="num">${fmtInt(healthyProviders)}<span class="muted">/${fmtInt(providers.length)}</span></span>`, "Healthy upstreams"),
      statCard("Accounts", `<span class="num">${fmtInt(enabledAccounts)}<span class="muted">/${fmtInt(accounts.length)}</span></span>`, "Enabled accounts"),
      statCard("Models", `<span class="num">${fmtInt(models.length)}</span>`, "Published model IDs"),
      statCard("Quota windows", `<span class="num">${fmtInt(windows.length)}</span>`, cooldowns.length ? `${fmtInt(cooldowns.length)} active cooldowns` : "No active cooldowns"),
    ].join("");

    const providerTable = tableWrap([
      { label: "ID", mono: true, render: (p) => providerCell(p.id) },
      { label: "Transport", render: (p) => esc(text(p.transport)) },
      { label: "Native", render: (p) => esc(text(p.native)) },
      { label: "Auth", render: (p) => p.auth_configured ? `<span class="inline-meta muted">${ic("lock", 13)} configured</span>` : `<span class="muted">—</span>` },
      { label: "Status", render: (p) => statusBadge(p.status) },
    ], providers, {
      loading: state.loading && !state.data.providers,
      error: endpointError("providers"),
      emptyTitle: "No providers configured",
    });

    const listenerTable = tableWrap([
      { label: "ID", mono: true, render: (l) => esc(l.id) },
      { label: "Bind", mono: true, render: (l) => esc(l.bind) },
      { label: "Protocol", render: (l) => esc(text(l.protocol)) },
      { label: "TLS", render: (l) => l.tls ? `<span class="inline-meta muted">${ic("lock", 13)} yes</span>` : `<span class="muted">no</span>` },
      { label: "Routes", align: "right", render: (l) => `<span class="num">${fmtInt(l.route_count)}</span>` },
    ], listeners, {
      loading: state.loading && !state.data.listeners,
      error: endpointError("listeners"),
      emptyTitle: "No listeners configured",
    });

    const routeTable = tableWrap([
      { label: "ID", mono: true, render: (r) => esc(r.id) },
      { label: "Listener", mono: true, render: (r) => esc(r.listener) },
      { label: "Path", mono: true, nowrap: false, render: (r) => esc(text(r.path)) },
      { label: "Target", mono: true, nowrap: false, render: (r) => esc(text(r.target?.upstream)) },
    ], routes, {
      loading: state.loading && !state.data.routes,
      error: endpointError("routes"),
      emptyTitle: "No routes compiled",
    });

    const activeByListener = Object.entries(active.by_listener || {});
    const activeTable = activeByListener.length
      ? tableWrap([
          { label: "Listener", mono: true, render: ([id]) => esc(id) },
          { label: "Active", align: "right", render: ([, count]) => `<span class="num">${fmtInt(count)}</span>` },
        ], activeByListener, {})
      : "";

    root.innerHTML = `
      ${viewHeader("Overview", views.overview.subtitle, `<span class="section-hint">Auto-refreshes every ${POLL_MS / 1000}s</span>`)}
      ${cooldowns.length ? `<div class="banner banner-warning"><span class="banner-icon">${ic("hourglass", 16)}</span><div class="banner-body">${fmtInt(cooldowns.length)} cooldown${cooldowns.length === 1 ? "" : "s"} in effect. See Usage for details.</div></div>` : ""}
      <section class="grid-stats">${stats}</section>
      ${section("Providers", providerTable)}
      <div class="grid-2">
        ${section("Listeners", listenerTable)}
        ${section("Routes", routeTable)}
      </div>
      ${activeTable ? section("Active by listener", activeTable) : ""}`;
  }

  /* ---------------- Models ---------------- */

  function renderModels(root) {
    const payload = state.data.models || {};
    const catalog = state.data.catalog || {};
    let models = payload.models || [];
    const sources = payload.catalog_sources || catalog.sources || [];
    const overrides = payload.model_overrides || {};

    if (state.filter) {
      const needle = state.filter.toLowerCase();
      models = models.filter((m) =>
        String(m.id).toLowerCase().includes(needle)
        || (m.targets || []).some((t) => `${t.provider} ${t.upstream_model}`.toLowerCase().includes(needle)));
    }

    const configured = (payload.models || []).filter((m) => m.selection_origin === "configured").length;
    const discovered = (payload.models || []).length - configured;

    const stats = [
      statCard("Published", `<span class="num">${fmtInt((payload.models || []).length)}</span>`, "Merged model view"),
      statCard("Configured", `<span class="num">${fmtInt(configured)}</span>`, "Declared in config"),
      statCard("Discovered", `<span class="num">${fmtInt(discovered)}</span>`, "From catalog sources"),
      statCard("Catalog sources", `<span class="num">${fmtInt(sources.length)}</span>`, catalog.catalog_generation ? `catalog gen ${esc(catalog.catalog_generation)}` : "No catalog runtime"),
    ].join("");

    const modelTable = tableWrap([
      { label: "Model", mono: true, nowrap: false, render: (m) => providerCell(m.id) },
      { label: "Origin", render: (m) => `<span class="badge ${m.selection_origin === "configured" ? "badge-accent" : "badge-neutral"}">${esc(text(m.selection_origin || "discovered"))}</span>` },
      { label: "Targets", nowrap: false, render: (m) => (m.targets || []).map((t) =>
          `<div class="inline-meta" style="padding-block:1px">${providerCell(t.provider)}<span class="muted">→</span><span class="mono">${esc(text(t.upstream_model))}</span></div>`).join("") || "—" },
      { label: "Capabilities", nowrap: false, render: (m) => {
          const caps = [...new Set((m.targets || []).flatMap((t) => t.capabilities || []))];
          return caps.length ? caps.map((c) => `<span class="chip">${esc(c)}</span>`).join(" ") : "—";
        } },
      { label: "Exposure", render: (m) => enabledBadge(m.enabled !== false) },
      { label: "Actions", render: (m) => {
          const enabled = m.enabled !== false;
          const action = enabled ? "disable" : "enable";
          return `<div class="row-actions">
            <button class="btn btn-subtle btn-xs" type="button" data-model-action="${action}" data-model-id="${esc(m.id)}">
              ${ic(enabled ? "pause" : "play", 13)} ${enabled ? "Disable" : "Enable"}
            </button>
          </div>`;
        } },
    ], models, {
      loading: state.loading && !state.data.models,
      error: endpointError("models"),
      emptyTitle: state.filter ? "No models match the filter" : "No published models",
      emptyDescription: state.filter ? "" : "Configure models or catalog sources, then reload.",
    });

    const sourceTable = tableWrap([
      { label: "Source", mono: true, render: (s) => esc(s.id) },
      { label: "Provider", mono: true, render: (s) => providerCell(s.provider) },
      { label: "Parser", render: (s) => esc(text(s.parser)) },
      { label: "Prefix", mono: true, render: (s) => esc(text(s.prefix)) },
      { label: "Priority", align: "right", render: (s) => `<span class="num">${fmtInt(s.priority)}</span>` },
      { label: "Aliases", align: "right", render: (s) => `<span class="num">${fmtInt((s.aliases || []).length)}</span>` },
      { label: "State", nowrap: false, render: (s) => renderSourceState(s.state) },
    ], sources, {
      loading: state.loading && !state.data.models,
      error: endpointError("catalog"),
      emptyTitle: "No catalog sources",
      emptyDescription: "Discovery sources appear here when a model catalog is configured.",
    });

    const aliasRows = sources.flatMap((s) => (s.aliases || []).map((a) => ({ ...a, source: s.id })));
    const aliasTable = aliasRows.length ? tableWrap([
      { label: "Upstream ID", mono: true, nowrap: false, render: (a) => esc(a.name) },
      { label: "Public alias", mono: true, nowrap: false, render: (a) => esc(a.alias) },
      { label: "Display name", render: (a) => esc(text(a.display_name)) },
      { label: "Source", mono: true, render: (a) => esc(a.source) },
      { label: "Fork", render: (a) => (a.fork ? `<span class="chip">fork</span>` : "—") },
    ], aliasRows, {}) : "";

    const disabledOverrides = overrides.disabled_models || [];
    const unmatchedOverrides = overrides.unmatched_models || [];
    const overrideBlock = (disabledOverrides.length || unmatchedOverrides.length) ? `
      <div class="panel">
        <div class="toolbar"><h2 class="section-title">Catalog overrides</h2></div>
        ${disabledOverrides.length ? `<p class="section-hint" style="margin-top:8px">Disabled by override</p><div class="inline-meta">${disabledOverrides.map((m) => `<span class="chip mono">${esc(m)}</span>`).join("")}</div>` : ""}
        ${unmatchedOverrides.length ? `<p class="section-hint" style="margin-top:8px">Unmatched overrides</p><div class="inline-meta">${unmatchedOverrides.map((m) => `<span class="chip mono">${esc(m)}</span>`).join("")}</div>` : ""}
      </div>` : "";

    root.innerHTML = `
      ${viewHeader("Models", views.models.subtitle, `
        <input id="model-filter" class="filter-input" type="search" placeholder="Filter models" value="${esc(state.filter)}" aria-label="Filter models">
        <button class="btn btn-outline btn-sm" type="button" data-action="reload-models">${ic("refresh-double", 15)} Reload catalog</button>`)}
      <section class="grid-stats" style="grid-template-columns:repeat(4,minmax(0,1fr))">${stats}</section>
      ${section("Published models", modelTable, "Enablement is a runtime control; durable policy belongs in catalog overrides.")}
      ${section("Catalog sources", sourceTable)}
      ${aliasTable ? section("Aliases", aliasTable) : ""}
      ${overrideBlock}`;

    const filter = $("#model-filter", root);
    filter.addEventListener("input", () => {
      state.filter = filter.value;
      const pos = filter.selectionStart;
      renderModels(root);
      const again = $("#model-filter", root);
      again.focus();
      again.setSelectionRange(pos, pos);
    });
  }

  function renderSourceState(sourceState) {
    if (!sourceState) return `<span class="muted">—</span>`;
    if (typeof sourceState === "string") return statusBadge(sourceState);
    const status = sourceState.status || sourceState.state || sourceState.kind;
    const detail = sourceState.error || sourceState.detail || sourceState.message;
    return `${statusBadge(status || "unknown")}${detail ? ` <span class="muted" title="${esc(detail)}">${esc(shortId(detail, 40))}</span>` : ""}`;
  }

  /* ---------------- Accounts ---------------- */

  function renderAccounts(root) {
    const accounts = state.data.accounts?.accounts || [];

    const healthy = accounts.filter((a) => a.status === "healthy").length;
    const cooling = accounts.filter((a) => a.status === "cooling_down").length;

    const stats = [
      statCard("Accounts", `<span class="num">${fmtInt(accounts.length)}</span>`, "Configured accounts"),
      statCard("Healthy", `<span class="num">${fmtInt(healthy)}</span>`, "Selectable now"),
      statCard("Cooling down", `<span class="num">${fmtInt(cooling)}</span>`, "Temporarily excluded"),
      statCard("Enabled", `<span class="num">${fmtInt(accounts.filter((a) => a.enabled).length)}</span>`, "Operator-enabled"),
    ].join("");

    const accountTable = tableWrap([
      { label: "ID", mono: true, nowrap: false, render: (a) => `<div class="cell-ellipsis" title="${esc(a.id)}">${esc(a.id)}</div>` },
      { label: "Provider", mono: true, render: (a) => providerCell(a.provider) },
      { label: "Enabled", render: (a) => enabledBadge(a.enabled) },
      { label: "Status", render: (a) => statusBadge(a.status) },
      { label: "Failures", align: "right", render: (a) => `<span class="num">${fmtInt(a.failure_count)}</span>` },
      { label: "Cooldown", render: (a) => a.cooldown_until
          ? `<span class="num" title="${esc(fmtTime(a.cooldown_until))}">${esc(relTime(a.cooldown_until))}</span>`
          : `<span class="muted">—</span>` },
      { label: "Actions", nowrap: false, render: (a) => {
          const id = esc(a.id);
          return `<div class="row-actions">
            <button class="btn btn-subtle btn-xs" type="button" data-account-action="switch" data-account-id="${id}" title="Make this the selected account for its provider">${ic("switch-on", 13)} Switch</button>
            <button class="btn btn-subtle btn-xs" type="button" data-account-action="${a.enabled ? "disable" : "enable"}" data-account-id="${id}">${ic(a.enabled ? "pause" : "play", 13)} ${a.enabled ? "Disable" : "Enable"}</button>
            <button class="btn btn-subtle btn-xs" type="button" data-account-action="refresh" data-account-id="${id}" title="Queue an OAuth token refresh">${ic("refresh-double", 13)} Refresh</button>
            <button class="btn btn-subtle btn-xs" type="button" data-account-action="revoke" data-account-id="${id}" title="Remove Pooler's local credential and disable the account">${ic("trash", 13)} Revoke</button>
          </div>`;
        } },
    ], accounts, {
      loading: state.loading && !state.data.accounts,
      error: endpointError("accounts"),
      emptyTitle: "No accounts configured",
      emptyDescription: "Accounts are declared in configuration and authenticated on the server.",
    });

    root.innerHTML = `
      ${viewHeader("Accounts", views.accounts.subtitle)}
      <section class="grid-stats" style="grid-template-columns:repeat(4,minmax(0,1fr))">${stats}</section>
      ${section("Accounts", accountTable, "Switch enables the account and disables its same-provider siblings atomically.")}
      <div class="banner banner-info">
        <span class="banner-icon">${ic("shield", 16)}</span>
        <div class="banner-body">Refresh and revoke apply to OAuth accounts only, are queued on the native runtime, and their result lands in the audit log under Operations. Revocation removes Pooler's local credential payload; it does not claim provider-side revocation.</div>
      </div>`;
  }

  /* ---------------- Usage ---------------- */

  function renderUsage(root) {
    const metrics = state.data.metrics?.metrics || {};
    const quota = state.data.quota || {};
    const usage = metrics.usage || [];
    const attempts = metrics.attempts || [];
    const latencies = metrics.latencies || [];
    const windows = quota.windows || [];
    const cooldowns = quota.cooldowns || [];

    const sum = (rows, field) => rows.reduce((total, row) => total + (Number(row[field]) || 0), 0);
    const totalRequests = sum(usage, "requests") || sum(attempts, "count");
    const inputTokens = sum(usage, "input_tokens");
    const outputTokens = sum(usage, "output_tokens");
    const costTicks = sum(usage, "cost_in_usd_ticks");

    const stats = [
      statCard("Requests", `<span class="num">${fmtCompact(totalRequests)}</span>`, "Observed attempts"),
      statCard("Input tokens", `<span class="num" title="${fmtInt(inputTokens)}">${fmtCompact(inputTokens)}</span>`, "Normalized from responses"),
      statCard("Output tokens", `<span class="num" title="${fmtInt(outputTokens)}">${fmtCompact(outputTokens)}</span>`, "Normalized from responses"),
      statCard("Cost ticks", `<span class="num" title="${fmtInt(costTicks)}">${fmtCompact(costTicks)}</span>`, "Provider-reported, fixed-decimal"),
      statCard("Quota windows", `<span class="num">${fmtInt(windows.length)}</span>`, "Typed windows observed"),
      statCard("Cooldowns", `<span class="num">${fmtInt(cooldowns.length)}</span>`, cooldowns.length ? "Selection is avoiding entries" : "Nothing cooling down"),
    ].join("");

    const usageTable = tableWrap([
      { label: "Route", mono: true, render: (u) => esc(u.route) },
      { label: "Provider", mono: true, render: (u) => providerCell(u.provider) },
      { label: "Model", mono: true, nowrap: false, render: (u) => providerCell(u.model) },
      { label: "Requests", align: "right", render: (u) => `<span class="num">${fmtInt(u.requests)}</span>` },
      { label: "Input", align: "right", render: (u) => `<span class="num">${fmtInt(u.input_tokens)}</span>` },
      { label: "Output", align: "right", render: (u) => `<span class="num">${fmtInt(u.output_tokens)}</span>` },
      { label: "Total", align: "right", render: (u) => `<span class="num">${fmtInt(u.total_tokens)}</span>` },
      { label: "Cost ticks", align: "right", render: (u) => `<span class="num">${fmtInt(u.cost_in_usd_ticks)}</span>` },
    ], usage, {
      loading: state.loading && !state.data.metrics,
      error: endpointError("metrics"),
      emptyTitle: "No usage recorded yet",
      emptyDescription: "Token usage appears after the first attributed responses.",
    });

    const windowTable = tableWrap([
      { label: "Scope", render: (w) => `<span class="badge badge-neutral">${esc(text(w.identity?.kind || w.scope))}</span>` },
      { label: "Subject", mono: true, nowrap: false, render: (w) => esc(quotaSubject(w)) },
      { label: "Unit", render: (w) => esc(text(w.unit)) },
      { label: "State", render: (w) => statusBadge(w.state) },
      { label: "Remaining", align: "right", render: (w) => `<span class="num">${w.remaining === null || w.remaining === undefined ? "—" : fmtInt(w.remaining)}</span>${w.limit ? `<span class="muted"> / ${fmtInt(w.limit)}</span>` : ""}` },
      { label: "Reset", render: (w) => w.reset_at_unix_ms
          ? `<span class="num" title="${esc(fmtTime(w.reset_at_unix_ms))}">${esc(relTime(w.reset_at_unix_ms))}</span>`
          : `<span class="muted">—</span>` },
    ], windows, {
      loading: state.loading && !state.data.quota,
      error: endpointError("quota"),
      emptyTitle: "No quota windows observed",
      emptyDescription: "Windows appear when providers report rate-limit state.",
    });

    const cooldownTable = tableWrap([
      { label: "Scope", render: (c) => `<span class="badge badge-neutral">${esc(text(c.scope))}</span>` },
      { label: "Key", mono: true, nowrap: false, render: (c) => esc(c.key) },
      { label: "Until", render: (c) => `<span class="num" title="${esc(fmtTime(c.until))}">${esc(relTime(c.until))}</span>` },
      { label: "Reason", nowrap: false, render: (c) => esc(text(c.reason)) },
    ], cooldowns, {
      loading: state.loading && !state.data.quota,
      error: endpointError("quota"),
      emptyTitle: "No active cooldowns",
    });

    const latencyTable = tableWrap([
      { label: "Route", mono: true, render: (l) => esc(l.route) },
      { label: "Kind", render: (l) => esc(text(l.kind)) },
      { label: "Samples", align: "right", render: (l) => `<span class="num">${fmtInt(l.histogram?.count)}</span>` },
      { label: "Mean", align: "right", render: (l) => {
          const h = l.histogram || {};
          const mean = h.count ? Math.round((h.sum_ms || 0) / h.count) : null;
          return `<span class="num">${mean === null ? "—" : `${fmtInt(mean)} ms`}</span>`;
        } },
      { label: "Max", align: "right", render: (l) => `<span class="num">${l.histogram?.max_ms === undefined ? "—" : `${fmtInt(l.histogram.max_ms)} ms`}</span>` },
    ], latencies, {
      loading: state.loading && !state.data.metrics,
      error: endpointError("metrics"),
      emptyTitle: "No latency samples yet",
    });

    root.innerHTML = `
      ${viewHeader("Usage", views.usage.subtitle)}
      <section class="grid-stats">${stats}</section>
      ${section("Token usage", usageTable, "Cost is recorded only when a provider response supplies it.")}
      <div class="grid-2">
        ${section("Quota windows", windowTable)}
        ${section("Cooldowns", cooldownTable)}
      </div>
      ${section("Latency", latencyTable)}`;
  }

  function quotaSubject(windowRow) {
    const identity = windowRow.identity || {};
    const parts = [];
    if (identity.provider) parts.push(identity.provider);
    if (identity.credential) parts.push(identity.credential);
    if (identity.project) parts.push(identity.project);
    if (identity.model) parts.push(identity.model);
    return parts.length ? parts.join(" / ") : "—";
  }

  /* ---------------- Operations ---------------- */

  function renderOperations(root) {
    const decisions = state.data.decisions?.decisions || [];
    const traces = state.data.traces?.traces || [];
    const audit = state.data.audit?.events || [];
    const droppedTraces = state.data.traces?.dropped || 0;

    const actionsPanel = `
      <div class="panel">
        <div class="toolbar">
          <h2 class="section-title">Runtime controls</h2>
          <span class="spacer"></span>
          <button class="btn btn-outline btn-sm" type="button" data-action="reload-config">${ic("refresh", 15)} Reload configuration</button>
          <button class="btn btn-outline btn-sm" type="button" data-action="reload-models">${ic("refresh-double", 15)} Reload model catalog</button>
        </div>
        <p class="section-hint" style="margin-top:8px">
          Reload asks the serving process to reread and compile the configured source. Invalid candidates leave the active generation unchanged. Listener and management binding changes require a restart.
        </p>
      </div>`;

    const decisionTable = tableWrap([
      { label: "Time", render: (d) => `<span class="num muted" title="${esc(fmtTime(d.recorded_at))}">${esc(relTime(d.recorded_at))}</span>` },
      { label: "Request", mono: true, render: (d) => `<span title="${esc(d.request_id)}">${esc(shortId(d.request_id))}</span>` },
      { label: "Route", mono: true, render: (d) => esc(d.route_id) },
      { label: "Model", mono: true, nowrap: false, render: (d) => providerCell(d.model) },
      { label: "Selected", mono: true, nowrap: false, render: (d) => providerCell(d.selected_provider) },
      { label: "Credential", mono: true, render: (d) => esc(text(d.selected_credential)) },
      { label: "Attempt", align: "right", render: (d) => `<span class="num">${fmtInt(d.attempt)}</span>` },
      { label: "Candidates", align: "right", render: (d) => `<span class="num muted">${fmtInt((d.candidates || []).length)}</span>` },
      { label: "Reason", nowrap: false, render: (d) => esc(text(d.reason)) },
    ], [...decisions].reverse(), {
      loading: state.loading && !state.data.decisions,
      error: endpointError("decisions"),
      emptyTitle: "No routing decisions recorded",
      emptyDescription: "Decisions appear as requests flow through the proxy.",
      rowKey: (d, i) => String(d.id || i),
      expandable: (d) => `
        <div style="padding:4px 0">
          ${tableWrap([
            { label: "Provider", mono: true, render: (c) => providerCell(c.provider_id) },
            { label: "Credential", mono: true, render: (c) => esc(text(c.credential_id)) },
            { label: "Score", align: "right", render: (c) => `<span class="num">${fmtInt(c.score)}</span>` },
            { label: "Eligible", render: (c) => (c.eligible ? statusBadge("eligible", "success") : statusBadge("ineligible", "muted")) },
            { label: "Reason", nowrap: false, render: (c) => esc(text(c.reason)) },
          ], d.candidates || [], { emptyTitle: "No candidates recorded" })}
        </div>`,
    });

    const traceTable = tableWrap([
      { label: "Time", render: (t) => `<span class="num muted" title="${esc(fmtTime(t.timestamp_ms))}">${esc(relTime(t.timestamp_ms))}</span>` },
      { label: "Stage", render: (t) => `<span class="badge badge-neutral">${esc(text(t.stage))}</span>` },
      { label: "Route", mono: true, render: (t) => esc(text(t.route)) },
      { label: "Provider", mono: true, render: (t) => providerCell(t.provider) },
      { label: "Attempt", align: "right", render: (t) => `<span class="num">${t.attempt === undefined ? "—" : fmtInt(t.attempt)}</span>` },
      { label: "Duration", align: "right", render: (t) => `<span class="num">${t.duration_ms === undefined || t.duration_ms === null ? "—" : `${fmtInt(t.duration_ms)} ms`}</span>` },
      { label: "Outcome", render: (t) => statusBadge(t.outcome) },
    ], [...traces].reverse(), {
      loading: state.loading && !state.data.traces,
      error: endpointError("traces"),
      emptyTitle: "No traces recorded",
      emptyDescription: "Bounded, redacted runtime traces appear here.",
    });

    const auditTable = tableWrap([
      { label: "Time", render: (e) => `<span class="num muted" title="${esc(fmtTime(e.timestamp_ms))}">${esc(relTime(e.timestamp_ms))}</span>` },
      { label: "Action", mono: true, render: (e) => esc(text(e.action)) },
      { label: "Subject", mono: true, nowrap: false, render: (e) => esc(text(e.subject)) },
      { label: "Outcome", render: (e) => statusBadge(e.outcome) },
    ], [...audit].reverse(), {
      loading: state.loading && !state.data.audit,
      error: endpointError("audit"),
      emptyTitle: "No management mutations yet",
      emptyDescription: "Audit events are process-local and reset on restart.",
    });

    root.innerHTML = `
      ${viewHeader("Operations", views.operations.subtitle)}
      ${actionsPanel}
      ${section("Routing decisions", decisionTable, "Newest first. Select a row to inspect candidates.")}
      ${section("Traces", traceTable, droppedTraces ? `${fmtInt(droppedTraces)} records dropped by bounded retention` : "Bounded process-local retention")}
      ${section("Audit log", auditTable)}`;
  }

  /* ---------------- Diagnostics ---------------- */

  function renderDiagnostics(root) {
    const health = state.data.health || {};
    const catalog = state.data.catalog || {};
    const listeners = state.data.listeners?.listeners || [];
    const routes = state.data.routes?.routes || [];

    const exportPanel = `
      <div class="panel">
        <div class="toolbar">
          <h2 class="section-title">Diagnostic export</h2>
          <span class="spacer"></span>
          <button class="btn btn-primary btn-sm" type="button" data-action="export">${ic("cloud-download", 15)} Download export</button>
        </div>
        <p class="section-hint" style="margin-top:8px">
          A versioned JSON snapshot of health, plans, accounts, quota, models, metrics, traces, and audit events, redacted at the API boundary.
          It is a diagnostic backup, not a credential backup: credential payloads, secret references, request bodies, and authorization headers are never included, and it cannot restore tokens.
        </p>
      </div>`;

    const configRows = [
      ["Configuration generation", text(health.configuration_generation ?? state.data.routes?.configuration_generation)],
      ["Catalog generation", catalog.catalog_generation ? text(catalog.catalog_generation) : "—"],
      ["Catalog refreshed", catalog.catalog_refreshed_at_unix_ms ? `${fmtTime(catalog.catalog_refreshed_at_unix_ms)} (${relTime(catalog.catalog_refreshed_at_unix_ms)})` : "—"],
      ["Listeners", fmtInt(listeners.length)],
      ["Compiled routes", fmtInt(routes.length)],
      ["Health entries", fmtInt(health.credential_health_entries)],
      ["Cooling providers", fmtInt(health.cooling_provider_entries)],
    ];
    const configPanel = `
      <div class="panel">
        <h2 class="section-title">Configuration state</h2>
        <dl class="kv-list" style="margin-top:12px">
          ${configRows.map(([k, v]) => `<dt>${esc(k)}</dt><dd class="mono">${esc(v)}</dd>`).join("")}
        </dl>
      </div>`;

    const failed = Object.entries(state.errors).filter(([, error]) => error);
    const errorRows = failed.map(([key, error]) => ({
      endpoint: ENDPOINTS[key]?.path || key,
      message: error.status ? `${error.status} — ${error.message}` : error.message,
    }));
    const errorPanel = `
      <div class="panel">
        <h2 class="section-title">Endpoint errors</h2>
        <p class="section-hint" style="margin-top:4px">Errors observed by this dashboard in the current session, including unavailable state stores and rejected reloads.</p>
        <div style="margin-top:12px">
          ${tableWrap([
            { label: "Endpoint", mono: true, render: (e) => esc(e.endpoint) },
            { label: "Error", nowrap: false, render: (e) => esc(e.message) },
          ], errorRows, { emptyTitle: "No errors observed", emptyDescription: "Every management endpoint answered successfully in this session." })}
        </div>
      </div>`;

    const redactionPanel = `
      <div class="banner banner-info">
        <span class="banner-icon">${ic("shield", 16)}</span>
        <div class="banner-body">
          Accounts, traces, audit events, and exports contain metadata only. Credential entry, OAuth callbacks, and token storage stay server-side; this dashboard never sees a credential payload.
        </div>
      </div>`;

    root.innerHTML = `
      ${viewHeader("Diagnostics", views.diagnostics.subtitle)}
      ${exportPanel}
      <div class="grid-2">
        ${configPanel}
        ${errorPanel}
      </div>
      ${redactionPanel}`;
  }

  /* ---------------- Mutations ---------------- */

  async function runMutation(path, { confirm, successMessage, queuedMessage }) {
    try {
      if (confirm) {
        const accepted = await confirmAction(confirm);
        if (!accepted) return;
      }
      const result = await mutate(path);
      if (result.status === "queued" && queuedMessage) {
        notify("info", queuedMessage(result));
      } else {
        notify("success", successMessage ? successMessage(result) : "Done.");
      }
    } catch (error) {
      if (error.status === 401) {
        authRequired();
      } else {
        notify("error", esc(error.message));
      }
    }
    await refreshCurrentView();
  }

  function accountAction(accountId, action) {
    const path = `/accounts/${encodeURIComponent(accountId)}/${action}`;
    const label = action.charAt(0).toUpperCase() + action.slice(1);
    if (action === "revoke") {
      return runMutation(path, {
        confirm: {
          title: `Revoke ${accountId}?`,
          copy: `Pooler removes its local credential payload for <span class="mono">${esc(accountId)}</span> and disables the account. Provider-side revocation only happens when the provider flow performs it.`,
          acceptLabel: "Revoke",
          destructive: true,
        },
        queuedMessage: () => `Revocation queued for ${esc(accountId)}. The result lands in the audit log under Operations.`,
        successMessage: () => `Revoked ${esc(accountId)}.`,
      });
    }
    if (action === "refresh") {
      return runMutation(path, {
        queuedMessage: () => `Refresh queued for ${esc(accountId)}. The result lands in the audit log under Operations.`,
        successMessage: () => `Refresh requested for ${esc(accountId)}.`,
      });
    }
    if (action === "switch") {
      return runMutation(path, {
        successMessage: () => `Switched to ${esc(accountId)}; same-provider siblings were disabled.`,
      });
    }
    return runMutation(path, { successMessage: () => `${label}d ${esc(accountId)}.` });
  }

  function modelAction(modelId, action) {
    const path = `/models/${modelPath(modelId)}/${action}`;
    return runMutation(path, {
      successMessage: () => `${action === "enable" ? "Enabled" : "Disabled"} ${esc(modelId)}.`,
    });
  }

  /* ---------------- Router and polling ---------------- */

  function currentRoute() {
    const hash = window.location.hash.replace(/^#\/?/, "").split("?")[0];
    return views[hash] ? hash : "overview";
  }

  async function refreshCurrentView() {
    const view = views[state.route];
    await loadEndpoints(view.endpoints);
    view.render($("#view"));
  }

  function stopPolling() {
    if (state.pollTimer) {
      clearInterval(state.pollTimer);
      state.pollTimer = null;
    }
  }

  function startPolling() {
    stopPolling();
    state.pollTimer = setInterval(() => {
      if (document.visibilityState === "visible") refreshCurrentView();
    }, POLL_MS);
  }

  async function navigate() {
    state.route = currentRoute();
    state.filter = "";
    state.expanded.clear();
    document.querySelectorAll(".nav-link").forEach((link) => {
      link.classList.toggle("active", link.dataset.route === state.route);
    });
    const view = views[state.route];
    $("#view").innerHTML = `
      ${viewHeader(view.title, view.subtitle)}
      <div class="table-wrap"><table class="data-table"><tbody>
        ${Array.from({ length: 5 }, () => `<tr class="skeleton-row"><td><div class="skeleton-bar"></div></td><td><div class="skeleton-bar"></div></td><td><div class="skeleton-bar"></div></td></tr>`).join("")}
      </tbody></table></div>`;
    await refreshCurrentView();
    startPolling();
  }

  /* ---------------- Boot ---------------- */

  function bindStaticChrome() {
    document.querySelectorAll("[data-icon]").forEach((slot) => {
      slot.innerHTML = ic(slot.dataset.icon, 16);
    });
    $("#refresh-now").innerHTML = ic("refresh", 16);
    $("#session-dialog [data-close]").innerHTML = ic("cancel", 16);
    $("#confirm-dialog [data-close]").innerHTML = ic("cancel", 16);
    $("#token-visibility").innerHTML = ic("eye-empty", 16);

    $("#theme-toggle").addEventListener("click", () => {
      const rootEl = document.documentElement;
      const dark = rootEl.classList.contains("dark")
        || (!rootEl.classList.contains("light") && window.matchMedia("(prefers-color-scheme: dark)").matches);
      rootEl.classList.toggle("dark", !dark);
      rootEl.classList.toggle("light", dark);
      updateThemeIcon();
    });
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", updateThemeIcon);
    updateThemeIcon();

    $("#refresh-now").addEventListener("click", () => refreshCurrentView());
    $("#session-button").addEventListener("click", openSessionDialog);
    document.querySelectorAll("[data-close]").forEach((button) => {
      button.addEventListener("click", () => $("#" + button.dataset.close).close());
    });

    $("#token-apply").addEventListener("click", () => {
      state.token = $("#token-input").value.trim();
      $("#session-dialog").close();
      updateHeader();
      refreshCurrentView();
    });
    $("#token-input").addEventListener("keydown", (event) => {
      if (event.key === "Enter") $("#token-apply").click();
    });
    $("#token-clear").addEventListener("click", () => {
      state.token = "";
      $("#token-input").value = "";
      $("#session-dialog").close();
      updateHeader();
      refreshCurrentView();
    });
    $("#token-visibility").addEventListener("click", () => {
      const input = $("#token-input");
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      $("#token-visibility").innerHTML = ic(show ? "eye-off" : "eye-empty", 16);
      input.focus();
    });

    $("#view").addEventListener("click", (event) => {
      const openSession = event.target.closest("[data-open-session]");
      if (openSession) { openSessionDialog(); return; }

      const accountButton = event.target.closest("[data-account-action]");
      if (accountButton) {
        accountAction(accountButton.dataset.accountId, accountButton.dataset.accountAction);
        return;
      }
      const modelButton = event.target.closest("[data-model-action]");
      if (modelButton) {
        modelAction(modelButton.dataset.modelId, modelButton.dataset.modelAction);
        return;
      }
      const actionButton = event.target.closest("[data-action]");
      if (actionButton) {
        handleViewAction(actionButton.dataset.action);
        return;
      }
      const expandRow = event.target.closest("[data-expand]");
      if (expandRow) {
        const key = expandRow.dataset.expand;
        if (state.expanded.has(key)) state.expanded.delete(key);
        else state.expanded.add(key);
        views[state.route].render($("#view"));
      }
    });

    $("#banner-area").addEventListener("click", (event) => {
      if (event.target.closest("[data-open-session]")) openSessionDialog();
    });
  }

  function handleViewAction(action) {
    if (action === "reload-config") {
      runMutation("/reload", {
        confirm: {
          title: "Reload configuration?",
          copy: "The serving process rereads and compiles the configured source. Invalid candidates leave the active generation unchanged.",
          acceptLabel: "Reload",
        },
        queuedMessage: () => "Reload requested. The generation advances once the new candidate compiles.",
        successMessage: () => "Reload requested.",
      });
    } else if (action === "reload-models") {
      runMutation("/models/reload", {
        queuedMessage: () => "Model catalog reload requested.",
        successMessage: () => "Model catalog reload requested.",
      });
    } else if (action === "export") {
      downloadExport()
        .then(() => notify("success", "Export downloaded."))
        .catch((error) => {
          if (error.status === 401) authRequired();
          else notify("error", esc(error.message));
        });
    }
  }

  window.addEventListener("hashchange", navigate);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") refreshCurrentView();
  });

  bindStaticChrome();
  navigate();
})();
