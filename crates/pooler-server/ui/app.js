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
    authState: "anonymous",
    authPrompted: false,
    requestGeneration: 0,
    sessionGeneration: 0,
    readController: null,
    endpointMeta: {},
    lastSuccessfulRefresh: null,
    pending: new Set(),
    connectionAccount: "",
    setup: {
      step: 1,
      provider: "",
      auth: "",
      account: "",
      model: "",
      client: "",
      configuration: "",
      testResult: null,
      busy: false,
      generation: 0,
    },
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

  async function readJson(path, signal) {
    const response = await fetch(`${BASE}${path}`, { headers: requestHeaders(), cache: "no-store", signal });
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

  async function downloadExport(sessionGeneration) {
    const response = await fetch(`${BASE}/export`, { headers: requestHeaders(), cache: "no-store" });
    if (sessionGeneration !== state.sessionGeneration) return false;
    if (!response.ok) {
      const detail = await response.json().catch(() => null);
      const error = new Error(detail && detail.error ? detail.error : `${response.status} ${response.statusText}`);
      error.status = response.status;
      throw error;
    }
    const blob = await response.blob();
    if (sessionGeneration !== state.sessionGeneration) return false;
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `pooler-management-export-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
    link.hidden = true;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    return true;
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
    if (options.id) banner.dataset.notice = options.id;
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

  function invalidateReads({ clearData = false } = {}) {
    state.requestGeneration += 1;
    state.readController?.abort();
    state.readController = null;
    state.loading = false;
    if (clearData) {
      state.data = {};
      state.errors = {};
      state.endpointMeta = {};
      state.lastSuccessfulRefresh = null;
      state.connectionAccount = "";
    }
  }

  function clearSetupResults() {
    state.setup.generation += 1;
    state.setup.configuration = "";
    state.setup.testResult = null;
    state.setup.busy = false;
  }

  function renderAuthorizationRequired() {
    const root = $("#view");
    const view = views[state.route] || views.overview;
    root.className = `view view-${state.route}`;
    root.innerHTML = `
      ${viewHeader(view.title, view.subtitle)}
      <div class="panel empty-state" role="status">
        <p class="empty-title">Authorization required</p>
        <p class="empty-description">Connect with a valid management bearer token to load this view.</p>
        <button class="btn btn-primary btn-sm" type="button" data-open-session>Open session</button>
      </div>`;
  }

  function authRequired() {
    const firstPrompt = !state.authPrompted;
    state.sessionGeneration += 1;
    state.pending.clear();
    clearSetupResults();
    invalidateReads({ clearData: true });
    state.authState = "required";
    state.authPrompted = true;
    stopPolling();
    renderAuthorizationRequired();
    updateHeader();
    if (!firstPrompt) return;
    notify("warning", `Authorization is required or the current token was rejected. <button class="btn btn-outline btn-xs" type="button" data-open-session>Open session</button>`, { sticky: true, id: "auth" });
    openSessionDialog();
  }

  /* ---------------- Dialogs ---------------- */

  function openSessionDialog() {
    const dialog = $("#session-dialog");
    const input = $("#token-input");
    const visibility = $("#token-visibility");
    input.value = state.token;
    input.type = "password";
    visibility.innerHTML = ic("eye-empty", 16);
    visibility.setAttribute("aria-label", "Show bearer token");
    visibility.title = "Show bearer token";
    if (!dialog.open) dialog.showModal();
    setTimeout(() => input.focus(), 50);
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
    if (["ok", "healthy", "succeeded", "success", "available", "not_cooling", "enabled", "accepted"].includes(s)) return "success";
    if (["cooling_down", "degraded", "stale", "queued", "pending", "warning"].includes(s)) return "warning";
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
    const head = columns.map((c) => `<th scope="col" class="${c.align === "right" ? "cell-right" : ""}">${esc(c.label)}</th>`).join("");
    const totalColumns = columns.length + (options.expandable ? 1 : 0);
    let body;
    if (options.loading) {
      body = Array.from({ length: 4 }, () =>
        `<tr class="skeleton-row">${Array.from({ length: totalColumns }, () => `<td><div class="skeleton-bar"></div></td>`).join("")}</tr>`).join("");
    } else if (options.error) {
      body = `<tr><td class="error-cell" colspan="${totalColumns}">${esc(options.error)}</td></tr>`;
    } else if (!rows || rows.length === 0) {
      body = `<tr><td colspan="${totalColumns}">
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
        const key = String(options.rowKey ? options.rowKey(row, i) : i);
        let detail = "";
        let disclosure = "";
        if (options.expandable) {
          const expanded = state.expanded.has(key);
          const detailId = `detail-${state.route}-${i}`;
          disclosure = `<button class="disclosure-button" type="button" data-expand="${esc(key)}" aria-expanded="${expanded}" aria-controls="${detailId}" aria-label="${expanded ? "Hide" : "Show"} details for ${esc(key)}">${ic("nav-arrow-down", 14)}</button>`;
          detail = `<tr class="detail-row" id="${detailId}"${expanded ? "" : " hidden"}><td colspan="${totalColumns}">${options.expandable(row)}</td></tr>`;
        }
        return `<tr>${disclosure ? `<td class="disclosure-cell">${disclosure}</td>` : ""}${cells}</tr>${detail}`;
      }).join("");
    }
    const disclosureHead = options.expandable ? `<th scope="col" class="disclosure-cell"><span class="sr-only">Details</span></th>` : "";
    const caption = options.caption || "Management data";
    return `<div class="table-wrap"><table class="data-table"><caption class="sr-only">${esc(caption)}</caption><thead><tr>${disclosureHead}${head}</tr></thead><tbody>${body}</tbody></table></div>`;
  }

  function section(title, inner, hint = "") {
    const labelledInner = inner.replace(">Management data</caption>", `>${esc(title)}</caption>`);
    return `
      <section class="section">
        <div class="toolbar">
          <h2 class="section-title">${esc(title)}</h2>
          ${hint ? `<span class="section-hint">${esc(hint)}</span>` : ""}
        </div>
        ${labelledInner}
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
    return state.errors[key] && !Object.prototype.hasOwnProperty.call(state.data, key)
      ? state.errors[key].message
      : "";
  }

  function renderEndpointState(root, keys) {
    const failed = keys.filter((key) => state.errors[key]);
    if (!failed.length) return;
    const stale = failed.filter((key) => state.endpointMeta[key]?.stale);
    const unavailable = failed.filter((key) => !state.endpointMeta[key]?.stale);
    const parts = [];
    if (stale.length) parts.push(`Showing last known data for ${stale.map((key) => ENDPOINTS[key].path).join(", ")}.`);
    if (unavailable.length) parts.push(`No data is available for ${unavailable.map((key) => ENDPOINTS[key].path).join(", ")}.`);
    const banner = document.createElement("div");
    banner.className = "banner banner-warning endpoint-state";
    banner.setAttribute("role", "status");
    const summary = failed.length === keys.length ? "Refresh failed." : "Partial refresh.";
    banner.innerHTML = `<span class="banner-icon">${ic("warning-triangle", 16)}</span><div class="banner-body"><strong>${summary}</strong> ${esc(parts.join(" "))}</div>`;
    const header = $(".view-header", root);
    if (header) header.insertAdjacentElement("afterend", banner);
    else root.prepend(banner);
  }

  /* ---------------- Data loading ---------------- */

  async function loadEndpoints(keys) {
    const generation = ++state.requestGeneration;
    if (state.readController) state.readController.abort();
    const controller = new AbortController();
    state.readController = controller;
    state.loading = true;
    updateHeader();

    let unauthorized = false;
    let successful = 0;
    await Promise.all(keys.map(async (key) => {
      const spec = ENDPOINTS[key];
      try {
        const payload = await readJson(spec.path, controller.signal);
        if (generation !== state.requestGeneration) return undefined;
        state.data[key] = payload;
        state.errors[key] = null;
        state.endpointMeta[key] = { stale: false, updatedAt: Date.now() };
        successful += 1;
      } catch (error) {
        if (error.name === "AbortError" || generation !== state.requestGeneration) return undefined;
        state.errors[key] = error;
        state.endpointMeta[key] = {
          stale: Object.prototype.hasOwnProperty.call(state.data, key),
          updatedAt: state.endpointMeta[key]?.updatedAt || null,
        };
        if (error.status === 401) unauthorized = true;
      }
      return undefined;
    }));

    if (generation !== state.requestGeneration) return false;
    state.loading = false;
    state.readController = null;
    if (unauthorized) {
      authRequired();
      return false;
    }
    if (successful > 0) state.lastSuccessfulRefresh = Date.now();
    if (state.token && successful > 0) {
      state.authState = "authenticated";
      state.authPrompted = false;
      $("[data-notice=\"auth\"]")?.remove();
    } else if (state.token) {
      state.authState = "unavailable";
    } else if (successful > 0) {
      state.authState = "anonymous";
    }
    updateHeader();
    return true;
  }

  const ENDPOINTS = {
    setupOptions: { path: "/setup/options" },
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
    reloads: { path: "/reloads" },
  };

  /* ---------------- Header ---------------- */

  function updateHeader() {
    const health = state.data.health;
    const generation = health?.configuration_generation
      ?? state.data.routes?.configuration_generation
      ?? state.data.models?.configuration_generation;
    $("#generation-badge").textContent = `gen ${text(generation)}`;
    const staleCount = (views[state.route]?.endpoints || []).filter((key) => state.errors[key]).length;
    if (state.loading) {
      $("#footer-updated").textContent = state.lastSuccessfulRefresh
        ? `Refreshing… Last data ${fmtTime(state.lastSuccessfulRefresh)}`
        : "Refreshing… No data loaded yet";
    } else if (state.lastSuccessfulRefresh) {
      $("#footer-updated").textContent = `${staleCount ? `Partial · ${staleCount} endpoint issue${staleCount === 1 ? "" : "s"} · ` : ""}Data refreshed ${fmtTime(state.lastSuccessfulRefresh)}`;
    } else {
      $("#footer-updated").textContent = "No successful refresh yet";
    }
    const sessionLabels = {
      anonymous: "Connect",
      checking: "Verifying…",
      unavailable: "Not verified",
      authenticated: "Connected",
      required: state.token ? "Token rejected" : "Connect",
    };
    $("#session-button").textContent = sessionLabels[state.authState];
    $("#session-button").dataset.authState = state.authState;
  }

  function updateThemeIcon() {
    const dark = document.documentElement.classList.contains("dark")
      || (!document.documentElement.classList.contains("light")
        && window.matchMedia("(prefers-color-scheme: dark)").matches);
    $("#theme-toggle").innerHTML = ic(dark ? "sun-light" : "half-moon", 18);
    $("#theme-toggle").setAttribute("aria-label", dark ? "Switch to light theme" : "Switch to dark theme");
    $("#theme-toggle").title = dark ? "Switch to light theme" : "Switch to dark theme";
  }

  /* ---------------- Views ---------------- */

  const views = {
    setup: {
      title: "First-run setup",
      subtitle: "Choose a provider, connect an account safely, select a model and client, then verify the active runtime.",
      endpoints: ["setupOptions", "models", "accounts", "health"],
      render: renderSetup,
    },
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
      endpoints: ["accounts", "setupOptions"],
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
      endpoints: ["health", "decisions", "traces", "audit", "reloads"],
      render: renderOperations,
    },
    diagnostics: {
      title: "Diagnostics",
      subtitle: "Redacted export and configuration state for support bundles.",
      endpoints: ["health", "catalog", "listeners", "routes"],
      render: renderDiagnostics,
    },
  };


  /* ---------------- First-run setup ---------------- */

  function setupProvider() {
    const providers = state.data.setupOptions?.providers || [];
    return providers.find((provider) => provider.id === state.setup.provider) || null;
  }

  function setupDefaults() {
    const providers = state.data.setupOptions?.providers || [];
    if (!providers.length) return;
    if (!providers.some((provider) => provider.id === state.setup.provider)) {
      const configured = providers.find((provider) => (provider.configured_upstreams || []).length);
      state.setup.provider = (configured || providers.find((provider) => provider.id === "openai") || providers[0]).id;
    }
    const provider = setupProvider();
    const methods = (provider?.authentication || []).filter((method) => method.support === "supported");
    if (!methods.some((method) => method.method === state.setup.auth)) {
      state.setup.auth = (methods.find((method) => method.method === "api_key") || methods[0] || {}).method || "";
    }
    if (!(provider?.clients || []).includes(state.setup.client)) {
      state.setup.client = (provider?.clients || ["native"])[0];
    }
    if (!state.setup.account) state.setup.account = `${state.setup.provider}-primary`;
    const configuredModels = setupModels(provider);
    if (!state.setup.model && configuredModels.length) state.setup.model = configuredModels[0].id;
  }

  function setupModels(provider = setupProvider()) {
    const upstreams = new Set(provider?.configured_upstreams || []);
    if (provider?.id) upstreams.add(provider.id);
    return (state.data.models?.models || []).filter((model) =>
      (model.targets || []).some((target) => upstreams.has(target.provider)));
  }

  function setupQuery() {
    const query = new URLSearchParams({
      provider: state.setup.provider,
      auth: state.setup.auth,
      account: state.setup.account,
      model: state.setup.model,
      client: state.setup.client,
    });
    return query.toString();
  }

  function setupReadyForStep(step) {
    if (step === 1) return Boolean(state.setup.provider);
    if (step === 2) return Boolean(state.setup.auth && /^[A-Za-z0-9_.-]{1,128}$/.test(state.setup.account));
    if (step === 3) return Boolean(state.setup.model && state.setup.model.length <= 256 && !/[\u0000-\u001F\u007F]/u.test(state.setup.model));
    if (step === 4) return Boolean(state.setup.client);
    return true;
  }

  function setupAuthInstructions(provider) {
    const method = (provider?.authentication || []).find((item) => item.method === state.setup.auth);
    if (!provider || !method) return `<p class="empty-description">Select a supported authentication method.</p>`;
    const commandMethod = state.setup.auth === "authorization_code_pkce" ? "" : ` --method ${esc(state.setup.auth.replaceAll("_", "-"))}`;
    const command = `pooler --config pooler.setup.yaml --credential-key-ref env:POOLER_STORE_KEY auth login ${esc(provider.id)} --account ${esc(state.setup.account)}${commandMethod}`;
    const environments = provider.credential_environment_variables || [];
    const secretGuidance = state.setup.auth === "api_key"
      ? `<p>Set the provider key outside the browser using one of these documented environment names: ${environments.length ? environments.map((name) => `<code class="mono">${esc(name)}</code>`).join(", ") : "no built-in environment variable is documented"}.</p>`
      : `<p>Run the command from a trusted terminal. Browser/device tokens are written only to Pooler's encrypted credential store.</p>`;
    const warning = method.support === "requires_explicit_configuration"
      ? `<div class="callout callout-warning"><strong>Explicit provider registration required.</strong> ${esc(method.note || "Supply operator-owned OAuth registration details; Pooler does not invent them.")}</div>`
      : "";
    return `${warning}${secretGuidance}<pre class="code-block"><code>${command}</code></pre><p class="muted">No credential value is accepted, retained, or placed in a URL by this dashboard.</p>`;
  }

  function setupClientInstructions() {
    const addresses = { factory: "http://127.0.0.1:18474", devin: "http://127.0.0.1:18473" };
    const base = addresses[state.setup.client] || "http://127.0.0.1:8319";
    if (["openai", "codex", "cursor", "droid"].includes(state.setup.client)) {
      return `Set the client's OpenAI-compatible base URL to <code class="mono">${base}/v1</code>. Use a non-secret local placeholder only if the client requires an API-key field; Pooler resolves the upstream credential server-side.`;
    }
    if (state.setup.client === "anthropic") return `Set the Anthropic SDK base URL to <code class="mono">${base}</code>. Pooler supplies the upstream <code class="mono">x-api-key</code> header server-side.`;
    if (state.setup.client === "gemini") return `Set the Gemini client base URL to <code class="mono">${base}</code>. Pooler supplies the upstream Google credential server-side.`;
    return `Point the selected client at <code class="mono">${base}</code>. The generated route preserves the selected provider's request dialect.`;
  }

  function renderSetup(root) {
    setupDefaults();
    const provider = setupProvider();
    const methods = (provider?.authentication || []).filter((method) => method.support === "supported");
    const unavailableMethods = (provider?.authentication || []).filter((method) => method.support !== "supported");
    const models = setupModels(provider);
    const clients = state.data.setupOptions?.clients || [];
    const compatibleClients = new Set(provider?.clients || []);
    const steps = ["Provider", "Account", "Model", "Client", "Verify"];
    const stepNav = steps.map((label, index) => {
      const number = index + 1;
      const current = number === state.setup.step;
      return `<li class="setup-step${current ? " active" : ""}${number < state.setup.step ? " complete" : ""}"${current ? ' aria-current="step"' : ""}><span>${number}</span>${esc(label)}</li>`;
    }).join("");
    let body = "";
    if (state.setup.step === 1) {
      body = `
        <fieldset class="wizard-fieldset"><legend>Choose a provider</legend>
          <label class="field"><span class="field-label">Provider</span><select id="setup-provider" data-setup-field="provider">
            ${(state.data.setupOptions?.providers || []).map((item) => `<option value="${esc(item.id)}"${item.id === state.setup.provider ? " selected" : ""}>${esc(item.name)} · ${esc(item.id)}</option>`).join("")}
          </select></label>
          ${provider ? `<div class="setup-facts"><span class="badge badge-neutral">${esc(provider.request_dialect)} dialect</span><span class="badge badge-neutral">${esc(provider.native_kind)}</span>${(provider.capabilities || []).map((capability) => `<span class="badge badge-neutral">${esc(capability)}</span>`).join("")}</div><p class="muted">${provider.discovery?.available ? "Bounded model discovery is documented for this provider." : "This provider has no catalog discovery contract; enter a documented model ID manually."}</p>` : ""}
        </fieldset>`;
    } else if (state.setup.step === 2) {
      body = `
        <fieldset class="wizard-fieldset"><legend>Connect an account</legend>
          <label class="field"><span class="field-label">Authentication method</span><select id="setup-auth" data-setup-field="auth">
            ${methods.map((method) => `<option value="${esc(method.method)}"${method.method === state.setup.auth ? " selected" : ""}>${esc(method.method.replaceAll("_", " "))} · ${esc(method.support.replaceAll("_", " "))}</option>`).join("")}
          </select></label>
          <label class="field"><span class="field-label">Account ID</span><input id="setup-account" data-setup-field="account" value="${esc(state.setup.account)}" maxlength="128" pattern="[A-Za-z0-9_.-]+" autocomplete="off" spellcheck="false"></label>
          <div class="callout">${setupAuthInstructions(provider)}</div>
          ${unavailableMethods.length ? `<div class="callout callout-warning"><strong>Methods not offered by this wizard</strong><ul class="check-list">${unavailableMethods.map((method) => `<li><span class="mono">${esc(method.method.replaceAll("_", " "))}</span> — ${esc(method.note || method.support.replaceAll("_", " "))}</li>`).join("")}</ul></div>` : ""}
        </fieldset>`;
    } else if (state.setup.step === 3) {
      body = `
        <fieldset class="wizard-fieldset"><legend>Select a model</legend>
          <label class="field"><span class="field-label">Published or documented model ID</span><input id="setup-model" data-setup-field="model" list="setup-models" value="${esc(state.setup.model)}" maxlength="256" autocomplete="off" spellcheck="false"><datalist id="setup-models">${models.map((model) => `<option value="${esc(model.id)}"></option>`).join("")}</datalist></label>
          <p class="muted">${models.length ? `${fmtInt(models.length)} active model mapping${models.length === 1 ? "" : "s"} match this provider.` : provider?.discovery?.available ? "No active model mapping matches yet. Enter a provider-documented ID; the generated configuration enables bounded discovery." : "No active model mapping matches yet. Enter a provider-documented ID; the generated configuration adds an explicit mapping."}</p>
        </fieldset>`;
    } else if (state.setup.step === 4) {
      body = `
        <fieldset class="wizard-fieldset"><legend>Choose a client</legend>
          <label class="field"><span class="field-label">Client or protocol</span><select id="setup-client" data-setup-field="client">
            ${clients.filter((client) => compatibleClients.has(client.id)).map((client) => `<option value="${esc(client.id)}"${client.id === state.setup.client ? " selected" : ""}>${esc(client.name)}</option>`).join("")}
          </select></label>
          <div class="callout">${setupClientInstructions()}</div>
        </fieldset>`;
    } else {
      const test = state.setup.testResult;
      const checks = test?.checks || [];
      body = `
        <section aria-labelledby="setup-review-title"><h2 id="setup-review-title" class="section-title">Review and verify</h2>
          <dl class="detail-grid"><div><dt>Provider</dt><dd>${esc(provider?.name || state.setup.provider)}</dd></div><div><dt>Account</dt><dd class="mono">${esc(state.setup.account)}</dd></div><div><dt>Model</dt><dd class="mono">${esc(state.setup.model)}</dd></div><div><dt>Client</dt><dd>${esc(clients.find((client) => client.id === state.setup.client)?.name || state.setup.client)}</dd></div></dl>
          <div class="callout callout-warning"><strong>Review before applying.</strong> Pooler validates this sidecar but does not overwrite your hand-written YAML. Download it, set the referenced environment secrets, then run <code class="mono">pooler check --config pooler.setup.yaml</code> and <code class="mono">pooler serve --config pooler.setup.yaml</code>.</div>
          <div class="button-row"><button class="btn btn-outline btn-sm" type="button" data-setup-action="generate"${state.setup.busy ? " disabled" : ""}>Generate configuration</button>${state.setup.configuration ? '<button class="btn btn-outline btn-sm" type="button" data-setup-action="copy">Copy YAML</button><button class="btn btn-outline btn-sm" type="button" data-setup-action="download">Download sidecar</button>' : ""}<button class="btn btn-primary btn-sm" type="button" data-setup-action="test"${state.setup.busy || !state.setup.configuration ? " disabled" : ""}>${state.setup.busy ? "Checking…" : "Test active connection"}</button>${test?.ready ? '<a class="btn btn-primary btn-sm" href="#/overview">Finish setup</a>' : ""}</div>
          ${state.setup.configuration ? `<pre class="code-block setup-config"><code>${esc(state.setup.configuration)}</code></pre>` : '<div class="empty-state"><p class="empty-title">Configuration not generated</p><p class="empty-description">Generate a compiler-validated, secret-reference-only sidecar to continue.</p></div>'}
          ${test ? `<div class="callout ${test.ready ? "callout-success" : "callout-warning"}" role="status"><strong>${test.ready ? "Connection evidence verified" : "Setup is not verified yet"}</strong><p>${test.connection === "verified" ? "A successful bounded model-discovery observation exists for this provider and account." : "No outbound catalog observation has succeeded for this provider and account. Pooler did not send a billable inference request."}</p><ul class="check-list">${checks.map((check) => `<li><span class="badge ${check.status === "passed" ? "badge-success" : "badge-neutral"}">${esc(check.status)}</span> <strong>${esc(check.id.replaceAll("_", " "))}</strong> — ${esc(check.detail)}</li>`).join("")}</ul></div>` : ""}
        </section>`;
    }
    const nextDisabled = !setupReadyForStep(state.setup.step) || state.setup.busy;
    root.innerHTML = `
      ${viewHeader("First-run setup", "No credentials are entered in or retained by this dashboard.")}
      <ol class="setup-progress" aria-label="Setup progress">${stepNav}</ol>
      <div class="panel wizard-panel">${body}<div class="wizard-actions">${state.setup.step > 1 ? `<button class="btn btn-outline" type="button" data-setup-action="back"${state.setup.busy ? " disabled" : ""}>Back</button>` : ""}${state.setup.step < 5 ? `<button class="btn btn-primary" type="button" data-setup-action="next"${nextDisabled ? " disabled" : ""}>Continue</button>` : ""}</div></div>`;
  }

  async function generateSetupConfiguration() {
    const setupGeneration = state.setup.generation;
    state.setup.busy = true;
    renderSetup($("#view"));
    const sessionGeneration = state.sessionGeneration;
    try {
      const result = await readJson(`/setup/config?${setupQuery()}`);
      if (sessionGeneration !== state.sessionGeneration || setupGeneration !== state.setup.generation) return;
      state.setup.configuration = result.configuration || "";
      state.setup.testResult = null;
    } catch (error) {
      if (sessionGeneration !== state.sessionGeneration || setupGeneration !== state.setup.generation) return;
      if (error.status === 401) authRequired();
      else notify("error", esc(error.message));
    } finally {
      if (sessionGeneration === state.sessionGeneration && setupGeneration === state.setup.generation) {
        state.setup.busy = false;
        if (state.route === "setup") renderSetup($("#view"));
      }
    }
  }

  async function waitForSetupReload(requestId, sessionGeneration) {
    for (let attempt = 0; attempt < 20; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 500));
      if (sessionGeneration !== state.sessionGeneration) return null;
      const reloads = await readJson("/reloads");
      const record = (reloads.reloads || []).find((item) => item.request_id === requestId);
      if (record && record.status !== "pending") return record;
    }
    return null;
  }

  async function runSetupConnectionTest() {
    const setupGeneration = state.setup.generation;
    state.setup.busy = true;
    state.setup.testResult = null;
    renderSetup($("#view"));
    const sessionGeneration = state.sessionGeneration;
    try {
      if (state.data.health?.management?.mutations && state.authState === "authenticated") {
        const request = await mutate("/models/reload");
        const result = await waitForSetupReload(request.request_id, sessionGeneration);
        if (result?.status === "failed") notify("warning", `Catalog refresh failed: ${esc(result.detail || "see reload history")}`);
      }
      if (sessionGeneration !== state.sessionGeneration || setupGeneration !== state.setup.generation) return;
      const testResult = await readJson(`/setup/test?${setupQuery()}`);
      if (sessionGeneration !== state.sessionGeneration || setupGeneration !== state.setup.generation) return;
      state.setup.testResult = testResult;
    } catch (error) {
      if (sessionGeneration !== state.sessionGeneration || setupGeneration !== state.setup.generation) return;
      if (error.status === 401) authRequired();
      else notify("error", esc(error.message));
    } finally {
      if (sessionGeneration === state.sessionGeneration && setupGeneration === state.setup.generation) {
        state.setup.busy = false;
        if (state.route === "setup") renderSetup($("#view"));
      }
    }
  }

  function downloadSetupConfiguration() {
    const blob = new Blob([state.setup.configuration], { type: "application/yaml;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "pooler.setup.yaml";
    link.hidden = true;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  async function setupAction(action) {
    if (action === "back") { state.setup.step = Math.max(1, state.setup.step - 1); renderSetup($("#view")); return; }
    if (action === "next") {
      if (!setupReadyForStep(state.setup.step)) return;
      state.setup.step = Math.min(5, state.setup.step + 1);
      renderSetup($("#view"));
      if (state.setup.step === 5 && !state.setup.configuration) await generateSetupConfiguration();
      return;
    }
    if (action === "generate") await generateSetupConfiguration();
    else if (action === "test") await runSetupConnectionTest();
    else if (action === "copy") {
      try { await navigator.clipboard.writeText(state.setup.configuration); notify("success", "Configuration copied."); }
      catch { notify("warning", "Clipboard access was unavailable. Select the YAML manually."); }
    } else if (action === "download") downloadSetupConfiguration();
  }

  function updateSetupField(field, value) {
    if (!Object.prototype.hasOwnProperty.call(state.setup, field)) return;
    const changed = state.setup[field] !== value;
    state.setup[field] = value;
    if (!changed) return;
    state.setup.generation += 1;
    state.setup.busy = false;
    state.setup.configuration = "";
    state.setup.testResult = null;
    if (field === "provider") {
      state.setup.auth = "";
      state.setup.client = "";
      state.setup.account = `${value}-primary`;
      state.setup.model = "";
      setupDefaults();
    }
  }


  function renderOverview(root) {
    const health = state.data.health || {};
    const providers = state.data.providers?.providers || [];
    const accounts = state.data.accounts?.accounts || [];
    const quota = state.data.quota || {};
    const models = state.data.models?.models || [];
    const listeners = state.data.listeners?.listeners || [];
    const routes = state.data.routes?.routes || [];
    const active = state.data.active || {};

    const availableProviders = providers.filter((p) => p.status === "not_cooling" || p.status === "available").length;
    const enabledAccounts = accounts.filter((a) => a.enabled).length;
    const cooldowns = quota.cooldowns || [];
    const windows = quota.windows || [];

    const stats = [
      statCard("Status", statusBadge(health.status || (endpointError("health") ? "error" : "unknown")),
        endpointError("health") ? esc(endpointError("health")) : `${fmtInt(health.credential_health_entries)} health entries`),
      statCard("Active requests", `<span class="num">${fmtInt(active.active ?? health.active)}</span>`, "Across all listeners"),
      statCard("Providers", `<span class="num">${fmtInt(availableProviders)}<span class="muted">/${fmtInt(providers.length)}</span></span>`, "Not cooling down; connectivity is not probed"),
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
    const mutationCapable = payload.mutation_capable === true && !state.errors.models;
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
          `<div class="inline-meta target-row">${providerCell(t.provider)}<span class="muted">→</span><span class="mono">${esc(text(t.upstream_model))}</span></div>`).join("") || "—" },
      { label: "Capabilities", nowrap: false, render: (m) => {
          const caps = [...new Set((m.targets || []).flatMap((t) => t.capabilities || []))];
          return caps.length ? caps.map((c) => `<span class="chip">${esc(c)}</span>`).join(" ") : "—";
        } },
      { label: "Exposure", render: (m) => enabledBadge(m.enabled !== false) },
      { label: "Actions", render: (m) => {
          if (!mutationCapable) return `<span class="muted">Unavailable</span>`;
          const enabled = m.enabled !== false;
          const action = enabled ? "disable" : "enable";
          const path = `/models/${modelPath(m.id)}/${action}`;
          const pending = state.pending.has(path);
          return `<div class="row-actions">
            <button class="btn btn-subtle btn-xs" type="button" data-model-action="${action}" data-model-id="${esc(m.id)}" title="${enabled ? "Disable" : "Enable"} ${esc(m.id)}"${pending ? ` disabled aria-busy="true"` : ""}>
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
        ${disabledOverrides.length ? `<p class="section-hint spaced-top-sm">Disabled by override</p><div class="inline-meta">${disabledOverrides.map((m) => `<span class="chip mono">${esc(m)}</span>`).join("")}</div>` : ""}
        ${unmatchedOverrides.length ? `<p class="section-hint spaced-top-sm">Unmatched overrides</p><div class="inline-meta">${unmatchedOverrides.map((m) => `<span class="chip mono">${esc(m)}</span>`).join("")}</div>` : ""}
      </div>` : "";

    root.innerHTML = `
      ${viewHeader("Models", views.models.subtitle, `
        <input id="model-filter" class="filter-input" type="search" placeholder="Filter models" value="${esc(state.filter)}" aria-label="Filter models">
        ${mutationCapable ? `<button class="btn btn-outline btn-sm" type="button" data-action="reload-models" title="Refresh configured catalog sources"${state.pending.has("/models/reload") ? ` disabled aria-busy="true"` : ""}>${ic("refresh-double", 15)} Reload catalog</button>` : `<span class="section-hint">Authenticated mutations are unavailable.</span>`}`)}
      <section class="grid-stats grid-stats-4">${stats}</section>
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

  function accountIsSelected(account) {
    return account.selected === true || account.is_selected === true;
  }

  function accountSupports(account, action) {
    if (state.errors.accounts) return false;
    const explicit = account.available_actions ?? account.capabilities ?? account.actions ?? account.supported_actions;
    if (Array.isArray(explicit)) return explicit.includes(action);
    if (explicit && typeof explicit === "object" && Object.prototype.hasOwnProperty.call(explicit, action)) return Boolean(explicit[action]);
    for (const key of [`can_${action}`, `supports_${action}`]) {
      if (Object.prototype.hasOwnProperty.call(account, key)) return Boolean(account[key]);
    }
    if (action === "refresh" || action === "revoke") return String(account.auth_kind || account.authentication || "").toLowerCase() === "oauth";
    return true;
  }

  function accountActionButton(account, action, label, icon, title) {
    const supported = accountSupports(account, action);
    const selected = action === "switch" && accountIsSelected(account);
    if (!supported || selected) return "";
    const path = `/accounts/${encodeURIComponent(account.id)}/${action}`;
    const pending = state.pending.has(path);
    return `<button class="btn btn-subtle btn-xs" type="button" data-account-action="${action}" data-account-id="${esc(account.id)}" data-account-provider="${esc(account.provider)}" title="${esc(title || label)}"${pending ? ` disabled aria-busy="true"` : ""}>${ic(icon, 13)} ${esc(label)}</button>`;
  }

  function shellArg(value) {
    const raw = String(value);
    return /^[A-Za-z0-9_./:@-]+$/u.test(raw) ? raw : `'${raw.replaceAll("'", "'\\''")}'`;
  }

  function accountProviderProfile(account) {
    return (state.data.setupOptions?.providers || []).find((provider) =>
      provider.id === account.provider || (provider.configured_upstreams || []).includes(account.provider)) || null;
  }

  function accountConnectionGuide(account) {
    if (!account) return "";
    const provider = accountProviderProfile(account);
    const expectedMethod = account.auth_kind === "oauth" ? new Set(["authorization_code_pkce", "device_code"]) : new Set(["api_key"]);
    const methods = (provider?.authentication || []).filter((method) => expectedMethod.has(method.method) && method.support === "supported");
    const unavailable = (provider?.authentication || []).filter((method) => expectedMethod.has(method.method) && method.support !== "supported");
    const commands = methods.map((method) => {
      const methodName = { authorization_code_pkce: "oauth", device_code: "device-code", api_key: "api-key" }[method.method];
      const args = ["pooler", "--credential-key-ref", "env:POOLER_STORE_KEY", "auth", "login", account.id];
      if (provider?.id) args.push("--profile", provider.id);
      args.push("--method", methodName);
      return `<div><strong>${esc(method.method.replaceAll("_", " "))}</strong><pre class="code-block"><code>${esc(args.map(shellArg).join(" "))}</code></pre><p class="muted">${esc(method.note)}</p></div>`;
    }).join("");
    const environments = provider?.credential_environment_variables || [];
    const keyInstructions = account.auth_kind === "api_key"
      ? `<p>Set the provider key outside this browser using ${environments.length ? environments.map((name) => `<code class="mono">${esc(name)}</code>`).join(" or ") : "the protected secret reference already declared in configuration"}. The API-key command prints provider-safe guidance and never accepts the key as an argument.</p>`
      : `<p>OAuth runs in a trusted terminal and writes tokens only to Pooler's encrypted credential store. The dashboard never receives the authorization code, refresh token, client secret, or access token.</p>`;
    return `<section class="panel connection-panel" aria-labelledby="connection-title">
      <div class="toolbar"><h2 class="section-title" id="connection-title" tabindex="-1">Connect ${esc(account.id)}</h2><span class="spacer"></span><button class="btn btn-ghost btn-sm" type="button" data-account-connect-close>Close</button></div>
      ${keyInstructions}
      ${commands || '<div class="callout callout-warning"><strong>No safe built-in connection command is available.</strong> Keep using the protected secret or OAuth registration already declared by the operator.</div>'}
      ${unavailable.length ? `<div class="callout callout-warning"><strong>Not offered</strong><ul class="check-list">${unavailable.map((method) => `<li><span class="mono">${esc(method.method.replaceAll("_", " "))}</span> — ${esc(method.note)}</li>`).join("")}</ul></div>` : ""}
      ${provider?.documentation_url ? `<p><a class="text-link" href="${esc(provider.documentation_url)}" target="_blank" rel="noreferrer">Open provider authentication documentation</a></p>` : ""}
      <div class="button-row"><button class="btn btn-primary btn-sm" type="button" data-account-connect-check>Check redacted account status</button></div>
      <p class="muted">Current local state: ${statusBadge(account.status)}. An available credential is not a provider connectivity probe.</p>
    </section>`;
  }

  function renderAccounts(root) {
    const accounts = state.data.accounts?.accounts || [];

    const selectable = accounts.filter((a) => a.enabled && a.status === "available").length;
    const cooling = accounts.filter((a) => a.status === "cooling_down").length;

    const stats = [
      statCard("Accounts", `<span class="num">${fmtInt(accounts.length)}</span>`, "Configured accounts"),
      statCard("Selectable", `<span class="num">${fmtInt(selectable)}</span>`, "Enabled and not cooling down"),
      statCard("Cooling down", `<span class="num">${fmtInt(cooling)}</span>`, "Temporarily excluded"),
      statCard("Enabled", `<span class="num">${fmtInt(accounts.filter((a) => a.enabled).length)}</span>`, "Operator-enabled"),
    ].join("");

    const accountTable = tableWrap([
      { label: "ID", mono: true, nowrap: false, render: (a) => `<div class="cell-ellipsis" title="${esc(a.id)}">${esc(a.id)}</div>` },
      { label: "Provider", mono: true, render: (a) => providerCell(a.provider) },
      { label: "Selected", render: (a) => accountIsSelected(a) ? statusBadge("selected", "accent") : `<span class="muted">—</span>` },
      { label: "Enabled", render: (a) => enabledBadge(a.enabled) },
      { label: "Status", render: (a) => statusBadge(a.status) },
      { label: "Failures", align: "right", render: (a) => `<span class="num">${fmtInt(a.failure_count)}</span>` },
      { label: "Cooldown", render: (a) => a.cooldown_until
          ? `<span class="num" title="${esc(fmtTime(a.cooldown_until))}">${esc(relTime(a.cooldown_until))}</span>`
          : `<span class="muted">—</span>` },
      { label: "Actions", nowrap: false, render: (a) => {
          const enableAction = a.enabled ? "disable" : "enable";
          return `<div class="row-actions">
            <button class="btn btn-subtle btn-xs" type="button" data-account-connect="${esc(a.id)}">${ic("key-alt", 13)} Connect</button>
            ${accountActionButton(a, "switch", "Switch", "switch-on", "Select this account and disable its same-provider siblings")}
            ${accountActionButton(a, enableAction, a.enabled ? "Disable" : "Enable", a.enabled ? "pause" : "play")}
            ${accountActionButton(a, "refresh", "Refresh", "refresh-double", "Queue an OAuth token refresh")}
            ${accountActionButton(a, "revoke", "Revoke", "trash", "Remove Pooler's local credential and disable the account")}
          </div>`;
        } },
    ], accounts, {
      loading: state.loading && !state.data.accounts,
      error: endpointError("accounts"),
      emptyTitle: "No accounts configured",
      emptyDescription: "Accounts are declared in configuration and authenticated on the server.",
    });

    const connectionAccount = accounts.find((account) => account.id === state.connectionAccount);

    root.innerHTML = `
      ${viewHeader("Accounts", views.accounts.subtitle)}
      <section class="grid-stats grid-stats-4">${stats}</section>
      ${section("Accounts", accountTable, "Switch enables the account and disables its same-provider siblings atomically.")}
      ${accountConnectionGuide(connectionAccount)}
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
    const health = state.data.health || {};
    const decisions = state.data.decisions?.decisions || [];
    const traces = state.data.traces?.traces || [];
    const audit = state.data.audit?.events || [];
    const reloads = state.data.reloads?.reloads || [];
    const mutationCapable = health.management?.mutations === true && !state.errors.health;
    const droppedTraces = state.data.traces?.dropped || 0;

    const runtimeControls = mutationCapable ? `
      <button class="btn btn-outline btn-sm" type="button" data-action="reload-config" title="Reread and compile the configured source"${state.pending.has("/reload") ? ` disabled aria-busy="true"` : ""}>${ic("refresh", 15)} Reload configuration</button>
      <button class="btn btn-outline btn-sm" type="button" data-action="reload-models" title="Refresh configured catalog sources"${state.pending.has("/models/reload") ? ` disabled aria-busy="true"` : ""}>${ic("refresh-double", 15)} Reload model catalog</button>`
      : `<span class="section-hint">Authenticated mutations are unavailable.</span>`;

    const actionsPanel = `
      <div class="panel">
        <div class="toolbar">
          <h2 class="section-title">Runtime controls</h2>
          <span class="spacer"></span>
          ${runtimeControls}
        </div>
        <p class="section-hint spaced-top-sm">
          Reload asks the serving process to reread and compile the configured source. Invalid candidates leave the active generation unchanged. Listener and management binding changes require a restart.
        </p>
      </div>`;

    const reloadTable = tableWrap([
      { label: "Request", mono: true, render: (r) => esc(text(r.request_id)) },
      { label: "Kind", render: (r) => `<span class="badge badge-neutral">${esc(text(r.kind))}</span>` },
      { label: "Status", render: (r) => statusBadge(r.status) },
      { label: "Requested", render: (r) => `<span class="num muted" title="${esc(fmtTime(r.requested_at_ms))}">${esc(relTime(r.requested_at_ms))}</span>` },
      { label: "Completed", render: (r) => r.completed_at_ms ? `<span class="num muted" title="${esc(fmtTime(r.completed_at_ms))}">${esc(relTime(r.completed_at_ms))}</span>` : `<span class="muted">—</span>` },
      { label: "Accepted generation", align: "right", render: (r) => `<span class="num">${fmtInt(r.accepted_configuration_generation ?? r.configuration_generation)}</span>` },
      { label: "Result generation", align: "right", render: (r) => `<span class="num">${fmtInt(r.configuration_generation)}</span>` },
      { label: "Catalog generation", align: "right", render: (r) => `<span class="num">${fmtInt(r.catalog_generation)}</span>` },
    ], [...reloads].reverse(), {
      loading: state.loading && !state.data.reloads,
      error: endpointError("reloads"),
      emptyTitle: "No reload requests yet",
      emptyDescription: "Accepted configuration and catalog reloads appear here with their final outcome.",
    });

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
        <div class="detail-content">
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
      ${section("Reload history", reloadTable, "Bounded process-local status for accepted reload requests; newest first.")}
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
        <p class="section-hint spaced-top-sm">
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
        <dl class="kv-list spaced-top-md">
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
        <p class="section-hint spaced-top-xs">Errors observed by this dashboard in the current session, including unavailable state stores and rejected reloads.</p>
        <div class="spaced-top-md">
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

  async function runMutation(path, { confirm, successMessage, queuedMessage }, trigger) {
    if (state.pending.has(path)) return;
    const sessionGeneration = state.sessionGeneration;
    state.pending.add(path);
    if (trigger) {
      trigger.disabled = true;
      trigger.setAttribute("aria-busy", "true");
    }
    let changed = false;
    try {
      if (confirm) {
        const accepted = await confirmAction(confirm);
        if (!accepted || sessionGeneration !== state.sessionGeneration) return;
      }
      const result = await mutate(path);
      if (sessionGeneration !== state.sessionGeneration) return;
      changed = true;
      if ((result.status === "queued" || result.status === "pending") && queuedMessage) {
        notify("info", queuedMessage(result));
      } else {
        notify("success", successMessage ? successMessage(result) : "Done.");
      }
    } catch (error) {
      if (sessionGeneration !== state.sessionGeneration) return;
      if (error.status === 401) {
        authRequired();
      } else {
        notify("error", esc(error.message));
      }
    } finally {
      if (sessionGeneration === state.sessionGeneration) {
        state.pending.delete(path);
        if (trigger?.isConnected) {
          trigger.disabled = false;
          trigger.removeAttribute("aria-busy");
        }
      }
    }
    if (changed && sessionGeneration === state.sessionGeneration) await refreshCurrentView();
  }

  function accountAction(accountId, action, provider, trigger) {
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
      }, trigger);
    }
    if (action === "refresh") {
      return runMutation(path, {
        queuedMessage: () => `Refresh queued for ${esc(accountId)}. The result lands in the audit log under Operations.`,
        successMessage: () => `Refresh requested for ${esc(accountId)}.`,
      }, trigger);
    }
    if (action === "switch") {
      return runMutation(path, {
        confirm: {
          title: `Switch selected account to ${accountId}?`,
          copy: `Select <span class="mono">${esc(accountId)}</span>${provider ? ` for <span class="mono">${esc(provider)}</span>` : ""} and disable its same-provider siblings?`,
          acceptLabel: "Switch account",
        },
        successMessage: () => `Switched to ${esc(accountId)}; same-provider siblings were disabled.`,
      }, trigger);
    }
    return runMutation(path, { successMessage: () => `${label}d ${esc(accountId)}.` }, trigger);
  }

  function modelAction(modelId, action, trigger) {
    const path = `/models/${modelPath(modelId)}/${action}`;
    return runMutation(path, {
      successMessage: () => `${action === "enable" ? "Enabled" : "Disabled"} ${esc(modelId)}.`,
    }, trigger);
  }

  /* ---------------- Router and polling ---------------- */

  function currentRoute() {
    const hash = window.location.hash.replace(/^#\/?/, "").split("?")[0];
    return views[hash] ? hash : "overview";
  }

  function hasFocusedInteractiveView() {
    if ($("dialog[open]")) return true;
    const root = $("#view");
    const active = document.activeElement;
    return Boolean(active && root.contains(active) && active.matches("a, button, input, select, textarea, summary, [tabindex]:not([tabindex='-1'])"));
  }

  async function refreshCurrentView({ polling = false } = {}) {
    if (polling && hasFocusedInteractiveView()) return false;
    const route = state.route;
    const view = views[route];
    const loaded = await loadEndpoints(view.endpoints);
    if (!loaded || route !== state.route) return false;
    const root = $("#view");
    if (polling && hasFocusedInteractiveView()) return false;
    root.className = `view view-${route}`;
    view.render(root);
    renderEndpointState(root, view.endpoints);
    return true;
  }

  function stopPolling() {
    if (state.pollTimer) {
      clearInterval(state.pollTimer);
      state.pollTimer = null;
    }
  }

  function startPolling() {
    stopPolling();
    if (state.authState === "required") return;
    state.pollTimer = setInterval(() => {
      if (document.visibilityState === "visible" && state.authState !== "required") {
        refreshCurrentView({ polling: true });
      }
    }, POLL_MS);
  }

  async function navigate() {
    state.route = currentRoute();
    state.filter = "";
    state.expanded.clear();
    document.querySelectorAll(".nav-link").forEach((link) => {
      const active = link.dataset.route === state.route;
      link.classList.toggle("active", active);
      if (active) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    });
    const view = views[state.route];
    $("#view").className = `view view-${state.route}`;
    $("#view").innerHTML = `
      ${viewHeader(view.title, view.subtitle)}
      <div class="table-wrap"><table class="data-table"><caption class="sr-only">Loading ${esc(view.title)}</caption><tbody>
        ${Array.from({ length: 5 }, () => `<tr class="skeleton-row"><td><div class="skeleton-bar"></div></td><td><div class="skeleton-bar"></div></td><td><div class="skeleton-bar"></div></td></tr>`).join("")}
      </tbody></table></div>`;
    const loaded = await refreshCurrentView();
    if (loaded) startPolling();
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
    $("#token-visibility").title = "Show bearer token";

    $(".skip-link").addEventListener("click", (event) => {
      event.preventDefault();
      requestAnimationFrame(() => $("#main").focus());
    });

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
      state.sessionGeneration += 1;
      state.pending.clear();
      clearSetupResults();
      invalidateReads({ clearData: true });
      state.token = $("#token-input").value.trim();
      state.authState = state.token ? "checking" : "anonymous";
      state.authPrompted = false;
      $("[data-notice=\"auth\"]")?.remove();
      $("#session-dialog").close();
      updateHeader();
      refreshCurrentView().then((loaded) => { if (loaded) startPolling(); });
    });
    $("#token-input").addEventListener("keydown", (event) => {
      if (event.key === "Enter") $("#token-apply").click();
    });
    $("#token-clear").addEventListener("click", () => {
      state.sessionGeneration += 1;
      state.pending.clear();
      clearSetupResults();
      invalidateReads({ clearData: true });
      state.token = "";
      state.authState = "anonymous";
      state.authPrompted = false;
      $("#token-input").value = "";
      $("[data-notice=\"auth\"]")?.remove();
      $("#session-dialog").close();
      updateHeader();
      refreshCurrentView().then((loaded) => { if (loaded) startPolling(); });
    });
    $("#token-visibility").addEventListener("click", () => {
      const input = $("#token-input");
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      $("#token-visibility").innerHTML = ic(show ? "eye-off" : "eye-empty", 16);
      $("#token-visibility").setAttribute("aria-label", show ? "Hide bearer token" : "Show bearer token");
      $("#token-visibility").title = show ? "Hide bearer token" : "Show bearer token";
      input.focus();
    });

    $("#view").addEventListener("click", (event) => {
      const openSession = event.target.closest("[data-open-session]");
      if (openSession) { openSessionDialog(); return; }

      const setupButton = event.target.closest("[data-setup-action]");
      if (setupButton) { setupAction(setupButton.dataset.setupAction); return; }

      const connectionButton = event.target.closest("[data-account-connect]");
      if (connectionButton) {
        state.connectionAccount = connectionButton.dataset.accountConnect;
        renderAccounts($("#view"));
        $("#connection-title")?.focus();
        return;
      }
      if (event.target.closest("[data-account-connect-close]")) {
        state.connectionAccount = "";
        renderAccounts($("#view"));
        return;
      }
      if (event.target.closest("[data-account-connect-check]")) {
        refreshCurrentView();
        return;
      }

      const accountButton = event.target.closest("[data-account-action]");
      if (accountButton) {
        accountAction(accountButton.dataset.accountId, accountButton.dataset.accountAction, accountButton.dataset.accountProvider, accountButton);
        return;
      }
      const modelButton = event.target.closest("[data-model-action]");
      if (modelButton) {
        modelAction(modelButton.dataset.modelId, modelButton.dataset.modelAction, modelButton);
        return;
      }
      const actionButton = event.target.closest("[data-action]");
      if (actionButton) {
        handleViewAction(actionButton.dataset.action, actionButton);
        return;
      }
      const expandRow = event.target.closest("[data-expand]");
      if (expandRow) {
        const key = expandRow.dataset.expand;
        if (state.expanded.has(key)) state.expanded.delete(key);
        else state.expanded.add(key);
        const root = $("#view");
        const view = views[state.route];
        view.render(root);
        renderEndpointState(root, view.endpoints);
        const replacement = Array.from(root.querySelectorAll("[data-expand]")).find((button) => button.dataset.expand === key);
        replacement?.focus();
      }
    });

    $("#view").addEventListener("input", (event) => {
      const field = event.target.closest("[data-setup-field]");
      if (!field || state.route !== "setup") return;
      updateSetupField(field.dataset.setupField, field.value);
      const next = $("[data-setup-action=\"next\"]", $("#view"));
      if (next) next.disabled = !setupReadyForStep(state.setup.step);
    });
    $("#view").addEventListener("change", (event) => {
      const field = event.target.closest("[data-setup-field]");
      if (!field || state.route !== "setup" || field.tagName !== "SELECT") return;
      updateSetupField(field.dataset.setupField, field.value);
      renderSetup($("#view"));
      $(`#setup-${field.dataset.setupField}`)?.focus();
    });

    $("#banner-area").addEventListener("click", (event) => {
      if (event.target.closest("[data-open-session]")) openSessionDialog();
    });
  }

  function handleViewAction(action, trigger) {
    if (action === "reload-config") {
      runMutation("/reload", {
        confirm: {
          title: "Reload configuration?",
          copy: "The serving process rereads and compiles the configured source. Invalid candidates leave the active generation unchanged.",
          acceptLabel: "Reload",
        },
        queuedMessage: (result) => `Reload request ${esc(result.request_id)} accepted. Follow its final outcome in Reload history.`,
        successMessage: () => "Reload requested.",
      }, trigger);
    } else if (action === "reload-models") {
      runMutation("/models/reload", {
        queuedMessage: (result) => `Catalog refresh request ${esc(result.request_id)} accepted. Follow its final outcome in Reload history.`,
      }, trigger);
    } else if (action === "export") {
      const path = "/export";
      if (state.pending.has(path)) return;
      state.pending.add(path);
      trigger.disabled = true;
      trigger.setAttribute("aria-busy", "true");
      const sessionGeneration = state.sessionGeneration;
      downloadExport(sessionGeneration)
        .then((downloaded) => {
          if (downloaded && sessionGeneration === state.sessionGeneration) notify("success", "Export downloaded.");
        })
        .catch((error) => {
          if (sessionGeneration !== state.sessionGeneration) return;
          if (error.status === 401) authRequired();
          else notify("error", esc(error.message));
        })
        .finally(() => {
          if (sessionGeneration !== state.sessionGeneration) return;
          state.pending.delete(path);
          if (trigger.isConnected) {
            trigger.disabled = false;
            trigger.removeAttribute("aria-busy");
          }
        });
    }
  }

  window.addEventListener("hashchange", navigate);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible" && state.authState !== "required") {
      refreshCurrentView({ polling: true });
    }
  });

  bindStaticChrome();
  navigate();
})();
