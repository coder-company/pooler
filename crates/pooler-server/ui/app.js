/*
 * Pooler management dashboard.
 *
 * Reads the redacted management JSON endpoints exposed by the pooler-server
 * management listener. The bearer token is held in memory only: it is never
 * persisted, never put in a URL, and only sent as the Authorization header
 * to this same listener. Operational controls are body-free POSTs; typed
 * configuration edits use bounded JSON bodies with ETag preconditions.
 */
(() => {
  const BASE = "/management";
  const POLL_MS = 10_000;
  let controlMutationQueue = Promise.resolve();

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
    modelsProvider: "",
    authState: "anonymous",
    authPrompted: false,
    requestGeneration: 0,
    sessionGeneration: 0,
    readController: null,
    endpointMeta: {},
    lastSuccessfulRefresh: null,
    pending: new Set(),
    controlDraft: {
      id: null,
      etag: "",
      baseGeneration: null,
      dirty: false,
      busy: false,
      conflict: false,
      confirmationToken: "",
    },
    providerDraft: {
      id: "",
      name: "",
      origin: "",
      clientId: "",
      protocol: "openai",
      modelIds: "",
      template: "openai",
      visible: false,
      busy: false,
    },
    accountDraft: {
      id: "",
      provider: "",
      authKind: "api_key",
      secret: "",
      busy: false,
    },
    poolDraft: {
      id: "",
      provider: "",
      accounts: [],
      strategy: "ordered_fallback",
      busy: false,
    },
    onboarding: {
      provider: "",
      providerDetails: null,
      account: "",
      phase: "provider",
      discoveryBusy: false,
      selectedModels: new Set(),
      modelsInitialized: false,
    },
    oauthCapabilities: {},
    oauthCapabilityRequests: {},
    oauthFlow: {
      account: "",
      requestId: null,
      method: "",
      status: "",
      authorizationUrl: "",
      verificationUri: "",
      verificationUriComplete: "",
      userCode: "",
      expiresAt: 0,
      busy: false,
    },
    targetOrders: {},
    targetFocus: "",
    targetAnnouncement: "",
    targetDrag: null,
    policyEditor: {
      id: "",
      strategy: "ordered_fallback",
      ranking: "deterministic",
      allow: "",
      deny: "",
      allowFallbacks: true,
      requiredParameters: "",
      requiredCapabilities: "",
      minimumContext: "",
      quantization: "",
      privacy: "",
      requireZdr: false,
      dataPolicy: "",
      maxPrice: "",
      price: false,
      latency: false,
      throughput: false,
      maxLatency: "",
      minThroughput: "",
      minSamples: "",
      staleAfter: "",
      dirty: false,
      busy: false,
    },
    connectionAccount: "",
    usageRange: "24h",
    requestExplorer: {
      route: "",
      provider: "",
      status: "",
      timeline: {},
      busy: false,
    },
    configuration: {
      draftId: null,
      etag: "",
      operation: "upsert",
      section: "models",
      id: "",
      value: '{\n  "id": ""\n}',
      diff: [],
      confirmationToken: "",
      busy: false,
    },
  };

  /* ---------------- Small helpers ---------------- */

  const $ = (selector, root) => (root || document).querySelector(selector);

  function esc(value) {
    return String(value ?? "").replace(
      /[&<>"']/g,
      (ch) =>
        ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;",
        })[ch],
    );
  }

  function text(value) {
    return value === null || value === undefined || value === ""
      ? "—"
      : String(value);
  }

  function fmtInt(value) {
    if (value === null || value === undefined || Number.isNaN(Number(value)))
      return "—";
    return Number(value).toLocaleString("en-US");
  }

  function fmtCompact(value) {
    if (value === null || value === undefined || Number.isNaN(Number(value)))
      return "—";
    return new Intl.NumberFormat("en-US", {
      notation: "compact",
      maximumFractionDigits: 1,
    }).format(Number(value));
  }

  function pad2(n) {
    return String(n).padStart(2, "0");
  }

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

  function apiErrorMessage(detail, response) {
    const payload = detail?.error;
    if (typeof payload === "string" && payload.trim()) return payload;
    if (payload && typeof payload === "object") {
      if (typeof payload.message === "string" && payload.message.trim()) return payload.message;
      if (typeof payload.code === "string" && payload.code.trim()) return payload.code.replaceAll("_", " ");
    }
    if (typeof detail?.message === "string" && detail.message.trim()) return detail.message;
    return `${response.status} ${response.statusText}`.trim();
  }

  function responseError(detail, response) {
    const error = new Error(apiErrorMessage(detail, response));
    error.status = response.status;
    error.code = detail?.error?.code || null;
    return error;
  }

  async function readJson(path, signal) {
    const response = await fetch(`${BASE}${path}`, {
      headers: requestHeaders(),
      cache: "no-store",
      signal,
    });
    if (!response.ok) {
      const detail = await response.json().catch(() => null);
      throw responseError(detail, response);
    }
    return response.json();
  }

  async function mutate(path) {
    const response = await fetch(`${BASE}${path}`, {
      method: "POST",
      headers: requestHeaders(),
      cache: "no-store",
    });
    const detail = await response.json().catch(() => null);
    if (!response.ok) {
      throw responseError(detail, response);
    }
    return detail || {};
  }

  async function mutateJson(path, method, body, etag = "") {
    const headers = { ...requestHeaders() };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (etag) headers["If-Match"] = etag;
    const response = await fetch(`${BASE}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store",
    });
    const detail = await response.json().catch(() => null);
    if (!response.ok) {
      throw responseError(detail, response);
    }
    return detail || {};
  }

  async function downloadExport(
    sessionGeneration,
    path = "/export",
    filenamePrefix = "pooler-management-export",
  ) {
    const response = await fetch(`${BASE}${path}`, {
      headers: requestHeaders(),
      cache: "no-store",
    });
    if (sessionGeneration !== state.sessionGeneration) return false;
    if (!response.ok) {
      const detail = await response.json().catch(() => null);
      throw responseError(detail, response);
    }
    const blob = await response.blob();
    if (sessionGeneration !== state.sessionGeneration) return false;
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${filenamePrefix}-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
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
    const iconName =
      {
        success: "check-circle",
        error: "cancel",
        warning: "warning-triangle",
        info: "info-empty",
      }[kind] || "info-empty";
    const icon = document.createElement("span");
    icon.className = "banner-icon";
    icon.innerHTML = ic(iconName, 16);
    const body = document.createElement("div");
    body.className = "banner-body";
    body.append(document.createTextNode(String(message ?? "")));
    if (options.action) {
      const action = document.createElement("button");
      action.className = "btn btn-outline btn-xs";
      action.type = "button";
      action.dataset.openSession = "";
      action.textContent = options.action.label;
      body.append(" ", action);
    }
    const dismiss = document.createElement("button");
    dismiss.className = "banner-dismiss";
    dismiss.type = "button";
    dismiss.setAttribute("aria-label", "Dismiss");
    dismiss.innerHTML = ic("cancel", 14);
    banner.append(icon, body, dismiss);
    dismiss.addEventListener("click", () =>
      banner.remove(),
    );
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
      state.controlDraft = {
        id: null,
        etag: "",
        baseGeneration: null,
        dirty: false,
        busy: false,
        conflict: false,
      };
      state.oauthCapabilities = {};
      state.oauthCapabilityRequests = {};
      state.targetOrders = {};
      state.targetFocus = "";
      state.targetAnnouncement = "";
      state.targetDrag = null;
      state.policyEditor.dirty = false;
      controlMutationQueue = Promise.resolve();
      state.oauthFlow = {
        account: "",
        requestId: null,
        method: "",
        status: "",
        authorizationUrl: "",
        verificationUri: "",
        verificationUriComplete: "",
        userCode: "",
        expiresAt: 0,
        busy: false,
      };
      state.accountDraft.busy = false;
      state.requestExplorer.route = "";
      state.requestExplorer.provider = "";
      state.requestExplorer.status = "";
      state.requestExplorer.timeline = {};
      state.requestExplorer.busy = false;
    }
  }

  function clearConfigurationDraft() {
    state.configuration.draftId = null;
    state.configuration.etag = "";
    state.configuration.diff = [];
    state.configuration.confirmationToken = "";
    state.configuration.busy = false;
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
    clearConfigurationDraft();
    invalidateReads({ clearData: true });
    state.authState = "required";
    state.authPrompted = true;
    stopPolling();
    renderAuthorizationRequired();
    updateHeader();
    if (!firstPrompt) return;
    notify(
      "warning",
      "Authorization is required or the current token was rejected.",
      {
        sticky: true,
        id: "auth",
        action: { label: "Open session" },
      },
    );
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
    visibility.setAttribute("aria-label", "Show management key");
    visibility.title = "Show management key";
    if (!dialog.open) dialog.showModal();
    setTimeout(() => input.focus(), 50);
  }

  function confirmAction({
    title,
    copy,
    acceptLabel = "Confirm",
    destructive = false,
  }) {
    return new Promise((resolve) => {
      const dialog = $("#confirm-dialog");
      $("#confirm-title").textContent = title;
      $("#confirm-copy").innerHTML = copy;
      const accept = $("#confirm-accept");
      accept.textContent = acceptLabel;
      accept.className = destructive
        ? "btn btn-destructive"
        : "btn btn-primary";
      const settle = (value) => {
        dialog.removeEventListener("close", onClose);
        resolve(value);
      };
      const onClose = () => settle(false);
      dialog.addEventListener("close", onClose);
      $("#confirm-accept").onclick = () => {
        dialog.close();
        settle(true);
      };
      $("#confirm-cancel").onclick = () => {
        dialog.close();
        settle(false);
      };
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

  const TONE_BADGE = {
    success: "badge-success",
    warning: "badge-warning",
    error: "badge-error",
    accent: "badge-accent",
    muted: "badge-neutral",
  };

  function toneForStatus(status) {
    const s = String(status ?? "").toLowerCase();
    if (
      [
        "ok",
        "healthy",
        "succeeded",
        "success",
        "available",
        "not_cooling",
        "enabled",
        "accepted",
      ].includes(s)
    )
      return "success";
    if (
      [
        "cooling_down",
        "degraded",
        "stale",
        "queued",
        "pending",
        "warning",
      ].includes(s)
    )
      return "warning";
    if (
      [
        "failed",
        "error",
        "unauthorized",
        "exhausted",
        "rejected_body",
        "rejected_origin",
        "not_found",
        "disabled",
      ].includes(s)
    )
      return "error";
    if (["active", "running", "requested", "reload_requested"].includes(s))
      return "accent";
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
    if (name === null || name === undefined || name === "")
      return `<span class="muted">—</span>`;
    const label = String(name);
    return `<span class="provider-cell" title="${esc(label)}">${brand(label)}<span class="${mono ? "mono " : ""}cell-ellipsis">${esc(label)}</span></span>`;
  }

  function tableWrap(columns, rows, options = {}) {
    const head = columns
      .map(
        (c) =>
          `<th scope="col" class="${c.align === "right" ? "cell-right" : ""}">${esc(c.label)}</th>`,
      )
      .join("");
    const totalColumns = columns.length + (options.expandable ? 1 : 0);
    let body;
    if (options.loading) {
      body = Array.from(
        { length: 4 },
        () =>
          `<tr class="skeleton-row">${Array.from({ length: totalColumns }, () => `<td><div class="skeleton-bar"></div></td>`).join("")}</tr>`,
      ).join("");
    } else if (options.error) {
      body = `<tr><td class="error-cell" colspan="${totalColumns}">${esc(options.error)}</td></tr>`;
    } else if (!rows || rows.length === 0) {
      body = `<tr><td colspan="${totalColumns}">
        <div class="empty-state">
          <p class="empty-title">${esc(options.emptyTitle || "Nothing here yet")}</p>
          ${options.emptyDescription ? `<p class="empty-description">${esc(options.emptyDescription)}</p>` : ""}
        </div></td></tr>`;
    } else {
      body = rows
        .map((row, i) => {
          const cells = columns
            .map((c) => {
              const cls = [
                c.align === "right" ? "cell-right" : "",
                c.mono ? "cell-mono" : "",
                c.nowrap === false ? "" : "cell-nowrap",
                c.className || "",
              ]
                .filter(Boolean)
                .join(" ");
              return `<td class="${cls}">${c.render(row, i)}</td>`;
            })
            .join("");
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
        })
        .join("");
    }
    const disclosureHead = options.expandable
      ? `<th scope="col" class="disclosure-cell"><span class="sr-only">Details</span></th>`
      : "";
    const caption = options.caption || "Management data";
    return `<div class="table-wrap"><table class="data-table"><caption class="sr-only">${esc(caption)}</caption><thead><tr>${disclosureHead}${head}</tr></thead><tbody>${body}</tbody></table></div>`;
  }

  function section(title, inner, hint = "") {
    const labelledInner = inner.replace(
      ">Management data</caption>",
      `>${esc(title)}</caption>`,
    );
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
    return state.errors[key] && !Object.hasOwn(state.data, key)
      ? state.errors[key].message
      : "";
  }

  function renderEndpointState(root, keys) {
    const failed = keys.filter((key) => state.errors[key]);
    if (!failed.length) return;
    const stale = failed.filter((key) => state.endpointMeta[key]?.stale);
    const unavailable = failed.filter((key) => !state.endpointMeta[key]?.stale);
    const parts = [];
    if (stale.length)
      parts.push(
        `Showing last known data for ${stale.map((key) => ENDPOINTS[key].path).join(", ")}.`,
      );
    if (unavailable.length)
      parts.push(
        `No data is available for ${unavailable.map((key) => ENDPOINTS[key].path).join(", ")}.`,
      );
    const banner = document.createElement("div");
    banner.className = "banner banner-warning endpoint-state";
    banner.setAttribute("role", "status");
    const summary =
      failed.length === keys.length ? "Refresh failed." : "Partial refresh.";
    banner.innerHTML = `<span class="banner-icon">${ic("warning-triangle", 16)}</span><div class="banner-body"><strong>${summary}</strong> ${esc(parts.join(" "))}</div>`;
    const header = $(".view-header", root);
    if (header) header.insertAdjacentElement("afterend", banner);
    else root.prepend(banner);
  }

  function persistenceWarning(payload, streamKey, label) {
    const persistence = payload?.persistence;
    const stream = persistence?.[streamKey];
    if (!persistence || !stream) return "";
    if (persistence.enabled === false) {
      return `<div class="callout callout-warning" role="status"><strong>Historical ${esc(label)} persistence is disabled.</strong> This view cannot be treated as a complete record.</div>`;
    }
    if (stream.complete !== false) return "";
    const lost = fmtInt(stream.lost_writes ?? stream.write_failures ?? 0);
    const failure = stream.last_failure_class
      ? ` Last failure: ${esc(stream.last_failure_class)}${stream.last_failure_at_ms ? ` at ${esc(fmtTime(stream.last_failure_at_ms))}` : ""}.`
      : "";
    const lostCount = Number(stream.lost_writes ?? stream.write_failures) || 0;
    return `<div class="callout callout-warning" role="status"><strong>Historical ${esc(label)} is incomplete.</strong> ${lost} write${lostCount === 1 ? "" : "s"} were lost, so an empty or partial result does not prove that no activity occurred.${failure}</div>`;
  }

  /* ---------------- Data loading ---------------- */

  function usageRangeParams() {
    const duration = {
      "1h": 60 * 60 * 1000,
      "24h": 24 * 60 * 60 * 1000,
      "7d": 7 * 24 * 60 * 60 * 1000,
      "30d": 30 * 24 * 60 * 60 * 1000,
    }[state.usageRange];
    const params = new URLSearchParams();
    if (duration) {
      const until = Date.now();
      params.set("since", String(until - duration));
      params.set("until", String(until));
    }
    return params;
  }

  function usageAggregatePath() {
    const params = usageRangeParams();
    params.set(
      "group_by",
      "route,provider,upstream_model,result_class,cost_provenance,price_book_version",
    );
    return `/usage/aggregate?${params.toString()}`;
  }

  function usageExportPath() {
    const params = usageRangeParams();
    const query = params.toString();
    return `/usage/export${query ? `?${query}` : ""}`;
  }

  async function loadEndpoints(keys) {
    const generation = ++state.requestGeneration;
    if (state.readController) state.readController.abort();
    const controller = new AbortController();
    state.readController = controller;
    state.loading = true;
    updateHeader();

    let unauthorized = false;
    let successful = 0;
    await Promise.all(
      keys.map(async (key) => {
        const spec = ENDPOINTS[key];
        try {
          const path =
            typeof spec.path === "function" ? spec.path() : spec.path;
          const payload = await readJson(path, controller.signal);
          if (generation !== state.requestGeneration) return undefined;
          state.data[key] = payload;
          state.errors[key] = null;
          state.endpointMeta[key] = { stale: false, updatedAt: Date.now() };
          successful += 1;
        } catch (error) {
          if (
            error.name === "AbortError" ||
            generation !== state.requestGeneration
          )
            return undefined;
          state.errors[key] = error;
          state.endpointMeta[key] = {
            stale: Object.hasOwn(state.data, key),
            updatedAt: state.endpointMeta[key]?.updatedAt || null,
          };
          if (error.status === 401) unauthorized = true;
        }
        return undefined;
      }),
    );

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
      $('[data-notice="auth"]')?.remove();
    } else if (state.token) {
      state.authState = "unavailable";
    } else if (successful > 0) {
      state.authState = "anonymous";
    }
    updateHeader();
    return true;
  }

  const ENDPOINTS = {
    controlPlane: { path: "/control-plane" },
    endpointInventory: { path: "/control-plane/endpoints" },
    configuration: { path: "/config" },
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
    usageAggregate: { path: () => usageAggregatePath() },
    decisions: { path: "/decisions?limit=50" },
    requests: { path: () => requestExplorerPath() },
    traces: { path: "/traces" },
    audit: { path: "/audit" },
    reloads: { path: "/reloads" },
  };

  /* ---------------- Header ---------------- */

  function updateHeader() {
    const health = state.data.health;
    const generation =
      health?.configuration_generation ??
      state.data.routes?.configuration_generation ??
      state.data.models?.configuration_generation;
    $("#generation-badge").textContent = `config ${text(generation)}`;
    const staleCount = (views[state.route]?.endpoints || []).filter(
      (key) => state.errors[key],
    ).length;
    if (state.loading) {
      $("#footer-updated").textContent = state.lastSuccessfulRefresh
        ? `Refreshing… Last data ${fmtTime(state.lastSuccessfulRefresh)}`
        : "Refreshing… No data loaded yet";
    } else if (state.lastSuccessfulRefresh) {
      $("#footer-updated").textContent =
        `${staleCount ? `Partial · ${staleCount} endpoint issue${staleCount === 1 ? "" : "s"} · ` : ""}Data refreshed ${fmtTime(state.lastSuccessfulRefresh)}`;
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
    const dark =
      document.documentElement.classList.contains("dark") ||
      (!document.documentElement.classList.contains("light") &&
        window.matchMedia("(prefers-color-scheme: dark)").matches);
    $("#theme-toggle").innerHTML = ic(dark ? "sun-light" : "half-moon", 18);
    $("#theme-toggle").setAttribute(
      "aria-label",
      dark ? "Switch to light theme" : "Switch to dark theme",
    );
    $("#theme-toggle").title = dark
      ? "Switch to light theme"
      : "Switch to dark theme";
  }

  /* ---------------- Views ---------------- */

  const views = {
    configuration: {
      title: "Configuration",
      subtitle: "See what Pooler is using now. Advanced edits are available when you need them.",
      endpoints: ["configuration", "controlPlane", "endpointInventory", "reloads"],
      render: renderConfiguration,
    },
    providers: {
      title: "Providers",
      subtitle: "Choose a provider, add an account, and select the models you want to use.",
      endpoints: ["controlPlane"],
      render: renderProviders,
    },
    overview: {
      title: "Overview",
      subtitle: "Runtime health, providers, accounts, and quota at a glance.",
      endpoints: [
        "health",
        "active",
        "providers",
        "accounts",
        "quota",
        "models",
        "listeners",
        "routes",
      ],
      render: renderOverview,
    },
    models: {
      title: "Models",
      subtitle:
        "Review verified model discovery and choose the models exposed to every client.",
      endpoints: ["controlPlane", "models", "catalog", "accounts"],
      render: renderModels,
    },
    accounts: {
      title: "Accounts",
      subtitle: "Manage each login or API key separately.",
      endpoints: ["controlPlane", "accounts", "quota"],
      render: renderAccounts,
    },
    pools: {
      title: "Failover",
      subtitle: "Group accounts so Pooler can use another one when an account is unavailable or rate-limited.",
      endpoints: ["controlPlane"],
      render: renderPools,
    },
    endpoints: {
      title: "Endpoints",
      subtitle: "Copy a Pooler address into any compatible app or SDK.",
      endpoints: ["endpointInventory", "controlPlane"],
      render: renderEndpoints,
    },
    usage: {
      title: "Usage",
      subtitle: "See tokens, cost estimates, limits, and speed over time.",
      endpoints: ["usageAggregate", "metrics", "quota"],
      render: renderUsage,
    },
    requests: {
      title: "Request explorer",
      subtitle: "See what happened to each request without exposing its content.",
      endpoints: ["requests"],
      render: renderRequests,
    },
    operations: {
      title: "Operations",
      subtitle: "See configuration reloads, provider choices, errors, and change history.",
      endpoints: ["health", "decisions", "traces", "audit", "reloads"],
      render: renderOperations,
    },
    diagnostics: {
      title: "Diagnostics",
      subtitle: "Safe system information for troubleshooting.",
      endpoints: ["health", "catalog", "listeners", "routes"],
      render: renderDiagnostics,
    },
  };

  /* ---------------- Typed configuration ---------------- */

  function safeConfigurationSnapshot() {
    const graph = controlGraph();
    const inventory = state.data.endpointInventory || graph.endpoints || {};
    return {
      version: 2,
      generation: graph.configuration?.generation ?? state.data.configuration?.configuration_generation ?? null,
      listeners: (inventory.listeners || []).map((listener) => ({ id: listener.id, address: listener.bind, routes: (listener.routes || []).map((route) => ({ methods: route.methods, path: route.path })) })),
      providers: (graph.providers || []).map((provider) => ({ name: provider.known_provider || provider.id, connection_id: provider.id, api: provider.base_url, accounts: provider.accounts })),
      accounts: (graph.accounts || []).map((account) => ({ name: account.id, provider: account.provider, sign_in: account.auth_kind, enabled: account.enabled })),
      failover_groups: (graph.pools || []).map((pool) => ({ name: pool.id, provider: pool.provider, accounts: pool.accounts, strategy: pool.strategy })),
      models: (graph.models || []).map((model) => ({ name: model.id, enabled: model.enabled !== false, providers: (model.targets || []).map((target) => ({ provider: target.provider, account: target.account || target.account_pool, priority: target.priority, provider_model: target.upstream_model })) })),
      routing_rules: graph.policies || [],
    };
  }

  function renderConfiguration(root) {
    const active = state.data.configuration || {};
    const editor = state.configuration;
    const enabled = Boolean(active.management?.typed_drafts);
    const sections =
      editor.operation === "replace"
        ? ["catalog", "management", "usage_price_book"]
        : [
            "listeners",
            "upstreams",
            "accounts",
            "credentials",
            "account_pools",
            "policies",
            "extensions",
            "models",
            "routes",
          ];
    const changes = editor.diff || [];
    const form = editor.draftId
      ? `
      <div class="panel">
        <div class="panel-head"><div><h2 class="panel-title">Draft ${esc(editor.draftId)}</h2><p class="muted">Base generation ${esc(active.configuration_generation)} · ETag <code class="mono">${esc(editor.etag)}</code></p></div></div>
        <div class="form-grid">
          <label class="field"><span class="field-label">Operation</span><select data-config-field="operation">${["upsert", "remove", "replace"].map((item) => `<option value="${item}"${item === editor.operation ? " selected" : ""}>${item}</option>`).join("")}</select></label>
          <label class="field"><span class="field-label">Section</span><select data-config-field="section">${sections.map((item) => `<option value="${item}"${item === editor.section ? " selected" : ""}>${item}</option>`).join("")}</select></label>
          ${editor.operation === "replace" ? "" : `<label class="field"><span class="field-label">Entry ID</span><input data-config-field="id" value="${esc(editor.id)}" maxlength="128" pattern="[A-Za-z0-9_.:/-]+" autocomplete="off" spellcheck="false"></label>`}
        </div>
        ${editor.operation === "remove" ? "" : `<label class="field"><span class="field-label">Typed JSON value</span><textarea class="code-input" data-config-field="value" rows="12" spellcheck="false">${esc(editor.value)}</textarea></label>`}
        <p class="muted">Only typed section operations are accepted. Use environment, file, command, or credential-store references for secrets; literal secret values are rejected.</p>
        <div class="button-row"><button class="btn btn-outline btn-sm" type="button" data-config-action="patch"${editor.busy ? " disabled" : ""}>Apply patch</button><button class="btn btn-outline btn-sm" type="button" data-config-action="validate"${editor.busy ? " disabled" : ""}>Validate and diff</button>${editor.confirmationToken ? `<button class="btn btn-primary btn-sm" type="button" data-config-action="commit"${editor.busy ? " disabled" : ""}>Commit validated draft</button>` : ""}</div>
      </div>
      <div class="panel"><div class="panel-head"><div><h2 class="panel-title">Semantic diff</h2><p class="muted">Values and secret references are intentionally omitted.</p></div></div>
        ${changes.length ? `<ul class="check-list">${changes.map((change) => `<li><span class="badge badge-neutral">${esc(change.change)}</span> <code class="mono">${esc(change.section)}${change.id ? `/${esc(change.id)}` : ""}</code></li>`).join("")}</ul>` : '<div class="empty-state"><p class="empty-title">No validated changes</p><p class="empty-description">Validate the draft to produce a bounded structural diff and one-time confirmation token.</p></div>'}
      </div>`
      : `
      <div class="panel empty-state"><p class="empty-title">Start from the active configuration</p><p class="empty-description">Pooler renders includes and environment substitution server-side, then creates an expiring draft without returning configuration values to the browser.</p><button class="btn btn-primary" type="button" data-config-action="create"${!enabled || editor.busy ? " disabled" : ""}>Create typed draft</button></div>`;
    const safeConfiguration = safeConfigurationSnapshot();
    const providerCount = safeConfiguration.providers.length;
    const accountCount = safeConfiguration.accounts.length;
    const modelCount = safeConfiguration.models.length;
    root.innerHTML = `
      ${viewHeader("Configuration", "See the settings Pooler is using. Secrets are always hidden.")}
      ${enabled ? "" : '<div class="callout callout-warning"><strong>Managed configuration is unavailable.</strong> Start Pooler from a regular local configuration file and connect with management authentication.</div>'}
      <section class="grid-stats grid-stats-4">${statCard("Providers", `<span class="num">${fmtInt(providerCount)}</span>`, "connected services")}${statCard("Accounts", `<span class="num">${fmtInt(accountCount)}</span>`, "separate logins and keys")}${statCard("Models", `<span class="num">${fmtInt(modelCount)}</span>`, "available to clients")}${statCard("Version", `<span class="num">2</span>`, `generation ${esc(safeConfiguration.generation)}`)}</section>
      <section class="panel"><div class="panel-head"><div><h2 class="panel-title">Current setup</h2><p class="muted">This is the active configuration with secrets removed.</p></div></div><pre class="code-block current-config"><code>${esc(JSON.stringify(safeConfiguration, null, 2))}</code></pre></section>
      <details class="panel advanced-config"><summary><strong>Advanced configuration editor</strong> <span class="muted">For users who prefer direct configuration changes</span></summary><div class="section">${form}<div class="panel-flat"><div class="panel-head"><div><h2 class="panel-title">Undo the last saved change</h2><p class="muted">Restore the previous configuration only if the latest change caused a problem.</p></div></div><button class="btn btn-outline btn-sm" type="button" data-config-action="rollback"${!enabled || editor.busy ? " disabled" : ""}>Undo last change</button></div></div></details>`;
  }

  async function configurationAction(action) {
    const editor = state.configuration;
    if (editor.busy) return;
    editor.busy = true;
    renderConfiguration($("#view"));
    try {
      let result;
      if (action === "create") {
        result = await mutate("/config/drafts");
        editor.draftId = result.draft_id;
        editor.etag = result.etag;
        editor.diff = [];
        editor.confirmationToken = "";
      } else if (action === "patch") {
        const patch = { op: editor.operation, section: editor.section };
        if (editor.operation !== "replace") patch.id = editor.id;
        if (editor.operation !== "remove")
          patch.value = JSON.parse(editor.value);
        result = await mutateJson(
          `/config/drafts/${encodeURIComponent(editor.draftId)}`,
          "PATCH",
          patch,
          editor.etag,
        );
        editor.etag = result.etag;
        editor.diff = [];
        editor.confirmationToken = "";
      } else if (action === "validate") {
        result = await mutateJson(
          `/config/drafts/${encodeURIComponent(editor.draftId)}/validate`,
          "POST",
          undefined,
          editor.etag,
        );
        editor.diff = result.semantic_diff || [];
        editor.confirmationToken = result.confirmation_token || "";
      } else if (action === "commit") {
        result = await mutateJson(
          `/config/drafts/${encodeURIComponent(editor.draftId)}/commit`,
          "POST",
          { confirmation_token: editor.confirmationToken },
          editor.etag,
        );
        editor.draftId = null;
        editor.etag = "";
        editor.diff = [];
        editor.confirmationToken = "";
        notify(
          "success",
          `Configuration reload request ${result.request_id} accepted.`,
        );
        await refreshCurrentView();
      } else if (action === "rollback") {
        const accepted = await confirmAction({
          title: "Rollback managed configuration?",
          copy: "Restore the previous owner-private managed revision and queue a generation-protected reload? The active runtime changes only if that reload succeeds.",
          acceptLabel: "Rollback",
          destructive: true,
        });
        if (!accepted) return;
        result = await mutateJson(
          "/config/rollback",
          "POST",
          { confirm: "rollback" },
          activeConfigurationEtag(),
        );
        notify(
          "success",
          `Rollback reload request ${result.request_id} accepted.`,
        );
        await refreshCurrentView();
      }
      if (action === "patch")
        notify("success", "Typed patch applied to the draft.");
      if (action === "validate")
        notify(
          "success",
          "Draft compiled and semantic diff is ready for confirmation.",
        );
    } catch (error) {
      if (error.status === 401) authRequired();
      else
        notify(
          "error",
          error instanceof SyntaxError
            ? "Typed JSON value is invalid."
            : error.message,
        );
    } finally {
      editor.busy = false;
      if (state.route === "configuration") renderConfiguration($("#view"));
    }
  }

  function activeConfigurationEtag() {
    const active = state.data.configuration || {};
    return active.etag || `generation-${active.configuration_generation}`;
  }

  /* ---------------- Structured provider control plane ---------------- */

  function controlGraph() {
    return state.data.controlPlane || {};
  }

  function graphProviders() {
    const providers = [...(controlGraph().providers || [])];
    if (state.onboarding.provider && state.onboarding.providerDetails && !providers.some((provider) => provider.id === state.onboarding.provider)) {
      providers.push(state.onboarding.providerDetails);
    }
    return providers;
  }

  function graphAccounts() {
    const runtime = new Map(
      (state.data.accounts?.accounts || []).map((account) => [account.id, account]),
    );
    return (controlGraph().accounts || []).map((account) => {
      const live = runtime.get(account.id);
      if (!live) return account;
      return {
        ...account,
        enabled: live.enabled,
        health: {
          ...(account.health || {}),
          status: live.status || account.health?.status,
          failure_count: live.failure_count ?? account.health?.failure_count,
          cooldown_until: live.cooldown_until ?? account.health?.cooldown_until,
        },
      };
    });
  }

  function graphPools() {
    return controlGraph().pools || [];
  }

  function graphModels() {
    const discovery = controlGraph().discovery || {};
    if (Array.isArray(discovery.models)) return discovery.models;
    if (Array.isArray(controlGraph().models)) return controlGraph().models;
    return state.data.models?.models || [];
  }

  function draftBar() {
    const draft = state.controlDraft;
    if (!draft.id) {
      return `<div class="callout callout-info draft-bar"><strong>Nothing changes until you save.</strong> Pooler lets you review every change first.</div>`;
    }
    const conflict = draft.conflict
      ? `<div class="callout callout-warning draft-conflict" role="alert"><strong>The setup changed in another window.</strong> <button class="btn btn-outline btn-xs" type="button" data-control-action="recover">Reload current setup</button> before saving.</div>`
      : "";
    return `${conflict}<div class="draft-bar" role="status"><span class="badge ${draft.dirty ? "badge-warning" : "badge-accent"}">${draft.dirty ? "Unsaved changes" : "Ready"}</span><span class="spacer"></span><button class="btn btn-outline btn-xs" type="button" data-control-action="validate"${draft.busy || draft.conflict ? " disabled" : ""}>Review</button>${draft.confirmationToken ? `<button class="btn btn-primary btn-xs" type="button" data-control-action="commit"${draft.busy ? " disabled" : ""}>Save changes</button>` : ""}<button class="btn btn-ghost btn-xs" type="button" data-control-action="discard"${draft.busy ? " disabled" : ""}>Discard</button></div>`;
  }

  function resetControlDraft() {
    state.controlDraft = {
      id: null,
      etag: "",
      baseGeneration: null,
      dirty: false,
      busy: false,
      conflict: false,
      confirmationToken: "",
    };
  }

  async function ensureControlDraft() {
    if (state.controlDraft.id) return state.controlDraft;
    const result = await mutate("/control-plane/drafts");
    state.controlDraft.id = result.draft_id;
    state.controlDraft.etag = result.etag || "";
    state.controlDraft.baseGeneration = result.base_generation ?? controlGraph().configuration?.generation;
    state.controlDraft.dirty = false;
    state.controlDraft.conflict = false;
    return state.controlDraft;
  }

  function applyControlResource(resource, value, id = "") {
    const operation = async () => {
      const draft = await ensureControlDraft();
      const suffix = id ? `/${encodeURIComponent(id)}` : "";
      try {
        const result = await mutateJson(
          `/control-plane/drafts/${encodeURIComponent(draft.id)}/${resource}${suffix}`,
          "POST",
          value,
          draft.etag,
        );
        draft.etag = result.etag || draft.etag;
        draft.dirty = true;
        draft.conflict = false;
        return result;
      } catch (error) {
        if (error.status === 409) {
          draft.conflict = true;
          notify("warning", "This draft is out of date. Reload current state and review before retrying.", { sticky: true });
        }
        throw error;
      }
    };
    const result = controlMutationQueue.then(operation, operation);
    controlMutationQueue = result.catch(() => undefined);
    return result;
  }

  async function waitForReload(requestId, failureMessage, timeoutMessage) {
    for (let attempt = 0; attempt < 40; attempt += 1) {
      const result = await readJson("/reloads");
      const reload = (result.reloads || []).find((item) => String(item.request_id) === String(requestId));
      if (reload?.status === "succeeded") return reload;
      if (["failed", "cancelled"].includes(reload?.status)) {
        throw new Error(failureMessage);
      }
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
    throw new Error(timeoutMessage);
  }

  function waitForConfigurationReload(requestId) {
    return waitForReload(
      requestId,
      "Pooler could not activate the new setup.",
      "Pooler is still activating the new setup. Try again in a moment.",
    );
  }

  function waitForModelReload(requestId) {
    return waitForReload(
      requestId,
      "Pooler could not read the provider's model list. Check the account login and provider status.",
      "Pooler is still reading the provider's model list. Try again in a moment.",
    );
  }

  async function saveControlChanges() {
    const draft = state.controlDraft;
    if (!draft.id) return;
    const validated = await mutateJson(
      `/control-plane/drafts/${encodeURIComponent(draft.id)}/validate`,
      "POST",
      undefined,
      draft.etag,
    );
    draft.etag = validated.etag || draft.etag;
    const confirmationToken = validated.confirmation_token;
    if (!confirmationToken) throw new Error("Pooler could not validate these changes.");
    const committed = await mutateJson(
      `/control-plane/drafts/${encodeURIComponent(draft.id)}/commit`,
      "POST",
      { confirmation_token: confirmationToken },
      draft.etag,
    );
    await waitForConfigurationReload(committed.request_id);
    resetControlDraft();
    await refreshCurrentView();
  }

  async function controlDraftAction(action) {
    const draft = state.controlDraft;
    if (action === "recover") {
      resetControlDraft();
      await refreshCurrentView();
      return;
    }
    if (!draft.id) return;
    draft.busy = true;
    try {
      if (action === "discard") {
        resetControlDraft();
        notify("info", "Structured draft discarded.");
        return;
      }
      if (action === "validate") {
        const result = await mutateJson(
          `/control-plane/drafts/${encodeURIComponent(draft.id)}/validate`,
          "POST",
          undefined,
          draft.etag,
        );
        draft.etag = result.etag || draft.etag;
        draft.confirmationToken = result.confirmation_token || "";
        notify("success", "Draft compiled. Review the redacted semantic diff before committing.");
        return;
      }
      if (action === "commit") {
        const result = await mutateJson(
          `/control-plane/drafts/${encodeURIComponent(draft.id)}/commit`,
          "POST",
          { confirmation_token: draft.confirmationToken },
          draft.etag,
        );
        resetControlDraft();
        notify("success", `Configuration reload request ${text(result.request_id)} accepted.`);
        await refreshCurrentView();
      }
    } catch (error) {
      if (error.status === 401) authRequired();
      else if (error.status !== 409) notify("error", error.message);
    } finally {
      draft.busy = false;
      if (state.route !== "configuration") renderCurrentViewIfVisible();
    }
  }

  async function prepareExplicitRouteDraft(client) {
    try {
      const result = await mutate("/config/drafts");
      state.configuration.draftId = result.draft_id;
      state.configuration.etag = result.etag || "";
      state.configuration.operation = "upsert";
      state.configuration.section = "routes";
      state.configuration.id = `${String(client).toLowerCase().replace(/[^a-z0-9]+/gu, "-")}-route`;
      state.configuration.value = JSON.stringify({ id: state.configuration.id, client, explicit: true }, null, 2);
      state.configuration.diff = [];
      state.configuration.confirmationToken = "";
      notify("info", "A visible route draft is prepared for review; no route was created or enabled.");
      window.location.hash = "configuration";
    } catch (error) {
      if (error.status === 401) authRequired();
      else notify("error", `Route draft could not be prepared: ${error.message}`);
    }
  }

  function renderCurrentViewIfVisible() {
    const root = $("#view");
    const view = views[state.route];
    if (root && view) {
      view.render(root);
      renderEndpointState(root, view.endpoints);
    }
  }

  function providerForm() {
    const draft = state.providerDraft;
    const templates = [...(controlGraph().provider_templates || [])].sort((left, right) =>
      String(left.name || left.id).localeCompare(
        String(right.name || right.id),
        undefined,
        { sensitivity: "base" },
      ));
    const templateId = draft.template === "__custom" || templates.some((template) => template.id === draft.template) ? draft.template : templates.find((template) => template.id === "openai")?.id || templates[0]?.id || "__custom";
    draft.template = templateId;
    const custom = templateId === "__custom";
    const selected = templates.find((template) => template.id === templateId);
    let fields;
    if (custom) {
      fields = `<div class="form-grid"><label class="field"><span class="field-label">Provider name</span><input data-provider-field="name" value="${esc(draft.name)}" maxlength="128" autocomplete="off" placeholder="My company gateway"></label><label class="field"><span class="field-label">Provider API URL</span><input data-provider-field="origin" value="${esc(draft.origin)}" maxlength="2048" inputmode="url" autocomplete="url" placeholder="https://api.example.com/v1"></label><label class="field"><span class="field-label">Works like</span><select data-provider-field="protocol"><option value="openai"${draft.protocol === "openai" ? " selected" : ""}>OpenAI Chat Completions</option></select></label><label class="field"><span class="field-label">Model IDs</span><input data-provider-field="modelIds" value="${esc(draft.modelIds)}" maxlength="4096" autocomplete="off" placeholder="model-a, model-b"></label></div><p class="muted">Use the HTTPS address and model IDs supplied by the custom provider—not Pooler’s localhost address.</p>`;
    } else if (selected?.dynamic_origin) {
      fields = `<div class="form-grid"><label class="field"><span class="field-label">Foundry enrollment URL</span><input data-provider-field="origin" value="${esc(draft.origin)}" maxlength="2048" inputmode="url" autocomplete="url" placeholder="https://example.palantirfoundry.com"></label><label class="field"><span class="field-label">OAuth client ID</span><input data-provider-field="clientId" value="${esc(draft.clientId)}" maxlength="512" autocomplete="off" placeholder="Provided by your Foundry administrator"></label></div><p class="muted">Pooler derives Palantir’s sign-in endpoints from this enrollment URL.</p>`;
    } else {
      fields = `<div class="callout callout-info"><strong>${esc(selected?.name || templateId)}</strong><br><span class="muted">${esc(selected?.base_url || "Official API address supplied by Pooler")}${selected?.model_discovery ? " · automatic model discovery" : ""}</span></div><p class="muted">Nothing else is required here. You will name and authenticate the account on the next step.</p>`;
    }
    const heading = custom ? "Add custom provider" : "Connect a built-in provider";
    const copy = custom ? "Enter the name and API address supplied by the provider." : "Choose a provider. Pooler fills in its API settings.";
    const providerSelect = custom ? "" : `<label class="field"><span class="field-label">Provider</span><select data-provider-field="template">${templates.map((template) => `<option value="${esc(template.id)}"${template.id === templateId ? " selected" : ""}>${esc(template.name)}</option>`).join("")}</select></label>`;
    return `<section class="panel" aria-labelledby="provider-connect-title"><div class="panel-head"><div><h2 class="panel-title" id="provider-connect-title">${heading}</h2><p class="muted">${copy}</p></div></div>${providerSelect}${fields}<div class="button-row"><button class="btn btn-primary btn-sm" type="button" data-provider-action="create"${draft.busy ? " disabled aria-busy=\"true\"" : ""}>Continue</button></div></section>`;
  }

  function accountForm(providerId = "") {
    const draft = state.accountDraft;
    const providers = graphProviders();
    if (!draft.provider) draft.provider = providerId || providers[0]?.id || "";
    const provider = providers.find((candidate) => candidate.id === draft.provider)
      || (state.onboarding.providerDetails?.id === draft.provider ? state.onboarding.providerDetails : null);
    const authMethods = provider?.auth_methods?.length ? provider.auth_methods : ["api_key"];
    if (!authMethods.includes(draft.authKind)) draft.authKind = authMethods[0];
    const oauth = draft.authKind === "oauth";
    return `<section class="panel" aria-labelledby="account-create-title"><div class="panel-head"><div><h2 class="panel-title" id="account-create-title">Add an account</h2><p class="muted">Each login or API key is an independent account with its own health and limits. Add another account later for automatic failover.</p></div></div><div class="form-grid"><label class="field"><span class="field-label">Provider</span><select data-account-new-field="provider"${providerId ? " disabled" : ""}>${providers.map((provider) => `<option value="${esc(provider.id)}"${provider.id === draft.provider ? " selected" : ""}>${esc(provider.id)}</option>`).join("")}</select></label><label class="field"><span class="field-label">Account name</span><input data-account-new-field="id" value="${esc(draft.id)}" maxlength="128" autocomplete="off" placeholder="Personal" aria-describedby="account-name-help"></label>${authMethods.length > 1 ? `<label class="field"><span class="field-label">Sign in with</span><select data-account-new-field="authKind">${authMethods.map((method) => `<option value="${esc(method)}"${method === draft.authKind ? " selected" : ""}>${method === "oauth" ? "Browser or device login" : "API key"}</option>`).join("")}</select></label>` : `<div class="field"><span class="field-label">Sign in with</span><strong>${oauth ? "Browser or device login" : "API key"}</strong></div>`}</div><p class="muted" id="account-name-help">Use a memorable name such as Personal, Work, or Team 2.</p>${oauth ? `<p class="callout">Add the account, then Pooler will show the sign-in methods supported by this provider. Tokens stay encrypted inside Pooler.</p>` : `<label class="field"><span class="field-label">API key</span><input data-account-new-field="secret" type="password" value="${esc(draft.secret)}" autocomplete="new-password" spellcheck="false" placeholder="Paste once; it is cleared immediately"></label><p class="muted">Pooler stores the key encrypted and clears it from this page immediately.</p>`}<div class="button-row"><button class="btn btn-primary btn-sm" type="button" data-account-new-action="create"${draft.busy || !draft.provider ? " disabled" : ""}>Add account</button></div></section>`;
  }

  function bindAccountCreate(root) {
    $("[data-account-new-action]", root)?.addEventListener("click", (event) => {
      event.stopPropagation();
      const oneTimeSecret = state.accountDraft.secret;
      state.accountDraft.secret = "";
      const secretInput = $("[data-account-new-field=\"secret\"]", root);
      if (secretInput) {
        secretInput.value = "";
        secretInput.defaultValue = "";
        secretInput.setAttribute("value", "");
      }
      createStructuredAccount(oneTimeSecret);
    });
  }

  function providerAccounts(providerId) {
    return graphAccounts().filter((account) => account.provider === providerId);
  }

  function renderProviders(root) {
    const providers = graphProviders();
    const templates = controlGraph().provider_templates || [];
    const selectedId = state.onboarding.provider;
    const selected = providers.find((provider) => provider.id === selectedId)
      || (state.onboarding.providerDetails?.id === selectedId ? state.onboarding.providerDetails : null);
    const cards = providers.map((provider) => {
      const accounts = providerAccounts(provider.id);
      const template = templates.find((candidate) => candidate.id === provider.id)
        || templates.find((candidate) => candidate.id === provider.known_provider);
      const name = template?.name || provider.id;
      return `<article class="panel provider-card" data-provider="${esc(provider.id)}"><div class="toolbar"><h2 class="panel-title">${providerCell(template?.id || provider.id, false)} ${esc(name)}</h2><span class="spacer"></span>${statusBadge(accounts.length ? "connected" : "add an account", accounts.length ? "success" : "warning")}</div><dl class="detail-grid"><div><dt>Accounts</dt><dd>${fmtInt(accounts.length)}</dd></div><div><dt>Automatic failover groups</dt><dd>${fmtInt(provider.pools)}</dd></div></dl><details><summary>Advanced details</summary><dl class="detail-grid"><div><dt>Connection ID</dt><dd class="mono">${esc(provider.id)}</dd></div><div><dt>Provider API</dt><dd class="mono">${esc(provider.origin || provider.base_url)}</dd></div></dl></details><div class="button-row"><button class="btn btn-primary btn-sm" type="button" data-onboarding-provider="${esc(provider.id)}">${accounts.length ? "Add another account" : "Add account"}</button><a class="btn btn-outline btn-sm" href="#/accounts?provider=${encodeURIComponent(provider.id)}">Manage accounts</a></div></article>`;
    }).join("");
    const onboarding = selected
      ? `<section class="panel onboarding-panel" aria-labelledby="onboarding-title"><div class="toolbar"><h2 class="panel-title" id="onboarding-title">Finish connecting ${esc(templates.find((template) => template.id === selected.known_provider)?.name || selected.id)}</h2><span class="spacer"></span><button class="btn btn-ghost btn-xs" type="button" data-onboarding-action="close">Close</button></div><ol class="check-list onboarding-steps"><li class="badge badge-success">1 · Provider</li><li class="${["account", "auth"].includes(state.onboarding.phase) ? "badge-accent" : "badge-neutral"}">2 · Account</li><li class="${state.onboarding.phase === "models" ? "badge-accent" : "badge-neutral"}">3 · Find models</li><li class="${state.onboarding.phase === "review" ? "badge-accent" : "badge-neutral"}">4 · Choose models</li></ol>${state.onboarding.phase === "account" ? accountForm(selected.id) : state.onboarding.phase === "auth" ? onboardingAuthPanel(selected) : state.onboarding.phase === "models" ? discoveryPanel(selected) : state.onboarding.phase === "review" ? modelReviewPanel() : `<p class="muted">Add an account to continue.</p>`}</section>`
      : "";
    root.innerHTML = `${viewHeader("Providers", views.providers.subtitle, `<span class="button-row"><button class="btn btn-primary btn-sm" type="button" data-provider-action="show-form">Add built-in provider</button><button class="btn btn-outline btn-sm" type="button" data-provider-action="show-custom">Add custom provider</button></span>`)}${draftBar()}<div class="callout callout-info"><strong>Protocol support is automatic.</strong> Choose a provider; Pooler uses the correct API format. There are no adapters to enable.</div>${state.providerDraft.visible ? providerForm() : ""}${onboarding}${cards ? `<section class="section"><div class="toolbar"><h2 class="section-title">Your providers</h2><span class="section-hint">Add more accounts to increase capacity or provide failover.</span></div><div class="grid-2">${cards}</div></section>` : `<div class="panel empty-state"><p class="empty-title">No providers connected</p><p class="empty-description">Choose a built-in provider or add a custom provider.</p></div>`}`;
    bindAccountCreate(root);
  }

  function discoveryPanel(provider) {
    const details = state.onboarding.providerDetails?.id === provider.id
      ? state.onboarding.providerDetails
      : provider;
    if (details.model_discovery === false || (!details.known_provider && details.native?.kind === "openai_compatible")) {
      return manualModelPanel(provider);
    }
    const discovered = graphModels();
    const matching = discovered.filter((model) => (model.targets || []).some((target) => target.provider === provider.id));
    const models = matching.length || !state.onboarding.providerDetails ? matching : discovered;
    return `<section class="panel" aria-labelledby="discovery-title"><h2 class="panel-title" id="discovery-title">Verified model discovery</h2><p class="muted">After account authentication, Pooler reads the provider’s bounded model list. No inference request is sent.</p><p class="callout">${models.length ? `${fmtInt(models.length)} verified model${models.length === 1 ? "" : "s"} available.` : "No verified models are available yet."}</p><div class="button-row"><button class="btn btn-primary btn-sm" type="button" data-onboarding-action="discover"${state.onboarding.discoveryBusy ? " disabled aria-busy=\"true\"" : ""}>${state.onboarding.discoveryBusy ? "Discovering…" : "Find models"}</button>${models.length ? `<button class="btn btn-outline btn-sm" type="button" data-onboarding-action="review">Review models</button>` : ""}</div></section>`;
  }

  function manualModelPanel(provider) {
    return `<section class="panel" aria-labelledby="manual-model-title"><h2 class="panel-title" id="manual-model-title">Add the provider’s models</h2><p class="muted">This custom provider does not publish a model list Pooler can verify. Enter the exact model IDs from the provider.</p><label class="field"><span class="field-label">Model IDs</span><input data-provider-field="modelIds" value="${esc(state.providerDraft.modelIds)}" maxlength="4096" autocomplete="off" placeholder="model-a, model-b"></label><div class="button-row"><button class="btn btn-primary btn-sm" type="button" data-onboarding-action="save-manual-models">Create models and endpoints</button></div><details><summary>Advanced details</summary><p class="mono">Provider: ${esc(provider.id)} · account: ${esc(state.onboarding.account)}</p></details></section>`;
  }

  async function saveManualModels() {
    const provider = state.onboarding.provider;
    const account = state.onboarding.account;
    const models = csvValues(state.providerDraft.modelIds);
    if (!provider || !account || !models.length || models.length > 256) {
      notify("error", "Enter at least one valid model ID.");
      return;
    }
    if (models.some((model) => model.length > 256 || /\s|[\u0000-\u001f\u007f]/u.test(model))) {
      notify("error", "Model IDs cannot contain spaces or control characters.");
      return;
    }
    try {
      for (const [index, model] of [...new Set(models)].entries()) {
        await applyControlResource("models", {
          id: model,
          targets: [{
            id: `manual-target-${index + 1}`,
            provider,
            account,
            priority: 1,
            upstream_model: model,
            capabilities: ["text", "streaming"],
            codecs: ["openai"],
            wire_family: "openai",
          }],
        });
      }
      await ensureStandardRoutes(provider);
      await saveControlChanges();
      state.providerDraft.modelIds = "";
      state.onboarding.phase = "review";
      notify("success", "Custom models and standard Pooler endpoints are ready.");
    } catch (error) {
      if (error.status === 401) authRequired();
      else if (error.status !== 409) notify("error", error.message);
    }
  }

  function onboardingAuthPanel(provider) {
    const account = { id: state.onboarding.account, provider: provider.id, auth_kind: "oauth", enabled: true, health: { status: "pending" } };
    const panel = accountOAuthPanel(account);
    if (!state.oauthCapabilities[account.id]) loadOAuthCapabilities(account.id).then(() => renderCurrentViewIfVisible());
    return `${panel}<div class="button-row"><button class="btn btn-outline btn-sm" type="button" data-onboarding-action="continue-models">Continue to verified model discovery</button></div>`;
  }

  function normalizedId(label, fallback) {
    return String(label || fallback)
      .toLowerCase()
      .normalize("NFKD")
      .replace(/[^a-z0-9]+/gu, "-")
      .replace(/^-+|-+$/gu, "")
      .slice(0, 112) || fallback;
  }

  function availableId(label, fallback, used) {
    const base = normalizedId(label, fallback);
    if (!used.has(base)) return base;
    for (let suffix = 2; suffix < 10_000; suffix += 1) {
      const candidate = `${base}-${suffix}`;
      if (!used.has(candidate)) return candidate;
    }
    return `${base}-${Date.now()}`;
  }

  function availableProviderId(label) {
    return availableId(
      label,
      "provider",
      new Set(graphProviders().map((provider) => provider.id)),
    );
  }

  function availablePoolId(label) {
    return availableId(
      label,
      "failover-group",
      new Set(graphPools().map((pool) => pool.id)),
    );
  }

  function browserOAuthCallback() {
    const managementBase = (state.data.endpointInventory || controlGraph().endpoints || {}).management?.base_urls?.[0];
    const base = managementBase || window.location.origin;
    return new URL("/management/oauth/browser/callback", base).toString();
  }

  function ensureSelectedModels(models) {
    const ids = new Set(models.map((model) => model.id));
    if (!state.onboarding.modelsInitialized) {
      state.onboarding.selectedModels = new Set(models.filter((model) => model.enabled !== false && model.exposed !== false).map((model) => model.id));
      state.onboarding.modelsInitialized = true;
    } else {
      state.onboarding.selectedModels = new Set([...state.onboarding.selectedModels].filter((id) => ids.has(id)));
    }
  }

  function modelReviewPanel() {
    const models = graphModels();
    ensureSelectedModels(models);
    return `<section class="panel" aria-labelledby="model-review-title"><div class="toolbar"><div><h2 class="panel-title" id="model-review-title">Choose models</h2><p class="muted">Selected models will be available to your apps.</p></div><span class="spacer"></span><button class="btn btn-outline btn-xs" type="button" data-model-selection="all">Select all</button><button class="btn btn-outline btn-xs" type="button" data-model-selection="none">Select none</button></div><div class="model-review-list">${models.map((model) => `<label class="model-review-row"><input type="checkbox" data-model-selection-id="${esc(model.id)}"${state.onboarding.selectedModels.has(model.id) ? " checked" : ""}><span class="mono">${esc(model.id)}</span><span class="muted">${fmtInt((model.targets || []).length)} provider${(model.targets || []).length === 1 ? "" : "s"}</span></label>`).join("") || `<div class="empty-state"><p class="empty-title">No models found</p><p class="empty-description">Try finding models again after signing in.</p></div>`}</div><div class="button-row"><button class="btn btn-primary btn-sm" type="button" data-onboarding-action="save-models"${!models.length ? " disabled" : ""}>Save models</button></div></section>`;
  }

  async function createProvider() {
    const draft = state.providerDraft;
    const templates = controlGraph().provider_templates || [];
    const custom = draft.template === "__custom";
    const selected = templates.find((template) => template.id === draft.template);
    if (!custom && !selected) {
      notify("error", "Choose a provider.");
      return;
    }
    if (custom && (!draft.name.trim() || !/^https?:\/\/[^\s]+$/u.test(draft.origin.trim()))) {
      notify("error", "Enter a provider name and its valid HTTPS API URL.");
      return;
    }
    if (selected?.dynamic_origin && (!/^https:\/\/[^\s]+$/u.test(draft.origin.trim()) || !draft.clientId.trim())) {
      notify("error", "Enter the Foundry enrollment URL and OAuth client ID.");
      return;
    }
    const id = availableProviderId(custom ? draft.name : selected.id);
    const resource = custom
      ? { id, url: draft.origin.trim(), native: { kind: "openai_compatible" } }
      : selected.dynamic_origin
        ? { id, url: draft.origin.trim(), native: { kind: selected.native_kind }, oauth: { client_id: draft.clientId.trim(), scopes: ["api:use-language-models-execute", "offline_access"], callback: browserOAuthCallback() } }
        : { id, known_provider: selected.known_provider || selected.id, ...(selected.native_config ? { native: { kind: selected.native_kind } } : {}) };
    draft.busy = true;
    try {
      await applyControlResource("providers", resource);
      state.onboarding.provider = id;
      const origin = custom || selected.dynamic_origin ? draft.origin.trim() : selected.base_url;
      state.onboarding.providerDetails = { id, instance_id: id, known_provider: custom ? null : selected.known_provider || selected.id, origin, base_url: origin, auth_methods: custom ? ["api_key"] : selected.auth_methods, accounts: 0, pools: 0, model_discovery: custom ? false : selected.model_discovery, endpoint_families: custom ? ["models", "chat_completions"] : selected.endpoint_families };
      state.onboarding.phase = "account";
      state.providerDraft.visible = false;
      draft.id = "";
      draft.name = "";
      draft.origin = "";
      draft.clientId = "";
      draft.modelIds = custom ? draft.modelIds : "";
      draft.busy = false;
      notify("success", `${custom ? "Custom provider" : selected.name} is staged. Add an account to continue.`);
      renderProviders($("#view"));
    } catch (error) {
      draft.busy = false;
      if (error.status === 401) authRequired();
      else if (error.status !== 409) notify("error", error.message);
    }
  }

  async function createStructuredAccount(oneTimeSecret = "") {
    const draft = state.accountDraft;
    if (!draft.id.trim() || !draft.provider) {
      notify("error", "Choose a provider and enter an account name.");
      return;
    }
    draft.busy = true;
    let managedReference = "";
    try {
      if (draft.authKind === "api_key") {
        if (!oneTimeSecret) throw new Error("Enter the one-time provider secret.");
        const secret = await mutateJson("/control-plane/secrets", "POST", { kind: "api_key", value: oneTimeSecret });
        managedReference = secret.managed_secret?.reference || "";
        if (!managedReference) throw new Error("Managed secret storage did not return an opaque reference.");
      }
      await applyControlResource("accounts", { id: draft.id.trim(), provider: draft.provider, auth_kind: draft.authKind, ...(managedReference ? { secret: managedReference } : {}) });
      await saveControlChanges();
      state.onboarding.account = draft.id.trim();
      state.onboarding.phase = draft.authKind === "oauth" ? "auth" : "models";
      draft.id = "";
      draft.secret = "";
      draft.busy = false;
      notify("success", "Account staged. Authenticate it, then run verified model discovery.");
      await refreshCurrentView();
    } catch (error) {
      draft.busy = false;
      if (error.status === 401) authRequired();
      else if (error.status !== 409) notify("error", error.message);
    } finally {
      draft.secret = "";
    }
  }

  async function discoverVerifiedModels() {
    if (state.onboarding.discoveryBusy) return;
    state.onboarding.discoveryBusy = true;
    try {
      const result = await mutate("/models/reload");
      await waitForModelReload(result.request_id);
      await refreshCurrentView();
      state.onboarding.phase = "review";
      renderProviders($("#view"));
      notify("success", "Models found. Choose which ones Pooler should make available.");
    } catch (error) {
      if (error.status === 401) authRequired();
      else notify("error", `Model discovery failed: ${error.message}`);
    } finally {
      state.onboarding.discoveryBusy = false;
    }
  }

  async function saveModelExposure() {
    const models = graphModels();
    if (!models.length) return;
    try {
      const discovery = controlGraph().discovery || {};
      const sources = (discovery.sources || state.data.catalog?.sources || []).map((source) => {
        const config = {};
        for (const key of [
          "id",
          "provider",
          "account",
          "account_pool",
          "parser",
          "path",
          "max_response_bytes",
          "model_facts_provider",
          "prefix",
          "priority",
          "aliases",
          "included_models",
          "excluded_models",
        ]) {
          if (source[key] !== undefined && source[key] !== null) config[key] = source[key];
        }
        return config;
      });
      const overrides = models
        .filter((model) => !state.onboarding.selectedModels.has(model.id))
        .map((model) => ({ model: model.id, disabled: true }));
      const draft = await ensureControlDraft();
      const result = await mutateJson(
        `/control-plane/drafts/${encodeURIComponent(draft.id)}/models/select_all_models`,
        "POST",
        { id: "catalog", sources, overrides },
        draft.etag,
      );
      draft.etag = result.etag || draft.etag;
      draft.dirty = true;
      const providerId = state.onboarding.provider
        || models.flatMap((model) => model.targets || []).find((target) => target.provider)?.provider
        || "";
      await ensureStandardRoutes(providerId);
      await saveControlChanges();
      state.onboarding.phase = "review";
      notify("success", "Models and standard Pooler endpoints are ready.");
    } catch (error) {
      if (error.status === 401) authRequired();
      else if (error.status === 409) {
        state.controlDraft.conflict = true;
        notify("warning", "The model exposure draft is out of date. Reload current state before retrying.", { sticky: true });
      }
      else if (error.status !== 409) notify("error", error.message);
    }
  }

  async function ensureStandardRoutes(providerId) {
    const graph = controlGraph();
    const provider = graphProviders().find((item) => item.id === providerId)
      || (state.onboarding.providerDetails?.id === providerId ? state.onboarding.providerDetails : null);
    if (!provider) return;
    const templates = graph.provider_templates || [];
    const template = templates.find((item) => item.id === provider.id)
      || templates.find((item) => item.id === provider.known_provider)
      || (state.onboarding.providerDetails?.id === provider.id ? state.onboarding.providerDetails : null);
    const families = new Set(template?.endpoint_families || []);
    if (!families.size) return;
    if (!(graph.policies || []).some((policy) => policy.id === "default")) {
      await applyControlResource("policies", {
        id: "default",
        selection: { strategy: "ordered_fallback" },
        retry: {
          maximum_attempts: 3,
          maximum_credentials: 3,
          maximum_upstreams: 3,
          statuses: [408, 429, 500, 502, 503, 504],
          before_commit_only: true,
          base_delay: "25ms",
          maximum_delay: "250ms",
          maximum_total_delay: "2s",
        },
        routing: { allow_fallbacks: true },
      });
    }
    const routeIds = new Set((graph.routes || []).map((route) => route.id));
    const jsonLimits = {
      max_request_body_bytes: 8_388_608,
      max_response_body_bytes: 8_388_608,
      max_frame_bytes: 2_097_152,
      max_event_bytes: 2_097_152,
      max_queue_bytes: 4_194_304,
      max_queue_items: 256,
      request_timeout: "10m",
      connect_timeout: "10s",
    };
    const patchIngress = { mode: "patch", inspectors: ["inspect.openai.model"] };
    if (!routeIds.has("standard-models")) {
      await applyControlResource("routes", {
        id: "standard-models",
        listen: "inference",
        match: { methods: ["GET"], path: "/v1/models" },
        limits: { max_request_body_bytes: 65_536 },
        serve: "model_catalog",
        ingress: { mode: "opaque" },
        target: { provider: providerId, endpoint_family: "models" },
        response: { mode: "opaque" },
      });
    }
    if (families.has("chat_completions") && !routeIds.has("standard-chat-completions")) {
      await applyControlResource("routes", {
        id: "standard-chat-completions",
        listen: "inference",
        match: {
          methods: ["POST"],
          path: "/v1/chat/completions",
          content_types: ["application/json"],
        },
        limits: jsonLimits,
        ingress: patchIngress,
        target: {
          provider: providerId,
          model_from: "request.model",
          policy: "default",
          endpoint_family: "chat_completions",
        },
        response: { mode: "opaque" },
      });
    }
    if (families.has("responses") && !routeIds.has("standard-responses")) {
      const route = {
        id: "standard-responses",
        listen: "inference",
        match: {
          methods: ["POST"],
          path: "/v1/responses",
          content_types: ["application/json"],
        },
        limits: jsonLimits,
        ingress: patchIngress,
        target: {
          provider: providerId,
          model_from: "request.model",
          policy: "default",
          endpoint_family: "responses",
        },
        response: { mode: "opaque" },
      };
      if (provider.native?.kind === "codex") {
        route.ingress = {
          mode: "semantic",
          decoder: "decode.openai.responses",
          encoder: "encode.openai.responses",
        };
        route.response = {
          mode: "semantic",
          decoder: "decode.openai.responses.events",
          encoder: "encode.openai.responses.events",
        };
        route.loss_policy = "reject";
      }
      await applyControlResource("routes", route);
    }
    if (families.has("messages") && !routeIds.has("standard-messages")) {
      await applyControlResource("routes", {
        id: "standard-messages",
        listen: "inference",
        match: {
          methods: ["POST"],
          path: "/v1/messages",
          content_types: ["application/json"],
        },
        limits: jsonLimits,
        ingress: patchIngress,
        target: {
          provider: providerId,
          model_from: "request.model",
          policy: "default",
          endpoint_family: "messages",
        },
        response: { mode: "opaque" },
      });
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

    const availableProviders = providers.filter(
      (p) => p.status === "not_cooling" || p.status === "available",
    ).length;
    const enabledAccounts = accounts.filter((a) => a.enabled).length;
    const cooldowns = quota.cooldowns || [];
    const windows = quota.windows || [];

    const stats = [
      statCard(
        "Status",
        statusBadge(
          health.status || (endpointError("health") ? "error" : "unknown"),
        ),
        endpointError("health")
          ? esc(endpointError("health"))
          : `${fmtInt(health.credential_health_entries)} health entries`,
      ),
      statCard(
        "Active requests",
        `<span class="num">${fmtInt(active.active ?? health.active)}</span>`,
        "Across all listeners",
      ),
      statCard(
        "Providers",
        `<span class="num">${fmtInt(availableProviders)}<span class="muted">/${fmtInt(providers.length)}</span></span>`,
        "Not cooling down; connectivity is not probed",
      ),
      statCard(
        "Accounts",
        `<span class="num">${fmtInt(enabledAccounts)}<span class="muted">/${fmtInt(accounts.length)}</span></span>`,
        "Enabled accounts",
      ),
      statCard(
        "Models",
        `<span class="num">${fmtInt(models.length)}</span>`,
        "Published model IDs",
      ),
      statCard(
        "Quota windows",
        `<span class="num">${fmtInt(windows.length)}</span>`,
        cooldowns.length
          ? `${fmtInt(cooldowns.length)} active cooldowns`
          : "No active cooldowns",
      ),
    ].join("");

    const providerTable = tableWrap(
      [
        { label: "ID", mono: true, render: (p) => providerCell(p.id) },
        { label: "Transport", render: (p) => esc(text(p.transport)) },
        { label: "Native", render: (p) => esc(text(p.native)) },
        {
          label: "Auth",
          render: (p) =>
            p.auth_configured
              ? `<span class="inline-meta muted">${ic("lock", 13)} configured</span>`
              : `<span class="muted">—</span>`,
        },
        { label: "Status", render: (p) => statusBadge(p.status) },
      ],
      providers,
      {
        loading: state.loading && !state.data.providers,
        error: endpointError("providers"),
        emptyTitle: "No providers configured",
      },
    );

    const listenerTable = tableWrap(
      [
        { label: "ID", mono: true, render: (l) => esc(l.id) },
        { label: "Bind", mono: true, render: (l) => esc(l.bind) },
        { label: "Protocol", render: (l) => esc(text(l.protocol)) },
        {
          label: "TLS",
          render: (l) =>
            l.tls
              ? `<span class="inline-meta muted">${ic("lock", 13)} yes</span>`
              : `<span class="muted">no</span>`,
        },
        {
          label: "Routes",
          align: "right",
          render: (l) => `<span class="num">${fmtInt(l.route_count)}</span>`,
        },
      ],
      listeners,
      {
        loading: state.loading && !state.data.listeners,
        error: endpointError("listeners"),
        emptyTitle: "No listeners configured",
      },
    );

    const routeTable = tableWrap(
      [
        { label: "ID", mono: true, render: (r) => esc(r.id) },
        { label: "Listener", mono: true, render: (r) => esc(r.listener) },
        {
          label: "Path",
          mono: true,
          nowrap: false,
          render: (r) => esc(text(r.path)),
        },
        {
          label: "Target",
          mono: true,
          nowrap: false,
          render: (r) => esc(text(r.target?.upstream)),
        },
      ],
      routes,
      {
        loading: state.loading && !state.data.routes,
        error: endpointError("routes"),
        emptyTitle: "No routes compiled",
      },
    );

    const activeByListener = Object.entries(active.by_listener || {});
    const activeTable = activeByListener.length
      ? tableWrap(
          [
            { label: "Listener", mono: true, render: ([id]) => esc(id) },
            {
              label: "Active",
              align: "right",
              render: ([, count]) =>
                `<span class="num">${fmtInt(count)}</span>`,
            },
          ],
          activeByListener,
          {},
        )
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

  function modelExposureSwitch(model, mutationCapable) {
    const enabled = model.enabled !== false;
    if (!mutationCapable) return enabledBadge(enabled);
    const action = enabled ? "disable" : "enable";
    const path = `/models/${modelPath(model.id)}/${action}`;
    const pending = state.pending.has(path);
    return `<button class="switch" type="button" role="switch" aria-checked="${enabled}" aria-label="${enabled ? "Hide" : "Expose"} model ${esc(model.id)} from clients" aria-busy="${pending}" data-model-action="${action}" data-model-id="${esc(model.id)}" title="${enabled ? "Exposed to clients" : "Hidden from clients"} — ${esc(model.id)}"${pending ? " disabled" : ""}><span class="switch-thumb"></span></button>`;
  }

  function renderSourceState(sourceState) {
    if (!sourceState) return `<span class="muted">—</span>`;
    if (typeof sourceState === "string") return statusBadge(sourceState);
    const status = sourceState.status || sourceState.state || sourceState.kind;
    const detail =
      sourceState.error || sourceState.detail || sourceState.message;
    return `${statusBadge(status || "unknown")}${detail ? ` <span class="muted" title="${esc(detail)}">${esc(shortId(detail, 40))}</span>` : ""}`;
  }

  /* ---------------- Structured models, pools, accounts, and endpoints ---------------- */

  function renderModels(root) {
    const graph = controlGraph();
    const models = graphModels();
    const discovery = graph.discovery || {};
    const selected = new Set(state.onboarding.selectedModels);
    if (!state.onboarding.modelsInitialized && models.length) {
      models.filter((model) => model.enabled !== false && model.exposed !== false).forEach((model) => selected.add(model.id));
      state.onboarding.selectedModels = selected;
      state.onboarding.modelsInitialized = true;
    }
    const configuredOrder = new Map(
      (graph.effective_order || []).map((entry) => [entry.model, entry]),
    );
    const ordered = models
      .map((model) => configuredOrder.get(model.id) || {
        model: model.id,
        candidates: modelTargets(model).map((target, index) => ({
          provider: target.provider,
          account: target.account,
          account_pool: target.account_pool,
          priority: Number(target.priority) || index + 1,
        })),
      })
      .filter((entry) => entry.candidates.length);
    const rows = models.map((model) => `<div class="model-review-row"><label><input type="checkbox" data-model-selection-id="${esc(model.id)}"${selected.has(model.id) ? " checked" : ""}><span class="mono">${esc(model.id)}</span></label><span class="muted">${fmtInt((model.targets || []).length)} provider${(model.targets || []).length === 1 ? "" : "s"}</span><span class="spacer"></span><span class="badge ${selected.has(model.id) ? "badge-success" : "badge-neutral"}">${selected.has(model.id) ? "On" : "Off"}</span></div>`).join("");
    const targetSections = models.map((model) => `<section class="panel target-model-panel" data-target-model-panel="${esc(model.id)}"><div class="toolbar"><div><h2 class="panel-title mono">${esc(model.id)}</h2><p class="muted">Drag providers into the order Pooler should try them. Providers with the same priority can share traffic.</p></div><span class="spacer"></span><span class="badge badge-neutral">${fmtInt((model.targets || []).length)} providers</span></div>${renderTargetRows(model)}</section>`).join("");
    const effectivePreview = ordered.map((entry) => `<section class="panel-flat"><h3 class="section-title mono">${esc(entry.model)}</h3><p class="muted">${(entry.candidates || []).map((candidate) => `${esc(candidate.provider)} · priority ${esc(candidate.priority)}${candidate.account ? ` · ${esc(candidate.account)}` : candidate.account_pool ? ` · failover group ${esc(candidate.account_pool)}` : ""}`).join(" → ")}</p></section>`).join("");
    root.innerHTML = `${viewHeader("Models", views.models.subtitle, `<button class="btn btn-outline btn-sm" type="button" data-model-action="discover"${state.pending.has("/models/reload") ? " disabled aria-busy=\"true\"" : ""}>${ic("refresh-double", 15)} Find models</button>`)}${draftBar()}<p id="target-announcement" class="sr-only" aria-live="polite">${esc(state.targetAnnouncement)}</p><section class="grid-stats grid-stats-4">${statCard("Found", `<span class="num">${fmtInt(models.length)}</span>`, discovery.refreshed_at_unix_ms ? `updated ${esc(relTime(discovery.refreshed_at_unix_ms))}` : "Not checked yet")}${statCard("On", `<span class="num">${fmtInt([...selected].length)}</span>`, "available to apps")}${statCard("Providers", `<span class="num">${fmtInt((discovery.sources || []).length)}</span>`, "providers checked for models")}${statCard("Routing orders", `<span class="num">${fmtInt(ordered.length)}</span>`, "Provider order")}</section><section class="panel" aria-labelledby="model-exposure-title"><div class="toolbar"><div><h2 class="panel-title" id="model-exposure-title">Models available to clients</h2><p class="muted">Turn models on or off. Your changes are reviewed before they are saved.</p></div><span class="spacer"></span><button class="btn btn-outline btn-xs" type="button" data-model-selection="all">Select all</button><button class="btn btn-outline btn-xs" type="button" data-model-selection="none">Select none</button></div><div class="model-review-list">${rows || `<div class="empty-state"><p class="empty-title">No models found</p><p class="empty-description">Add and sign in to a provider, then find models.</p></div>`}</div><div class="button-row"><button class="btn btn-primary btn-sm" type="button" data-model-selection="save"${models.length ? "" : " disabled"}>Save model choices</button></div></section><section class="section" aria-labelledby="target-order-title"><div class="toolbar"><div><h2 class="section-title" id="target-order-title">Ordered providers</h2><span class="section-hint">Drag providers into the order you want. Use the same priority when providers should share traffic.</span></div><a class="btn btn-outline btn-sm" href="#/pools">Manage failover</a></div>${targetSections || `<div class="panel empty-state"><p class="empty-title">No providers are assigned to this model</p></div>`}</section><section class="panel" aria-labelledby="effective-order-title"><div class="toolbar"><h2 class="panel-title" id="effective-order-title">What Pooler will try</h2><span class="badge badge-neutral">current order</span></div>${effectivePreview || `<p class="empty-description">No provider order is available.</p>`}</section><details class="panel"><summary><strong>Advanced routing rules</strong> <span class="muted">Filters, privacy, price, and adaptive ranking</span></summary><div class="section">${renderPolicyControls()}</div></details>`;
    root.querySelectorAll("[data-target-row]").forEach((row) => {
      row.addEventListener("dragstart", () => {
        const model = graphModels().find((item) => item.id === row.dataset.targetModel);
        state.targetDrag = model ? { modelId: model.id, targetId: row.dataset.targetId, original: orderedTargetIds(model), dropped: false } : null;
        row.classList.add("dragging");
      });
      row.addEventListener("dragover", (event) => event.preventDefault());
      row.addEventListener("drop", (event) => {
        event.preventDefault();
        if (state.targetDrag) {
          state.targetDrag.dropped = true;
          moveTarget(state.targetDrag.modelId, state.targetDrag.targetId, Number(row.dataset.targetIndex));
        }
      });
      row.addEventListener("dragend", () => {
        row.classList.remove("dragging");
        if (state.targetDrag && !state.targetDrag.dropped) state.targetDrag = null;
      });
    });
  }

  function renderPools(root) {
    const pools = graphPools();
    const accounts = graphAccounts();
    const providers = graphProviders();
    const draft = state.poolDraft;
    const selectedProvider = draft.provider || providers[0]?.id || "";
    if (!draft.provider) draft.provider = selectedProvider;
    const providerAccountsList = accounts.filter((account) => account.provider === selectedProvider);
    const poolRows = pools.map((pool) => `<article class="panel"><div class="toolbar"><h2 class="panel-title">${esc(pool.id)}</h2><span class="spacer"></span>${statusBadge(pool.homogeneous ? "ready" : "needs attention", pool.homogeneous ? "success" : "warning")}</div><dl class="detail-grid"><div><dt>Provider</dt><dd>${esc(pool.provider)}</dd></div><div><dt>Account order</dt><dd>${pool.strategy === "health_weighted" ? "Prefer healthier accounts" : "Use accounts in order"}</dd></div><div><dt>Accounts</dt><dd>${(pool.accounts || []).map((id) => `<span class="chip">${esc(id)}</span>`).join(" ") || "—"}</dd></div><div><dt>When Pooler switches</dt><dd>Before a provider starts its response</dd></div></dl></article>`).join("");
    root.innerHTML = `${viewHeader("Failover", views.pools.subtitle)}${draftBar()}<section class="panel" aria-labelledby="pool-create-title"><div class="panel-head"><div><h2 class="panel-title" id="pool-create-title">Create a failover group</h2><p class="muted">Choose two or more accounts from the same provider.</p></div></div><div class="form-grid"><label class="field"><span class="field-label">Group name</span><input data-pool-field="id" value="${esc(draft.id)}" maxlength="128" placeholder="OpenAI accounts" autocomplete="off"></label><label class="field"><span class="field-label">Provider</span><select data-pool-field="provider">${providers.map((provider) => `<option value="${esc(provider.id)}"${provider.id === selectedProvider ? " selected" : ""}>${esc(provider.id)}</option>`).join("")}</select></label><label class="field"><span class="field-label">How Pooler should choose</span><select data-pool-field="strategy"><option value="ordered_fallback"${draft.strategy === "ordered_fallback" ? " selected" : ""}>Use accounts in order</option><option value="health_weighted"${draft.strategy === "health_weighted" ? " selected" : ""}>Prefer healthier accounts</option></select></label></div><fieldset class="field-group"><legend class="field-label">Accounts</legend><div class="model-review-list">${providerAccountsList.map((account) => `<label class="model-review-row"><input type="checkbox" data-pool-account="${esc(account.id)}"${draft.accounts.includes(account.id) ? " checked" : ""}><span>${esc(account.id)}</span><span class="muted">${esc(account.health?.status || "unknown")} · ${account.enabled === false ? "disabled" : "enabled"}</span></label>`).join("") || `<p class="empty-description">Add at least two accounts for this provider first.</p>`}</div></fieldset><div class="button-row"><button class="btn btn-primary btn-sm" type="button" data-pool-action="create"${draft.busy || !providerAccountsList.length ? " disabled" : ""}>Save failover group</button></div></section>${poolRows ? `<section class="section"><div class="toolbar"><h2 class="section-title">Failover groups</h2><span class="section-hint">A single account works without a group.</span></div><div class="grid-2">${poolRows}</div></section>` : `<div class="panel empty-state"><p class="empty-title">No failover groups</p><p class="empty-description">Create one after adding multiple accounts for the same provider.</p></div>`}`;
  }

  async function createFailoverGroup() {
    const draft = state.poolDraft;
    if (!draft.id.trim() || !draft.provider || draft.accounts.length < 2) {
      notify("error", "Enter a group name and select at least two accounts.");
      return;
    }
    const id = availablePoolId(draft.id);
    draft.busy = true;
    try {
      await applyControlResource("pools", {
        id,
        provider: draft.provider,
        accounts: draft.accounts,
        strategy: draft.strategy,
      });
      const selected = new Set(draft.accounts);
      for (const model of graphModels()) {
        const targets = modelTargets(model);
        const matching = targets.filter((target) =>
          target.provider === draft.provider && target.account && selected.has(target.account));
        if (!matching.length) continue;
        const first = matching[0];
        const poolTarget = targetConfig(first, targets.length);
        poolTarget.id = `pool-target-${id}`.slice(0, 128);
        delete poolTarget.account;
        poolTarget.account_pool = id;
        poolTarget.priority = Math.min(...matching.map((target) => Number(target.priority) || 1));
        const retained = targets
          .filter((target) => !matching.includes(target))
          .map((target, index) => targetConfig(target, index));
        await applyControlResource(
          "models",
          { id: model.id, targets: [...retained, poolTarget] },
          model.id,
        );
      }
      await saveControlChanges();
      draft.id = "";
      draft.accounts = [];
      draft.busy = false;
      notify("success", "Failover group saved and connected to matching models.");
    } catch (error) {
      draft.busy = false;
      if (error.status === 401) authRequired();
      else if (error.status !== 409) notify("error", error.message);
    }
  }

  function renderEndpoints(root) {
    const inventory = state.data.endpointInventory || {};
    const listeners = inventory.listeners || [];
    const management = inventory.management;
    const clientLabels = inventory.downstream_clients || ["Factory Droid", "Vercel fx", "Devin", "Codex", "Claude Code", "Cursor", "generic SDK"];
    const listenerSections = listeners.map((listener) => `<article class="panel endpoint-card"><div class="toolbar"><h2 class="panel-title">${esc(listener.id)}</h2><span class="spacer"></span><span class="badge badge-accent">works with any client</span></div><p class="mono endpoint-base">${(listener.base_urls || []).map((url) => esc(url)).join(" · ") || esc(listener.bind || "local socket")}</p>${(listener.routes || []).map((route) => `<div class="endpoint-route"><div class="toolbar"><span class="badge badge-neutral">${(route.methods || []).join(", ")}</span><code class="mono">${esc(route.path)}</code></div><p class="muted">App authentication: ${route.downstream_auth?.required ? "required" : "none"}</p></div>`).join("")}</article>`).join("");
    const tools = clientLabels.map((label) => `<details class="connect-tool"><summary>${esc(label)}</summary><p>Use the Pooler address shown above in ${esc(label)}. This helper does not change routing.</p><button class="btn btn-outline btn-xs" type="button" data-connect-tool="${esc(label)}">Prepare setup</button></details>`).join("");
    root.innerHTML = `${viewHeader("Endpoints", views.endpoints.subtitle, `<button class="btn btn-outline btn-sm" type="button" data-endpoints-copy>${ic("copy", 15)} Copy details</button>`)}<section class="callout callout-info"><strong>Use Pooler from any app.</strong> These are Pooler’s local addresses—not provider API URLs.</section>${management ? `<details class="panel endpoint-card"><summary><strong>Dashboard API</strong></summary><p class="mono endpoint-base">${(management.base_urls || []).map((url) => esc(url)).join(" · ")}</p><p class="muted">Management key required: ${management.auth?.required ? "yes" : "no"}</p></details>` : ""}<section class="section"><div class="toolbar"><h2 class="section-title">Addresses for your apps</h2><span class="section-hint">Choose the path supported by your app.</span></div><div class="grid-2">${listenerSections || `<div class="panel empty-state"><p class="empty-title">No app endpoints yet</p></div>`}</div></section><section class="panel" aria-labelledby="connect-tools-title"><div class="toolbar"><div><h2 class="panel-title" id="connect-tools-title">Setup helpers</h2><p class="muted">Optional instructions for common apps.</p></div><span class="badge badge-neutral">does not change routing</span></div><div class="connect-tool-list">${tools}</div></section><details class="panel"><summary><strong>Advanced endpoint JSON</strong></summary><pre class="code-block endpoint-json" id="endpoint-json"><code>${esc(JSON.stringify(inventory, null, 2))}</code></pre></details>`;
  }

  function modelTargets(model) {
    const targets = [...(model?.targets || [])];
    const byId = new Map(targets.map((target) => [targetBindingId(target), target]));
    const saved = state.targetOrders[model?.id];
    if (!saved) {
      return targets.sort((left, right) => {
        const priority = (Number(left.priority) || 1) - (Number(right.priority) || 1);
        return priority || targetBindingId(left).localeCompare(targetBindingId(right));
      });
    }
    const ordered = saved.map((id) => byId.get(id)).filter(Boolean);
    targets.forEach((target) => {
      if (!saved.includes(targetBindingId(target))) ordered.push(target);
    });
    return ordered;
  }

  function targetBindingId(target) {
    return target?.binding_id
      || target?.binding?.binding_id
      || target?.id
      || target?.binding?.target_id
      || "";
  }

  function targetConfigId(target, position) {
    return target?.id
      || target?.binding?.target_id
      || target?.binding_id?.split("/").at(-1)
      || `target-${position + 1}`;
  }

  function targetConfig(target, position) {
    const transform = target.profile?.request_transform || "";
    const wireFamily = target.wire_family
      || ({ anthropic_messages: "anthropic", gemini_generate_content: "gemini", xai_chat: "xai", kimi_chat: "kimi" }[transform])
      || "openai";
    const codecs = target.codecs?.length
      ? target.codecs
      : target.profile?.endpoint_variants?.responses
        ? ["decode.openai.responses"]
        : [];
    const value = {
      id: targetConfigId(target, position),
      provider: target.provider,
      priority: Number(target.priority) > 0 ? Number(target.priority) : position + 1,
      upstream_model: target.upstream_model,
      capabilities: target.capabilities || [],
      codecs,
      wire_family: wireFamily,
    };
    for (const key of ["account", "account_pool", "wire_family", "parameters", "context_window", "quantization", "privacy", "zdr", "data_policy", "region", "price", "weight"]) {
      if (target[key] !== undefined && target[key] !== null && target[key] !== "") value[key] = target[key];
    }
    return value;
  }

  function targetAccounts(target) {
    if (target.account) return [target.account];
    const pool = graphPools().find((item) => item.id === target.account_pool);
    return pool?.accounts || [];
  }

  function targetEvidence(target) {
    const accounts = new Set(targetAccounts(target));
    const credentials = controlGraph().health?.credentials || [];
    const health = credentials.filter((entry) => accounts.has(entry.account));
    const liveAccounts = (state.data.accounts?.accounts || []).filter((entry) => accounts.has(entry.id));
    const quota = (controlGraph().quota || []).filter((entry) => accounts.has(entry.identity?.credential || entry.account));
    const healthText = health.length
      ? health.map((entry) => entry.status).join(", ")
      : liveAccounts.length
        ? liveAccounts.map((entry) => entry.status).join(", ")
        : "unknown health";
    const quotaText = quota.length ? quota.map((entry) => entry.state || entry.remaining === undefined ? "quota observed" : `quota ${entry.remaining} remaining`).join(", ") : "unknown quota";
    const provider = graphProviders().find((entry) => entry.id === target.provider);
    return {
      healthText,
      quotaText,
      providerText: provider ? "provider configured" : "provider unknown",
      unknown: (!health.length && !liveAccounts.length) || !quota.length,
    };
  }

  function orderedTargetIds(model) {
    return modelTargets(model).map(targetBindingId);
  }

  async function stageModelTargets(model, targets) {
    const value = { id: model.id, targets: targets.map((target, index) => targetConfig(target, index)) };
    try {
      await applyControlResource("models", value, model.id);
      notify("success", `Target order staged for ${model.id}.`);
    } catch (error) {
      if (error.status === 401) authRequired();
      else if (error.status !== 409) notify("error", error.message);
    }
  }

  function announceTarget(message, focusId = "") {
    state.targetAnnouncement = message;
    state.targetFocus = focusId;
    renderCurrentViewIfVisible();
    if (focusId) requestAnimationFrame(() => $(`[data-target-id="${CSS.escape(focusId)}"]`)?.focus());
  }

  function moveTarget(modelId, targetId, destinationIndex) {
    const model = graphModels().find((item) => item.id === modelId);
    if (!model) return;
    const targets = modelTargets(model);
    const sourceIndex = targets.findIndex((target) => targetBindingId(target) === targetId);
    if (sourceIndex < 0) return;
    const boundedIndex = Math.max(0, Math.min(destinationIndex, targets.length - 1));
    if (sourceIndex === boundedIndex) return;
    const [target] = targets.splice(sourceIndex, 1);
    targets.splice(boundedIndex, 0, target);
    targets.forEach((item, index) => {
      item.priority = index + 1;
    });
    state.targetOrders[modelId] = orderedTargetIds({ ...model, targets });
    state.targetDrag = null;
    announceTarget(`${targetId} moved to priority ${boundedIndex + 1} of ${targets.length}.`, targetId);
    stageModelTargets(model, targets);
  }

  function setTargetPriority(modelId, targetId, priority) {
    const model = graphModels().find((item) => item.id === modelId);
    const value = Number(priority);
    if (!model || !Number.isSafeInteger(value) || value < 1 || value > 2 ** 31 - 1) return;
    const targets = modelTargets(model);
    const target = targets.find((item) => targetBindingId(item) === targetId);
    if (!target) return;
    target.priority = value;
    targets.sort((left, right) => (Number(left.priority) || 1) - (Number(right.priority) || 1) || targetBindingId(left).localeCompare(targetBindingId(right)));
    state.targetOrders[modelId] = orderedTargetIds({ ...model, targets });
    announceTarget(`${targetId} priority set to ${value}.`, targetId);
    stageModelTargets(model, targets);
  }

  function combineTarget(modelId, targetId, withTargetId) {
    const model = graphModels().find((item) => item.id === modelId);
    const targets = model ? modelTargets(model) : [];
    const target = targets.find((item) => targetBindingId(item) === targetId);
    const peer = targets.find((item) => targetBindingId(item) === withTargetId);
    if (!model || !target || !peer) return;
    target.priority = peer.priority;
    state.targetOrders[modelId] = orderedTargetIds({ ...model, targets });
    announceTarget(`${targetId} combined into priority tier ${peer.priority} with ${withTargetId}.`, targetId);
    stageModelTargets(model, targets);
  }

  function renderTargetRows(model) {
    const targets = modelTargets(model);
    return `<ol class="target-order" data-target-model="${esc(model.id)}" aria-label="Provider priority for ${esc(model.id)}">${targets.map((target, index) => {
      const targetId = targetBindingId(target);
      const evidence = targetEvidence(target);
      const capabilities = (target.capabilities || []).slice(0, 6).map((capability) => `<span class="chip">${esc(capability)}</span>`).join(" ");
      const account = target.account || target.account_pool;
      return `<li class="target-row" draggable="true" tabindex="0" data-target-row data-target-model="${esc(model.id)}" data-target-id="${esc(targetId)}" data-target-index="${index}" aria-label="${esc(target.provider)}, priority ${esc(target.priority || index + 1)}"><span class="drag-handle" aria-hidden="true">⋮⋮</span><span class="target-position num">${index + 1}</span>${providerCell(target.provider, false)}${account ? `<span class="chip">${esc(account)}</span>` : ""}<span class="badge ${evidence.unknown ? "badge-warning" : "badge-success"}">${esc(evidence.healthText)}</span><label class="target-priority"><span>Priority</span><input type="number" min="1" max="2147483647" step="1" value="${esc(target.priority || index + 1)}" data-target-priority data-target-model="${esc(model.id)}" data-target-id="${esc(targetId)}"></label><span class="target-actions"><button class="btn btn-ghost btn-xs target-move" type="button" data-target-move="up" data-target-model="${esc(model.id)}" data-target-id="${esc(targetId)}" aria-label="Move ${esc(target.provider)} up"${index === 0 ? " disabled" : ""}>↑</button><button class="btn btn-ghost btn-xs target-move" type="button" data-target-move="down" data-target-model="${esc(model.id)}" data-target-id="${esc(targetId)}" aria-label="Move ${esc(target.provider)} down"${index === targets.length - 1 ? " disabled" : ""}>↓</button><button class="btn btn-ghost btn-xs target-move" type="button" data-target-move="home" data-target-model="${esc(model.id)}" data-target-id="${esc(targetId)}" aria-label="Move ${esc(target.provider)} first"${index === 0 ? " disabled" : ""}>First</button><button class="btn btn-ghost btn-xs target-move" type="button" data-target-move="end" data-target-model="${esc(model.id)}" data-target-id="${esc(targetId)}" aria-label="Move ${esc(target.provider)} last"${index === targets.length - 1 ? " disabled" : ""}>Last</button>${index > 0 ? `<button class="btn btn-outline btn-xs target-combine" type="button" data-target-combine="${esc(targetBindingId(targets[index - 1]))}" data-target-model="${esc(model.id)}" data-target-id="${esc(targetId)}">Same priority</button>` : ""}</span><details><summary>Advanced details</summary><dl class="detail-grid"><div><dt>Provider model</dt><dd class="mono">${esc(text(target.upstream_model))}</dd></div><div><dt>Connection ID</dt><dd class="mono">${esc(targetId)}</dd></div><div><dt>Limits</dt><dd>${esc(evidence.quotaText)}</dd></div><div><dt>Evidence</dt><dd>${esc(evidence.providerText)}</dd></div></dl><div class="target-capabilities">${capabilities || `<span class="muted">Capabilities not verified</span>`}</div></details></li>`;
    }).join("")}</ol>`;
  }

  function syncPolicyEditor() {
    if (state.policyEditor.dirty) return;
    const policy = controlGraph().policies?.[0];
    if (!policy) return;
    const routing = policy.routing || {};
    const preference = routing.preference || {};
    state.policyEditor = {
      ...state.policyEditor,
      id: policy.id || "default",
      strategy: policy.selection?.strategy || "ordered_fallback",
      ranking: preference.price || preference.latency || preference.throughput ? "adaptive" : "deterministic",
      allow: (routing.allow || []).join(", "),
      deny: (routing.deny || []).join(", "),
      allowFallbacks: routing.allow_fallbacks !== false,
      requiredParameters: (routing.required_parameters || []).join(", "),
      requiredCapabilities: (routing.required_capabilities || []).join(", "),
      minimumContext: routing.minimum_context ?? "",
      quantization: (routing.quantization || []).join(", "),
      privacy: routing.privacy || "",
      requireZdr: routing.require_zdr === true,
      dataPolicy: routing.data_policy || "",
      maxPrice: routing.max_price ?? "",
      price: preference.price === true,
      latency: preference.latency === true,
      throughput: preference.throughput === true,
      maxLatency: preference.max_latency_ms ?? "",
      minThroughput: preference.min_throughput ?? "",
      minSamples: preference.min_samples ?? "",
      staleAfter: preference.stale_after_ms ?? "",
    };
  }

  function updatePolicyPreview() {
    const editor = state.policyEditor;
    const preview = $(".policy-preview .muted");
    if (!preview) return;
    preview.textContent = `allow ${editor.allow || "any"} · deny ${editor.deny || "none"} · ${editor.allowFallbacks ? "fallbacks enabled" : "fallbacks disabled"} · ${editor.ranking === "adaptive" ? "adaptive observations" : "deterministic facts"}`;
  }

  function csvValues(value) {
    return String(value || "").split(",").map((item) => item.trim()).filter(Boolean);
  }

  function positiveInteger(value) {
    if (value === "" || value === null || value === undefined) return null;
    const number = Number(value);
    return Number.isSafeInteger(number) && number >= 0 ? number : null;
  }

  function policyConfig() {
    const editor = state.policyEditor;
    const preference = {};
    if (editor.ranking === "adaptive" || editor.price) preference.price = editor.price;
    if (editor.ranking === "adaptive" || editor.latency) preference.latency = editor.latency;
    if (editor.ranking === "adaptive" || editor.throughput) preference.throughput = editor.throughput;
    for (const [key, value] of [["max_latency_ms", editor.maxLatency], ["min_throughput", editor.minThroughput], ["min_samples", editor.minSamples], ["stale_after_ms", editor.staleAfter]]) {
      const number = positiveInteger(value);
      if (number !== null) preference[key] = number;
    }
    const routing = {
      allow: csvValues(editor.allow),
      deny: csvValues(editor.deny),
      allow_fallbacks: editor.allowFallbacks,
      required_parameters: csvValues(editor.requiredParameters),
      required_capabilities: csvValues(editor.requiredCapabilities),
      quantization: csvValues(editor.quantization),
      ...(positiveInteger(editor.minimumContext) ? { minimum_context: positiveInteger(editor.minimumContext) } : {}),
      ...(editor.privacy ? { privacy: editor.privacy } : {}),
      ...(editor.requireZdr ? { require_zdr: true } : {}),
      ...(editor.dataPolicy ? { data_policy: editor.dataPolicy } : {}),
      ...(positiveInteger(editor.maxPrice) !== null ? { max_price: positiveInteger(editor.maxPrice) } : {}),
      ...(Object.keys(preference).length ? { preference } : {}),
    };
    return {
      id: editor.id || "default",
      selection: { strategy: editor.strategy },
      routing,
    };
  }

  async function savePolicyControls() {
    const editor = state.policyEditor;
    if (editor.busy) return;
    editor.busy = true;
    try {
      await applyControlResource("policies", policyConfig(), editor.id || "default");
      editor.dirty = false;
      notify("success", "Routing policy controls staged in the structured draft.");
      await refreshCurrentView();
    } catch (error) {
      if (error.status === 401) authRequired();
      else if (error.status !== 409) notify("error", error.message);
    } finally {
      editor.busy = false;
    }
  }

  function renderPolicyControls() {
    syncPolicyEditor();
    const editor = state.policyEditor;
    const policy = controlGraph().policies?.[0];
    const unknownFacts = !policy || !(policy.routing?.allow || []).length && !(policy.routing?.deny || []).length;
    return `<section class="panel policy-panel" aria-labelledby="policy-controls-title"><div class="toolbar"><div><h2 class="panel-title" id="policy-controls-title">Routing policy</h2><p class="muted">These controls are durable policy fields. Request bodies cannot override them.</p></div><span class="spacer"></span><button class="btn btn-primary btn-sm" type="button" data-policy-action="save"${editor.busy ? " disabled aria-busy=\"true\"" : ""}>Save policy</button></div><div class="form-grid policy-grid"><label class="field"><span class="field-label">Policy ID</span><input data-policy-field="id" value="${esc(editor.id)}" maxlength="128"></label><label class="field"><span class="field-label">Deterministic selection</span><select data-policy-field="strategy"><option value="ordered_fallback"${editor.strategy === "ordered_fallback" ? " selected" : ""}>Ordered fallback</option><option value="fill_first"${editor.strategy === "fill_first" ? " selected" : ""}>Fill first</option><option value="health_weighted"${editor.strategy === "health_weighted" ? " selected" : ""}>Health weighted</option><option value="round_robin"${editor.strategy === "round_robin" ? " selected" : ""}>Round robin</option></select></label><label class="field"><span class="field-label">Ranking mode</span><select data-policy-field="ranking"><option value="deterministic"${editor.ranking === "deterministic" ? " selected" : ""}>Deterministic facts only</option><option value="adaptive"${editor.ranking === "adaptive" ? " selected" : ""}>Adaptive price · latency · throughput</option></select></label><label class="field"><span class="field-label">Provider allow list</span><input data-policy-field="allow" value="${esc(editor.allow)}" placeholder="provider-a, provider-b" autocomplete="off"></label><label class="field"><span class="field-label">Provider deny list</span><input data-policy-field="deny" value="${esc(editor.deny)}" placeholder="provider-c" autocomplete="off"></label><label class="field"><span class="field-label">Maximum verified price</span><input type="number" min="0" step="1" data-policy-field="maxPrice" value="${esc(editor.maxPrice)}" placeholder="micro-USD / million"></label><label class="field"><span class="field-label">Minimum context window</span><input type="number" min="1" step="1" data-policy-field="minimumContext" value="${esc(editor.minimumContext)}"></label><label class="field"><span class="field-label">Required parameters</span><input data-policy-field="requiredParameters" value="${esc(editor.requiredParameters)}" placeholder="streaming, tools"></label><label class="field"><span class="field-label">Required capabilities</span><input data-policy-field="requiredCapabilities" value="${esc(editor.requiredCapabilities)}" placeholder="text, reasoning"></label><label class="field"><span class="field-label">Quantization</span><input data-policy-field="quantization" value="${esc(editor.quantization)}" placeholder="fp16"></label><label class="field"><span class="field-label">Privacy requirement</span><input data-policy-field="privacy" value="${esc(editor.privacy)}" placeholder="zero-retention"></label><label class="field"><span class="field-label">Data policy</span><input data-policy-field="dataPolicy" value="${esc(editor.dataPolicy)}" placeholder="no-training"></label></div><div class="policy-toggles"><label class="toggle-field"><input type="checkbox" data-policy-field="allowFallbacks"${editor.allowFallbacks ? " checked" : ""}>Allow bounded lower-tier failover</label><label class="toggle-field"><input type="checkbox" data-policy-field="requireZdr"${editor.requireZdr ? " checked" : ""}>Require verified zero-data-retention</label><label class="toggle-field"><input type="checkbox" data-policy-field="price"${editor.price ? " checked" : ""}>Prefer verified price</label><label class="toggle-field"><input type="checkbox" data-policy-field="latency"${editor.latency ? " checked" : ""}>Prefer observed latency</label><label class="toggle-field"><input type="checkbox" data-policy-field="throughput"${editor.throughput ? " checked" : ""}>Prefer observed throughput</label></div><div class="policy-preview"><strong>Effective preview</strong><span class="muted">allow ${editor.allow || "any"} · deny ${editor.deny || "none"} · ${editor.allowFallbacks ? "fallbacks enabled" : "fallbacks disabled"} · ${editor.ranking === "adaptive" ? "adaptive observations" : "deterministic facts"}</span></div>${unknownFacts ? `<div class="callout callout-warning" role="status"><strong>Unknown facts stay unknown.</strong> No verified allow/deny or telemetry provenance is available yet; adaptive ranking cannot invent health, quota, price, latency, or throughput evidence.</div>` : `<div class="callout callout-info" role="status"><strong>Provenance.</strong> Hard filters use configured IDs and verified facts. Adaptive preferences use only fresh observations and remain visible in the effective preview.</div>`}</section>`;
  }

  async function loadOAuthCapabilities(account) {
    if (state.oauthCapabilities[account]) return state.oauthCapabilities[account];
    if (state.oauthCapabilityRequests[account]) return state.oauthCapabilityRequests[account];
    const request = readJson(`/accounts/${encodeURIComponent(account)}/oauth-capabilities`)
      .then((result) => {
        state.oauthCapabilities[account] = result;
        return result;
      })
      .catch((error) => {
        if (error.status === 401) authRequired();
        else notify("error", `Could not load sign-in methods: ${error.message}`);
        return null;
      })
      .finally(() => {
        delete state.oauthCapabilityRequests[account];
      });
    state.oauthCapabilityRequests[account] = request;
    return request;
  }

  async function startOAuthFlow(account, method) {
    if (state.oauthFlow.busy) return;
    state.oauthFlow = { account, requestId: null, method, status: "starting", authorizationUrl: "", verificationUri: "", verificationUriComplete: "", userCode: "", expiresAt: Date.now() + 600_000, busy: true };
    try {
      const result = await mutateJson("/oauth/start", "POST", { account, method });
      state.oauthFlow.requestId = result.request_id;
      state.oauthFlow.authorizationUrl = result.authorization_url || "";
      state.oauthFlow.verificationUri = result.verification_uri || "";
      state.oauthFlow.verificationUriComplete = result.verification_uri_complete || "";
      state.oauthFlow.userCode = result.user_code || "";
      state.oauthFlow.expiresAt = result.expires_at_ms || state.oauthFlow.expiresAt;
      state.oauthFlow.status = result.status || (state.oauthFlow.authorizationUrl ? "authorization_required" : "starting");
      state.oauthFlow.busy = false;
      if (state.oauthFlow.authorizationUrl) window.open(state.oauthFlow.authorizationUrl, "pooler-oauth", "popup,width=640,height=760");
      renderCurrentViewIfVisible();
      if (state.oauthFlow.requestId) pollOAuthFlow(state.oauthFlow.requestId, state.sessionGeneration);
    } catch (error) {
      state.oauthFlow.busy = false;
      if (error.status === 401) authRequired();
      else notify("error", `Authentication flow failed: ${error.message}`);
      renderCurrentViewIfVisible();
    }
  }

  async function pollOAuthFlow(requestId, sessionGeneration) {
    for (let attempt = 0; attempt < 300; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 2_000));
      if (sessionGeneration !== state.sessionGeneration || state.oauthFlow.requestId !== requestId) return;
      try {
        const result = await readJson(`/oauth/status/${encodeURIComponent(requestId)}`);
        state.oauthFlow.status = result.status || "failed";
        state.oauthFlow.verificationUri = result.verification_uri || state.oauthFlow.verificationUri;
        state.oauthFlow.verificationUriComplete = result.verification_uri_complete || state.oauthFlow.verificationUriComplete;
        state.oauthFlow.userCode = result.user_code || state.oauthFlow.userCode;
        state.oauthFlow.expiresAt = result.expires_at_ms || state.oauthFlow.expiresAt;
        renderCurrentViewIfVisible();
        if (["succeeded", "failed", "cancelled", "stale_generation", "expired"].includes(state.oauthFlow.status)) {
          state.oauthFlow.busy = false;
          if (state.oauthFlow.status === "succeeded" && state.route === "providers" && state.onboarding.account === state.oauthFlow.account) state.onboarding.phase = "models";
          notify(state.oauthFlow.status === "succeeded" ? "success" : "warning", state.oauthFlow.status === "succeeded" ? "Authentication completed and the credential was stored securely." : `Authentication ended: ${state.oauthFlow.status}.`);
          await refreshCurrentView();
          return;
        }
      } catch (error) {
        state.oauthFlow.busy = false;
        if (error.status === 401) authRequired();
        else notify("error", `Authentication status failed: ${error.message}`);
        return;
      }
    }
    state.oauthFlow.busy = false;
    state.oauthFlow.status = "expired";
    renderCurrentViewIfVisible();
  }

  function oauthCountdown() {
    const remaining = Math.max(0, state.oauthFlow.expiresAt - Date.now());
    return `${Math.ceil(remaining / 1000)}s remaining`;
  }

  function oauthMethodLabel(method) {
    return {
      browser_pkce: "Browser login",
      authorization_code_pkce: "Browser login",
      device_code: "Device code",
      client_credentials: "Service account",
    }[method] || String(method).replaceAll("_", " ");
  }

  function accountOAuthPanel(account) {
    if (!account || account.auth_kind !== "oauth") return "";
    const capabilities = state.oauthCapabilities[account.id];
    const methods = capabilities?.methods || [];
    const flow = state.oauthFlow.account === account.id ? state.oauthFlow : null;
    return `<section class="panel oauth-panel" aria-labelledby="oauth-title"><div class="toolbar"><h2 class="panel-title" id="oauth-title">Sign in to ${esc(account.id)}</h2><span class="spacer"></span>${flow ? statusBadge(flow.status || "starting") : ""}</div><p class="muted">Choose a sign-in method supported by this provider.</p><div class="button-row">${methods.map((method) => `<button class="btn btn-outline btn-sm" type="button" data-oauth-start="${esc(method.method)}" data-oauth-account="${esc(account.id)}"${flow?.busy ? " disabled" : ""}>${esc(oauthMethodLabel(method.method))}</button>`).join("") || `<span class="muted">Loading sign-in methods…</span>`}</div>${flow ? `<div class="callout" role="status">${flow.authorizationUrl ? `<a class="btn btn-primary btn-sm" href="${esc(flow.authorizationUrl)}" target="_blank" rel="noreferrer">Open sign-in page</a>` : ""}${flow.verificationUri ? `<p>Open <a href="${esc(flow.verificationUri)}" target="_blank" rel="noreferrer">${esc(flow.verificationUri)}</a></p>` : ""}${flow.userCode ? `<p>Enter code <code class="mono">${esc(flow.userCode)}</code></p>` : ""}<p>${esc(oauthCountdown())}</p>${flow.requestId && !["succeeded", "failed", "cancelled", "expired"].includes(flow.status) ? `<button class="btn btn-ghost btn-xs" type="button" data-oauth-cancel="${esc(flow.requestId)}">Cancel</button>` : ""}</div>` : ""}</section>`;
  }

  function renderAccounts(root) {
    const accounts = graphAccounts();
    const connectionAccount = accounts.find((account) => account.id === state.connectionAccount);
    const grouped = accounts.map((account) => `<article class="panel account-card"><div class="toolbar"><h2 class="panel-title">${esc(account.id)}</h2><span class="spacer"></span>${statusBadge(account.health?.status || "unknown")}</div><p class="muted">Provider: ${esc(account.provider)}</p><dl class="detail-grid"><div><dt>Sign-in method</dt><dd>${account.auth_kind === "oauth" ? "OAuth" : "API key"}</dd></div><div><dt>Status</dt><dd>${account.enabled === false ? "Disabled" : "Enabled"}</dd></div><div><dt>Recent failures</dt><dd>${fmtInt(account.health?.failure_count)}</dd></div><div><dt>Available again</dt><dd>${account.health?.cooldown_until ? esc(relTime(account.health.cooldown_until)) : "Now"}</dd></div></dl><div class="button-row"><button class="btn btn-primary btn-xs" type="button" data-account-connect="${esc(account.id)}">${account.auth_kind === "oauth" ? "Sign in" : "View"}</button>${account.enabled === false ? `<button class="btn btn-outline btn-xs" type="button" data-account-action="enable" data-account-id="${esc(account.id)}">Enable</button>` : `<button class="btn btn-outline btn-xs" type="button" data-account-action="disable" data-account-id="${esc(account.id)}">Disable</button>`}<button class="btn btn-ghost btn-xs" type="button" data-account-action="refresh" data-account-id="${esc(account.id)}">Refresh</button><button class="btn btn-ghost btn-xs" type="button" data-account-action="revoke" data-account-id="${esc(account.id)}">Sign out</button></div></article>`).join("");
    const quotaRowsSource = (controlGraph().quota || []).length ? controlGraph().quota : (state.data.quota?.windows || []);
    const quotaRows = quotaRowsSource.filter((row) => !connectionAccount || row.identity?.credential === connectionAccount.id || row.account === connectionAccount.id).map((row) => `<li><span class="mono">${esc(row.identity?.credential || row.account || "account")}</span><span class="muted">${esc(row.state || row.unit || "quota")}</span><span class="spacer"></span>${row.remaining === undefined ? "—" : esc(fmtInt(row.remaining))}</li>`).join("");
    root.innerHTML = `${viewHeader("Accounts", views.accounts.subtitle)}${draftBar()}${accountForm()}${grouped ? `<section class="section"><div class="toolbar"><h2 class="section-title">Your accounts</h2><span class="section-hint">Each account keeps its own limits and status.</span></div><div class="grid-2">${grouped}</div></section>` : `<div class="panel empty-state"><p class="empty-title">No accounts</p><p class="empty-description">Add a provider first.</p></div>`}${connectionAccount ? accountOAuthPanel(connectionAccount) : ""}${quotaRows ? `<section class="panel"><h2 class="panel-title">Account limits</h2><ul class="check-list">${quotaRows}</ul></section>` : ""}`;
    bindAccountCreate(root);
    if (connectionAccount && connectionAccount.auth_kind === "oauth" && !state.oauthCapabilities[connectionAccount.id]) loadOAuthCapabilities(connectionAccount.id).then(() => renderCurrentViewIfVisible());
  }

  /* ---------------- Usage ---------------- */

  function renderUsage(root) {
    const metrics = state.data.metrics?.metrics || {};
    const quota = state.data.quota || {};
    const ledger = state.data.usageAggregate || {};
    const retained = ledger.series || [];
    const usage = metrics.usage || [];
    const latencies = metrics.latencies || [];
    const windows = quota.windows || [];
    const cooldowns = quota.cooldowns || [];

    const total = (field) =>
      retained.reduce(
        (value, row) => value + (Number(row.totals?.[field]) || 0),
        0,
      );
    const totalRequests = total("records");
    const inputTokens = total("input_tokens");
    const outputTokens = total("output_tokens");
    const reasoningTokens = total("reasoning_tokens");
    const cacheTokens = total("cache_tokens");
    const mediaUnits =
      total("image_units") + total("audio_units") + total("video_units");
    const costTicks = total("cost_in_usd_ticks");
    const droppedSeriesRecords = Number(ledger.dropped_series_records) || 0;

    const stats = [
      statCard(
        "Requests",
        `<span class="num">${fmtCompact(totalRequests)}</span>`,
        droppedSeriesRecords
          ? "Partial: returned series only"
          : `Retained in ${state.usageRange === "all" ? "all history" : state.usageRange}`,
      ),
      statCard(
        "Input tokens",
        `<span class="num" title="${fmtInt(inputTokens)}">${fmtCompact(inputTokens)}</span>`,
        "Explicitly reported",
      ),
      statCard(
        "Output tokens",
        `<span class="num" title="${fmtInt(outputTokens)}">${fmtCompact(outputTokens)}</span>`,
        "Explicitly reported",
      ),
      statCard(
        "Reasoning / cache",
        `<span class="num" title="${fmtInt(reasoningTokens)} reasoning, ${fmtInt(cacheTokens)} cache">${fmtCompact(reasoningTokens)} / ${fmtCompact(cacheTokens)}</span>`,
        "Explicitly reported",
      ),
      statCard(
        "Media units",
        `<span class="num" title="${fmtInt(mediaUnits)}">${fmtCompact(mediaUnits)}</span>`,
        "Image, audio, and video",
      ),
      statCard(
        "Cost ticks",
        `<span class="num" title="${fmtInt(costTicks)}">${fmtCompact(costTicks)}</span>`,
        "Reported or versioned estimate",
      ),
    ].join("");

    const retainedTable = tableWrap(
      [
        {
          label: "Route",
          mono: true,
          render: (row) => esc(row.dimensions?.route),
        },
        {
          label: "Provider",
          mono: true,
          render: (row) => providerCell(row.dimensions?.provider),
        },
        {
          label: "Model",
          mono: true,
          nowrap: false,
          render: (row) => providerCell(row.dimensions?.upstream_model),
        },
        {
          label: "Result",
          render: (row) => statusBadge(row.dimensions?.result_class),
        },
        {
          label: "Requests",
          align: "right",
          render: (row) =>
            `<span class="num">${fmtInt(row.totals?.records)}</span>`,
        },
        {
          label: "Input / output",
          align: "right",
          render: (row) =>
            `<span class="num">${fmtInt(row.totals?.input_tokens)} / ${fmtInt(row.totals?.output_tokens)}</span>`,
        },
        {
          label: "Reasoning / cache",
          align: "right",
          render: (row) =>
            `<span class="num">${fmtInt(row.totals?.reasoning_tokens)} / ${fmtInt(row.totals?.cache_tokens)}</span>`,
        },
        {
          label: "Media I/A/V",
          align: "right",
          render: (row) =>
            `<span class="num">${fmtInt(row.totals?.image_units)} / ${fmtInt(row.totals?.audio_units)} / ${fmtInt(row.totals?.video_units)}</span>`,
        },
        {
          label: "Latency / TTFT",
          align: "right",
          render: (row) => {
            const count = Number(row.totals?.records) || 0;
            const ttftCount = Number(row.totals?.ttft_records) || 0;
            const latency = count
              ? Math.round(Number(row.totals?.latency_ms || 0) / count)
              : null;
            const ttft = ttftCount
              ? Math.round(Number(row.totals?.ttft_ms || 0) / ttftCount)
              : null;
            return `<span class="num">${latency === null ? "—" : `${fmtInt(latency)} ms`} / ${ttft === null ? "—" : `${fmtInt(ttft)} ms`}</span>`;
          },
        },
        {
          label: "Cost",
          align: "right",
          render: (row) =>
            `<span class="num">${fmtInt(row.totals?.cost_in_usd_ticks)}</span><span class="muted"> ${esc(text(row.dimensions?.cost_provenance))}${row.dimensions?.price_book_version ? ` · ${esc(row.dimensions.price_book_version)}` : ""}</span>`,
        },
      ],
      retained,
      {
        loading: state.loading && !state.data.usageAggregate,
        error: endpointError("usageAggregate"),
        emptyTitle: "No retained usage in this range",
        emptyDescription:
          "Completed requests appear here after usage metadata is recorded.",
      },
    );

    const usageTable = tableWrap(
      [
        { label: "Route", mono: true, render: (u) => esc(u.route) },
        {
          label: "Provider",
          mono: true,
          render: (u) => providerCell(u.provider),
        },
        {
          label: "Model",
          mono: true,
          nowrap: false,
          render: (u) => providerCell(u.model),
        },
        {
          label: "Requests",
          align: "right",
          render: (u) => `<span class="num">${fmtInt(u.requests)}</span>`,
        },
        {
          label: "Input",
          align: "right",
          render: (u) => `<span class="num">${fmtInt(u.input_tokens)}</span>`,
        },
        {
          label: "Output",
          align: "right",
          render: (u) => `<span class="num">${fmtInt(u.output_tokens)}</span>`,
        },
        {
          label: "Total",
          align: "right",
          render: (u) => `<span class="num">${fmtInt(u.total_tokens)}</span>`,
        },
        {
          label: "Cost ticks",
          align: "right",
          render: (u) =>
            `<span class="num">${fmtInt(u.cost_in_usd_ticks)}</span>`,
        },
      ],
      usage,
      {
        loading: state.loading && !state.data.metrics,
        error: endpointError("metrics"),
        emptyTitle: "No usage recorded yet",
        emptyDescription:
          "Token usage appears after the first attributed responses.",
      },
    );

    const windowTable = tableWrap(
      [
        {
          label: "Scope",
          render: (w) =>
            `<span class="badge badge-neutral">${esc(text(w.identity?.kind || w.scope))}</span>`,
        },
        {
          label: "Subject",
          mono: true,
          nowrap: false,
          render: (w) => esc(quotaSubject(w)),
        },
        { label: "Unit", render: (w) => esc(text(w.unit)) },
        { label: "State", render: (w) => statusBadge(w.state) },
        {
          label: "Remaining",
          align: "right",
          render: (w) =>
            `<span class="num">${w.remaining === null || w.remaining === undefined ? "—" : fmtInt(w.remaining)}</span>${w.limit ? `<span class="muted"> / ${fmtInt(w.limit)}</span>` : ""}`,
        },
        {
          label: "Reset",
          render: (w) =>
            w.reset_at_unix_ms
              ? `<span class="num" title="${esc(fmtTime(w.reset_at_unix_ms))}">${esc(relTime(w.reset_at_unix_ms))}</span>`
              : `<span class="muted">—</span>`,
        },
      ],
      windows,
      {
        loading: state.loading && !state.data.quota,
        error: endpointError("quota"),
        emptyTitle: "No quota windows observed",
        emptyDescription:
          "Windows appear when providers report rate-limit state.",
      },
    );

    const cooldownTable = tableWrap(
      [
        {
          label: "Scope",
          render: (c) =>
            `<span class="badge badge-neutral">${esc(text(c.scope))}</span>`,
        },
        { label: "Key", mono: true, nowrap: false, render: (c) => esc(c.key) },
        {
          label: "Until",
          render: (c) =>
            `<span class="num" title="${esc(fmtTime(c.until))}">${esc(relTime(c.until))}</span>`,
        },
        { label: "Reason", nowrap: false, render: (c) => esc(text(c.reason)) },
      ],
      cooldowns,
      {
        loading: state.loading && !state.data.quota,
        error: endpointError("quota"),
        emptyTitle: "No active cooldowns",
      },
    );

    const latencyTable = tableWrap(
      [
        { label: "Route", mono: true, render: (l) => esc(l.route) },
        { label: "Kind", render: (l) => esc(text(l.kind)) },
        {
          label: "Samples",
          align: "right",
          render: (l) =>
            `<span class="num">${fmtInt(l.histogram?.count)}</span>`,
        },
        {
          label: "Mean",
          align: "right",
          render: (l) => {
            const h = l.histogram || {};
            const mean = h.count ? Math.round((h.sum_ms || 0) / h.count) : null;
            return `<span class="num">${mean === null ? "—" : `${fmtInt(mean)} ms`}</span>`;
          },
        },
        {
          label: "Max",
          align: "right",
          render: (l) =>
            `<span class="num">${l.histogram?.max_ms === undefined ? "—" : `${fmtInt(l.histogram.max_ms)} ms`}</span>`,
        },
      ],
      latencies,
      {
        loading: state.loading && !state.data.metrics,
        error: endpointError("metrics"),
        emptyTitle: "No latency samples yet",
      },
    );

    root.innerHTML = `
      ${viewHeader("Usage", views.usage.subtitle)}
      ${persistenceWarning(ledger, "usage_records", "usage")}
      <div class="toolbar">
        <label class="field"><span class="field-label">Time range</span><select id="usage-range">
          ${[
            ["1h", "Last hour"],
            ["24h", "Last 24 hours"],
            ["7d", "Last 7 days"],
            ["30d", "Last 30 days"],
            ["all", "All retained"],
          ]
            .map(
              ([value, label]) =>
                `<option value="${value}"${value === state.usageRange ? " selected" : ""}>${label}</option>`,
            )
            .join("")}
        </select></label>
        <button class="btn btn-secondary btn-sm" type="button" id="usage-export">${ic("cloud-download", 15)} Export JSON</button>
      </div>
      ${droppedSeriesRecords ? `<div class="callout callout-warning" role="status"><strong>Partial totals.</strong> ${fmtInt(droppedSeriesRecords)} retained records were omitted after the ${fmtInt(ledger.max_series || 256)}-series cardinality bound. Select a narrower time range before using these totals.</div>` : ""}
      <section class="grid-stats">${stats}</section>
      ${section("Historical usage ledger", retainedTable, `At most ${fmtInt(ledger.max_series || 256)} bounded series are returned. Cost provenance and price-book versions remain distinct.`)}
      ${section("Live process counters", usageTable, "Compatibility counters since this process started.")}
      <div class="grid-2">
        ${section("Quota windows", windowTable)}
        ${section("Cooldowns", cooldownTable)}
      </div>
      ${section("Latency", latencyTable)}`;

    $("#usage-range", root)?.addEventListener("change", (event) => {
      state.usageRange = event.target.value;
      refreshCurrentView();
    });
    $("#usage-export", root)?.addEventListener("click", async (event) => {
      const button = event.currentTarget;
      button.disabled = true;
      try {
        await downloadExport(
          state.sessionGeneration,
          usageExportPath(),
          `pooler-usage-${state.usageRange}`,
        );
      } catch (error) {
        if (error.status === 401) authRequired();
        else notify("error", `Usage export failed: ${error.message}`);
      } finally {
        button.disabled = false;
      }
    });
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

  function requestExplorerPath(cursor = "", limit = 50) {
    const filters = state.requestExplorer;
    const query = new URLSearchParams({ limit: String(limit) });
    if (filters.route) query.set("route", filters.route);
    if (filters.provider) query.set("provider", filters.provider);
    if (filters.status) query.set("status", filters.status);
    if (cursor) query.set("cursor", cursor);
    return `/requests?${query.toString()}`;
  }

  async function refreshRequestExplorer({ append = false } = {}) {
    const explorer = state.requestExplorer;
    if (explorer.busy) return;
    explorer.busy = true;
    renderRequests($("#view"));
    try {
      const current = state.data.requests || { requests: [] };
      const page = await readJson(
        requestExplorerPath(append ? current.next_cursor : ""),
      );
      state.data.requests = append
        ? {
            ...page,
            requests: [...(current.requests || []), ...(page.requests || [])],
          }
        : page;
      state.errors.requests = null;
    } catch (error) {
      if (error.status === 401) authRequired();
      else state.errors.requests = error.message;
    } finally {
      explorer.busy = false;
      if (state.route === "requests") renderRequests($("#view"));
    }
  }

  async function loadRequestTimeline(requestId) {
    const explorer = state.requestExplorer;
    if (explorer.busy) return;
    explorer.busy = true;
    renderRequests($("#view"));
    try {
      const result = await readJson(
        `/requests/${encodeURIComponent(requestId)}/timeline`,
      );
      explorer.timeline = { [requestId]: result.timeline || [] };
    } catch (error) {
      if (error.status === 401) authRequired();
      else notify("error", error.message);
    } finally {
      explorer.busy = false;
      if (state.route === "requests") renderRequests($("#view"));
    }
  }

  async function exportRequestExplorer() {
    const explorer = state.requestExplorer;
    if (explorer.busy) return;
    explorer.busy = true;
    renderRequests($("#view"));
    try {
      const path = requestExplorerPath("", 4096).replace(
        "/requests?",
        "/requests/export?",
      );
      await downloadExport(
        state.sessionGeneration,
        path,
        "pooler-request-history",
      );
      notify("success", "Redacted request history exported.");
    } catch (error) {
      if (error.status === 401) authRequired();
      else notify("error", error.message);
    } finally {
      explorer.busy = false;
      if (state.route === "requests") renderRequests($("#view"));
    }
  }

  function renderRequests(root) {
    const explorer = state.requestExplorer;
    const page = state.data.requests || {};
    const requests = page.requests || [];
    const timelineEntries = Object.entries(explorer.timeline);
    const filters = `
      <div class="panel">
        <div class="form-grid">
          <label class="field"><span class="field-label">Route</span><input data-request-filter="route" value="${esc(explorer.route)}" maxlength="128" autocomplete="off"></label>
          <label class="field"><span class="field-label">Provider</span><input data-request-filter="provider" value="${esc(explorer.provider)}" maxlength="128" autocomplete="off"></label>
          <label class="field"><span class="field-label">Status or class</span><input data-request-filter="status" value="${esc(explorer.status)}" maxlength="64" autocomplete="off" placeholder="200 or upstream_error"></label>
        </div>
        <div class="toolbar spaced-top-sm">
          <button class="btn btn-primary btn-sm" type="button" data-request-action="apply"${explorer.busy ? ' disabled aria-busy="true"' : ""}>Apply filters</button>
          <button class="btn btn-outline btn-sm" type="button" data-request-action="clear"${explorer.busy ? " disabled" : ""}>Clear</button>
          <span class="spacer"></span>
          <button class="btn btn-outline btn-sm" type="button" data-request-action="export"${explorer.busy ? " disabled" : ""}>${ic("cloud-download", 15)} Export redacted requests</button>
        </div>
      </div>`;
    const requestTable = tableWrap(
      [
        {
          label: "Updated",
          render: (request) =>
            `<span class="num muted" title="${esc(fmtTime(request.updated_at))}">${esc(relTime(request.updated_at))}</span>`,
        },
        {
          label: "Request",
          mono: true,
          render: (request) =>
            `<button class="link-button mono" type="button" data-request-id="${esc(request.request_id)}" aria-label="Load timeline for ${esc(request.request_id)}">${esc(shortId(request.request_id, 16))}</button>`,
        },
        {
          label: "Route",
          mono: true,
          render: (request) => esc(text(request.route)),
        },
        {
          label: "Model",
          mono: true,
          render: (request) => esc(text(request.public_model)),
        },
        {
          label: "Provider",
          mono: true,
          render: (request) => providerCell(request.provider),
        },
        {
          label: "Account",
          mono: true,
          render: (request) => esc(text(request.account_pseudonym)),
        },
        {
          label: "Attempts",
          align: "right",
          render: (request) =>
            `<span class="num">${fmtInt(request.attempts)}</span>`,
        },
        {
          label: "Status",
          render: (request) =>
            statusBadge(request.status ?? request.error_class),
        },
        {
          label: "TTFT",
          align: "right",
          render: (request) =>
            `<span class="num">${request.ttft_ms == null ? "—" : `${fmtInt(request.ttft_ms)} ms`}</span>`,
        },
        {
          label: "Latency",
          align: "right",
          render: (request) =>
            `<span class="num">${request.latency_ms == null ? "—" : `${fmtInt(request.latency_ms)} ms`}</span>`,
        },
      ],
      requests,
      {
        loading: state.loading && !state.data.requests,
        error: endpointError("requests"),
        emptyTitle: "No retained requests",
        emptyDescription:
          "Metadata-only request timelines appear here. Prompts and responses are never retained.",
      },
    );
    const timelines = timelineEntries.length
      ? timelineEntries
          .map(([requestId, events]) =>
            section(
              `Timeline ${shortId(requestId, 24)}`,
              tableWrap(
                [
                  {
                    label: "Phase",
                    render: (event) =>
                      `<span class="badge badge-neutral">${esc(text(event.kind))}</span>`,
                  },
                  {
                    label: "Time",
                    render: (event) =>
                      `<span class="num muted">${esc(fmtTime(event.recorded_at))}</span>`,
                  },
                  {
                    label: "Provider",
                    mono: true,
                    render: (event) => providerCell(event.provider),
                  },
                  {
                    label: "Attempt",
                    align: "right",
                    render: (event) =>
                      `<span class="num">${fmtInt(event.attempt)}</span>`,
                  },
                  {
                    label: "Status",
                    render: (event) =>
                      statusBadge(event.status ?? event.error_class),
                  },
                  {
                    label: "Retry / effects",
                    nowrap: false,
                    render: (event) =>
                      esc(
                        [
                          event.retry_reason,
                          event.quota_effect,
                          event.cooldown_effect,
                        ]
                          .filter(Boolean)
                          .join(" · ") || "—",
                      ),
                  },
                  {
                    label: "Latency",
                    align: "right",
                    render: (event) =>
                      `<span class="num">${event.latency_ms == null ? "—" : `${fmtInt(event.latency_ms)} ms`}</span>`,
                  },
                ],
                events,
                { emptyTitle: "Timeline is empty" },
              ),
              "All phases use the same logical request ID. Values are metadata-only and server-redacted.",
            ),
          )
          .join("")
      : `<div class="panel empty"><h2 class="section-title">Select a request</h2><p class="muted">Load its admission-to-completion timeline without exposing request or response content.</p></div>`;
    root.innerHTML = `
      ${viewHeader("Request explorer", views.requests.subtitle)}
      ${persistenceWarning(page, "request_events", "request history")}
      ${filters}
      ${section("Retained requests", requestTable, `${fmtInt(page.retention?.max_events)} total events · ${fmtInt(page.retention?.max_events_per_request)} per request · ${fmtInt(page.retention?.ttl_ms)} ms retention`)}
      ${page.next_cursor ? `<div class="toolbar"><button class="btn btn-outline btn-sm" type="button" data-request-action="more"${explorer.busy ? ' disabled aria-busy="true"' : ""}>Load more</button></div>` : ""}
      ${timelines}`;
  }

  function renderOperations(root) {
    const health = state.data.health || {};
    const decisions = state.data.decisions?.decisions || [];
    const traces = state.data.traces?.traces || [];
    const audit = state.data.audit?.events || [];
    const reloads = state.data.reloads?.reloads || [];
    const mutationCapable =
      health.management?.mutations === true && !state.errors.health;
    const droppedTraces = state.data.traces?.dropped || 0;

    const runtimeControls = mutationCapable
      ? `
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

    const reloadTable = tableWrap(
      [
        {
          label: "Request",
          mono: true,
          render: (r) => esc(text(r.request_id)),
        },
        {
          label: "Kind",
          render: (r) =>
            `<span class="badge badge-neutral">${esc(text(r.kind))}</span>`,
        },
        { label: "Status", render: (r) => statusBadge(r.status) },
        {
          label: "Requested",
          render: (r) =>
            `<span class="num muted" title="${esc(fmtTime(r.requested_at_ms))}">${esc(relTime(r.requested_at_ms))}</span>`,
        },
        {
          label: "Completed",
          render: (r) =>
            r.completed_at_ms
              ? `<span class="num muted" title="${esc(fmtTime(r.completed_at_ms))}">${esc(relTime(r.completed_at_ms))}</span>`
              : `<span class="muted">—</span>`,
        },
        {
          label: "Accepted generation",
          align: "right",
          render: (r) =>
            `<span class="num">${fmtInt(r.accepted_configuration_generation ?? r.configuration_generation)}</span>`,
        },
        {
          label: "Result generation",
          align: "right",
          render: (r) =>
            `<span class="num">${fmtInt(r.configuration_generation)}</span>`,
        },
        {
          label: "Catalog generation",
          align: "right",
          render: (r) =>
            `<span class="num">${fmtInt(r.catalog_generation)}</span>`,
        },
      ],
      [...reloads].reverse(),
      {
        loading: state.loading && !state.data.reloads,
        error: endpointError("reloads"),
        emptyTitle: "No reload requests yet",
        emptyDescription:
          "Accepted configuration and catalog reloads appear here with their final outcome.",
      },
    );

    const decisionTable = tableWrap(
      [
        {
          label: "Time",
          render: (d) =>
            `<span class="num muted" title="${esc(fmtTime(d.recorded_at))}">${esc(relTime(d.recorded_at))}</span>`,
        },
        {
          label: "Request",
          mono: true,
          render: (d) =>
            `<span title="${esc(d.request_id)}">${esc(shortId(d.request_id))}</span>`,
        },
        { label: "Route", mono: true, render: (d) => esc(d.route_id) },
        {
          label: "Model",
          mono: true,
          nowrap: false,
          render: (d) => providerCell(d.model),
        },
        {
          label: "Selected",
          mono: true,
          nowrap: false,
          render: (d) => providerCell(d.selected_provider),
        },
        {
          label: "Credential",
          mono: true,
          render: (d) => esc(text(d.selected_credential)),
        },
        {
          label: "Attempt",
          align: "right",
          render: (d) => `<span class="num">${fmtInt(d.attempt)}</span>`,
        },
        {
          label: "Candidates",
          align: "right",
          render: (d) =>
            `<span class="num muted">${fmtInt((d.candidates || []).length)}</span>`,
        },
        { label: "Reason", nowrap: false, render: (d) => esc(text(d.reason)) },
      ],
      [...decisions].reverse(),
      {
        loading: state.loading && !state.data.decisions,
        error: endpointError("decisions"),
        emptyTitle: "No routing decisions recorded",
        emptyDescription:
          "Decisions appear as requests flow through the proxy.",
        rowKey: (d, i) => String(d.id || i),
        expandable: (d) => `
        <div class="detail-content">
          ${tableWrap(
            [
              {
                label: "Provider",
                mono: true,
                render: (c) => providerCell(c.provider_id),
              },
              {
                label: "Credential",
                mono: true,
                render: (c) => esc(text(c.credential_id)),
              },
              {
                label: "Score",
                align: "right",
                render: (c) => `<span class="num">${fmtInt(c.score)}</span>`,
              },
              {
                label: "Eligible",
                render: (c) =>
                  c.eligible
                    ? statusBadge("eligible", "success")
                    : statusBadge("ineligible", "muted"),
              },
              {
                label: "Reason",
                nowrap: false,
                render: (c) => esc(text(c.reason)),
              },
            ],
            d.candidates || [],
            { emptyTitle: "No candidates recorded" },
          )}
        </div>`,
      },
    );

    const traceTable = tableWrap(
      [
        {
          label: "Time",
          render: (t) =>
            `<span class="num muted" title="${esc(fmtTime(t.timestamp_ms))}">${esc(relTime(t.timestamp_ms))}</span>`,
        },
        {
          label: "Stage",
          render: (t) =>
            `<span class="badge badge-neutral">${esc(text(t.stage))}</span>`,
        },
        { label: "Route", mono: true, render: (t) => esc(text(t.route)) },
        {
          label: "Provider",
          mono: true,
          render: (t) => providerCell(t.provider),
        },
        {
          label: "Attempt",
          align: "right",
          render: (t) =>
            `<span class="num">${t.attempt === undefined ? "—" : fmtInt(t.attempt)}</span>`,
        },
        {
          label: "Duration",
          align: "right",
          render: (t) =>
            `<span class="num">${t.duration_ms === undefined || t.duration_ms === null ? "—" : `${fmtInt(t.duration_ms)} ms`}</span>`,
        },
        { label: "Outcome", render: (t) => statusBadge(t.outcome) },
      ],
      [...traces].reverse(),
      {
        loading: state.loading && !state.data.traces,
        error: endpointError("traces"),
        emptyTitle: "No traces recorded",
        emptyDescription: "Bounded, redacted runtime traces appear here.",
      },
    );

    const auditTable = tableWrap(
      [
        {
          label: "Time",
          render: (e) =>
            `<span class="num muted" title="${esc(fmtTime(e.timestamp_ms))}">${esc(relTime(e.timestamp_ms))}</span>`,
        },
        { label: "Action", mono: true, render: (e) => esc(text(e.action)) },
        {
          label: "Subject",
          mono: true,
          nowrap: false,
          render: (e) => esc(text(e.subject)),
        },
        { label: "Outcome", render: (e) => statusBadge(e.outcome) },
      ],
      [...audit].reverse(),
      {
        loading: state.loading && !state.data.audit,
        error: endpointError("audit"),
        emptyTitle: "No management mutations yet",
        emptyDescription:
          "Audit events are process-local and reset on restart.",
      },
    );

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
      [
        "Configuration generation",
        text(
          health.configuration_generation ??
            state.data.routes?.configuration_generation,
        ),
      ],
      [
        "Catalog generation",
        catalog.catalog_generation ? text(catalog.catalog_generation) : "—",
      ],
      [
        "Catalog refreshed",
        catalog.catalog_refreshed_at_unix_ms
          ? `${fmtTime(catalog.catalog_refreshed_at_unix_ms)} (${relTime(catalog.catalog_refreshed_at_unix_ms)})`
          : "—",
      ],
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
      message: error.status
        ? `${error.status} — ${error.message}`
        : error.message,
    }));
    const errorPanel = `
      <div class="panel">
        <h2 class="section-title">Endpoint errors</h2>
        <p class="section-hint spaced-top-xs">Errors observed by this dashboard in the current session, including unavailable state stores and rejected reloads.</p>
        <div class="spaced-top-md">
          ${tableWrap(
            [
              { label: "Endpoint", mono: true, render: (e) => esc(e.endpoint) },
              { label: "Error", nowrap: false, render: (e) => esc(e.message) },
            ],
            errorRows,
            {
              emptyTitle: "No errors observed",
              emptyDescription:
                "Every management endpoint answered successfully in this session.",
            },
          )}
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

  async function runMutation(
    path,
    { confirm, successMessage, queuedMessage, waitForResult },
    trigger,
  ) {
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
      if (waitForResult) await waitForResult(result);
      if (sessionGeneration !== state.sessionGeneration) return;
      changed = true;
      if (
        (result.status === "queued" || result.status === "pending") &&
        queuedMessage
      ) {
        notify("info", queuedMessage(result));
      } else {
        notify("success", successMessage ? successMessage(result) : "Done.");
      }
    } catch (error) {
      if (sessionGeneration !== state.sessionGeneration) return;
      if (error.status === 401) {
        authRequired();
      } else {
        notify("error", error.message);
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
    if (changed && sessionGeneration === state.sessionGeneration)
      await refreshCurrentView();
  }

  function accountAction(accountId, action, provider, trigger) {
    const path = `/accounts/${encodeURIComponent(accountId)}/${action}`;
    const label = action.charAt(0).toUpperCase() + action.slice(1);
    if (action === "revoke") {
      return runMutation(
        path,
        {
          confirm: {
            title: `Revoke ${accountId}?`,
            copy: `Pooler removes its local credential payload for <span class="mono">${esc(accountId)}</span> and disables the account. Provider-side revocation only happens when the provider flow performs it.`,
            acceptLabel: "Revoke",
            destructive: true,
          },
          queuedMessage: () =>
            `Revocation queued for ${accountId}. The result lands in the audit log under Operations.`,
          successMessage: () => `Revoked ${accountId}.`,
        },
        trigger,
      );
    }
    if (action === "refresh") {
      return runMutation(
        path,
        {
          queuedMessage: () =>
            `Refresh queued for ${accountId}. The result lands in the audit log under Operations.`,
          successMessage: () => `Refresh requested for ${accountId}.`,
        },
        trigger,
      );
    }
    return runMutation(
      path,
      { successMessage: () => `${label}d ${accountId}.` },
      trigger,
    );
  }

  function modelAction(modelId, action, trigger) {
    const path = `/models/${modelPath(modelId)}/${action}`;
    return runMutation(
      path,
      {
        successMessage: () =>
          `${action === "enable" ? "Enabled" : "Disabled"} ${esc(modelId)}.`,
      },
      trigger,
    );
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
    return Boolean(
      active &&
        root.contains(active) &&
        active.matches(
          "a, button, input, select, textarea, summary, [tabindex]:not([tabindex='-1'])",
        ),
    );
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
      if (
        document.visibilityState === "visible" &&
        state.authState !== "required"
      ) {
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
    const activeNavigation = document.querySelector('.nav-link[aria-current="page"]');
    const navigation = activeNavigation?.parentElement;
    if (activeNavigation && navigation && navigation.scrollWidth > navigation.clientWidth) {
      const left = activeNavigation.offsetLeft;
      const right = left + activeNavigation.offsetWidth;
      if (left < navigation.scrollLeft) navigation.scrollLeft = left;
      else if (right > navigation.scrollLeft + navigation.clientWidth) {
        navigation.scrollLeft = right - navigation.clientWidth;
      }
    }
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
    $("#token-visibility").title = "Show management key";

    document.addEventListener("click", (event) => {
      document
        .querySelectorAll("details.menu[open]")
        .forEach((menu) => {
          if (!menu.contains(event.target)) menu.removeAttribute("open");
        });
    });

    document.addEventListener("keydown", (event) => {
      if (event.key !== "Escape") return;
      if (state.targetDrag) {
        state.targetOrders[state.targetDrag.modelId] = [...state.targetDrag.original];
        state.targetAnnouncement = "Target drag cancelled; the previous order was restored.";
        state.targetFocus = state.targetDrag.targetId;
        state.targetDrag = null;
        event.preventDefault();
        renderCurrentViewIfVisible();
        requestAnimationFrame(() => $(`[data-target-id="${CSS.escape(state.targetFocus)}"]`)?.focus());
        return;
      }
      const menu = document.querySelector("details.menu[open]");
      if (!menu) return;
      event.preventDefault();
      menu.removeAttribute("open");
      menu.querySelector("summary")?.focus();
    });

    $(".skip-link").addEventListener("click", (event) => {
      event.preventDefault();
      requestAnimationFrame(() => $("#main").focus());
    });

    $("#theme-toggle").addEventListener("click", () => {
      const rootEl = document.documentElement;
      const dark =
        rootEl.classList.contains("dark") ||
        (!rootEl.classList.contains("light") &&
          window.matchMedia("(prefers-color-scheme: dark)").matches);
      rootEl.classList.toggle("dark", !dark);
      rootEl.classList.toggle("light", dark);
      updateThemeIcon();
    });
    window
      .matchMedia("(prefers-color-scheme: dark)")
      .addEventListener("change", updateThemeIcon);
    updateThemeIcon();

    $("#refresh-now").addEventListener("click", () => refreshCurrentView());
    $("#session-button").addEventListener("click", openSessionDialog);
    document.querySelectorAll("[data-close]").forEach((button) => {
      button.addEventListener("click", () =>
        $("#" + button.dataset.close).close(),
      );
    });

    $("#token-apply").addEventListener("click", () => {
      state.sessionGeneration += 1;
      state.pending.clear();
      clearConfigurationDraft();
      invalidateReads({ clearData: true });
      state.token = $("#token-input").value.trim();
      state.authState = state.token ? "checking" : "anonymous";
      state.authPrompted = false;
      $('[data-notice="auth"]')?.remove();
      $("#session-dialog").close();
      updateHeader();
      refreshCurrentView().then((loaded) => {
        if (loaded) startPolling();
      });
    });
    $("#token-input").addEventListener("keydown", (event) => {
      if (event.key === "Enter") $("#token-apply").click();
    });
    $("#token-clear").addEventListener("click", () => {
      state.sessionGeneration += 1;
      state.pending.clear();
      clearConfigurationDraft();
      invalidateReads({ clearData: true });
      state.token = "";
      state.authState = "anonymous";
      state.authPrompted = false;
      $("#token-input").value = "";
      $('[data-notice="auth"]')?.remove();
      $("#session-dialog").close();
      updateHeader();
      refreshCurrentView().then((loaded) => {
        if (loaded) startPolling();
      });
    });
    $("#token-visibility").addEventListener("click", () => {
      const input = $("#token-input");
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      $("#token-visibility").innerHTML = ic(show ? "eye-off" : "eye-empty", 16);
      $("#token-visibility").setAttribute(
        "aria-label",
        show ? "Hide management key" : "Show management key",
      );
      $("#token-visibility").title = show
        ? "Hide management key"
        : "Show management key";
      input.focus();
    });

    $("#view").addEventListener("click", (event) => {
      const openSession = event.target.closest("[data-open-session]");
      if (openSession) {
        openSessionDialog();
        return;
      }

      const controlAction = event.target.closest("[data-control-action]");
      if (controlAction) {
        controlDraftAction(controlAction.dataset.controlAction);
        return;
      }

      const providerAction = event.target.closest("[data-provider-action]");
      if (providerAction) {
        if (providerAction.dataset.providerAction === "show-form") {
          state.providerDraft.visible = true;
          state.providerDraft.template = "openai";
          state.providerDraft.name = "";
          state.providerDraft.origin = "";
          state.providerDraft.clientId = "";
          state.providerDraft.protocol = "openai";
          state.providerDraft.modelIds = "";
          renderProviders($("#view"));
        } else if (providerAction.dataset.providerAction === "show-custom") {
          state.providerDraft.visible = true;
          state.providerDraft.template = "__custom";
          state.providerDraft.name = "";
          state.providerDraft.origin = "";
          state.providerDraft.clientId = "";
          state.providerDraft.protocol = "openai";
          state.providerDraft.modelIds = "";
          renderProviders($("#view"));
        } else if (providerAction.dataset.providerAction === "create") {
          createProvider();
        }
        return;
      }

      const providerChoice = event.target.closest("[data-onboarding-provider]");
      if (providerChoice) {
        state.onboarding.provider = providerChoice.dataset.onboardingProvider;
        state.onboarding.phase = "account";
        state.onboarding.selectedModels = new Set();
        state.onboarding.modelsInitialized = false;
        state.accountDraft.provider = state.onboarding.provider;
        renderProviders($("#view"));
        return;
      }

      const onboardingAction = event.target.closest("[data-onboarding-action]");
      if (onboardingAction) {
        const action = onboardingAction.dataset.onboardingAction;
        if (action === "close") {
          state.onboarding.provider = "";
          state.onboarding.providerDetails = null;
          state.onboarding.phase = "provider";
        } else if (action === "discover") {
          discoverVerifiedModels();
          return;
        } else if (action === "review") {
          state.onboarding.phase = "review";
        } else if (action === "continue-models") {
          state.onboarding.phase = "models";
        } else if (action === "save-models") {
          saveModelExposure();
          return;
        } else if (action === "save-manual-models") {
          saveManualModels();
          return;
        }
        renderProviders($("#view"));
        return;
      }

      const targetMove = event.target.closest("[data-target-move]");
      if (targetMove) {
        const model = graphModels().find((item) => item.id === targetMove.dataset.targetModel);
        const targets = model ? modelTargets(model) : [];
        const index = targets.findIndex((target) => targetBindingId(target) === targetMove.dataset.targetId);
        if (index >= 0) {
          const destination = { up: index - 1, down: index + 1, home: 0, end: targets.length - 1 }[targetMove.dataset.targetMove];
          moveTarget(targetMove.dataset.targetModel, targetMove.dataset.targetId, destination);
        }
        return;
      }

      const targetCombine = event.target.closest("[data-target-combine]");
      if (targetCombine) {
        combineTarget(targetCombine.dataset.targetModel, targetCombine.dataset.targetId, targetCombine.dataset.targetCombine);
        return;
      }

      const policyAction = event.target.closest("[data-policy-action]");
      if (policyAction && policyAction.dataset.policyAction === "save") {
        savePolicyControls();
        return;
      }

      const modelSelection = event.target.closest("[data-model-selection]");
      if (modelSelection) {
        const action = modelSelection.dataset.modelSelection;
        const models = graphModels();
        if (action === "all") {
          state.onboarding.selectedModels = new Set(models.map((model) => model.id));
          state.onboarding.modelsInitialized = true;
        } else if (action === "none") {
          state.onboarding.selectedModels = new Set();
          state.onboarding.modelsInitialized = true;
        }
        else if (action === "save") saveModelExposure();
        renderCurrentViewIfVisible();
        return;
      }

      const poolAction = event.target.closest("[data-pool-action]");
      if (poolAction && poolAction.dataset.poolAction === "create") {
        createFailoverGroup();
        return;
      }

      const oauthStart = event.target.closest("[data-oauth-start]");
      if (oauthStart) {
        startOAuthFlow(oauthStart.dataset.oauthAccount, oauthStart.dataset.oauthStart);
        return;
      }
      const oauthCancel = event.target.closest("[data-oauth-cancel]");
      if (oauthCancel) {
        mutate(`/oauth/cancel/${encodeURIComponent(oauthCancel.dataset.oauthCancel)}`)
          .then(() => {
            state.oauthFlow.status = "cancelled";
            state.oauthFlow.busy = false;
            renderCurrentViewIfVisible();
          })
          .catch((error) => {
            if (error.status === 401) authRequired();
            else notify("error", error.message);
          });
        return;
      }

      const endpointsCopy = event.target.closest("[data-endpoints-copy]");
      if (endpointsCopy) {
        const payload = JSON.stringify(state.data.endpointInventory || {}, null, 2);
        Promise.resolve(navigator.clipboard?.writeText(payload)).then(
          () => notify("success", "Endpoint inventory copied."),
          () => notify("warning", "Clipboard access was unavailable; use the machine-readable block below."),
        );
        return;
      }

      const connectTool = event.target.closest("[data-connect-tool]");
      if (connectTool) {
        prepareExplicitRouteDraft(connectTool.dataset.connectTool);
        return;
      }

      const requestId = event.target.closest("[data-request-id]");
      if (requestId) {
        loadRequestTimeline(requestId.dataset.requestId);
        return;
      }
      const requestAction = event.target.closest("[data-request-action]");
      if (requestAction) {
        const action = requestAction.dataset.requestAction;
        if (action === "apply") refreshRequestExplorer();
        else if (action === "more") refreshRequestExplorer({ append: true });
        else if (action === "export") exportRequestExplorer();
        else if (action === "clear") {
          state.requestExplorer.route = "";
          state.requestExplorer.provider = "";
          state.requestExplorer.status = "";
          state.requestExplorer.timeline = {};
          refreshRequestExplorer();
        }
        return;
      }

      const railButton = event.target.closest("[data-models-provider]");
      if (railButton) {
        state.modelsProvider = railButton.dataset.modelsProvider;
        renderModels($("#view"));
        return;
      }

      const configButton = event.target.closest("[data-config-action]");
      if (configButton) {
        configurationAction(configButton.dataset.configAction);
        return;
      }

      const connectionButton = event.target.closest("[data-account-connect]");
      if (connectionButton) {
        state.connectionAccount = connectionButton.dataset.accountConnect;
        renderAccounts($("#view"));
        $("#oauth-title")?.focus();
        return;
      }

      const accountButton = event.target.closest("[data-account-action]");
      if (accountButton) {
        accountButton.closest("details.menu")?.removeAttribute("open");
        accountAction(
          accountButton.dataset.accountId,
          accountButton.dataset.accountAction,
          accountButton.dataset.accountProvider,
          accountButton,
        );
        return;
      }
      const modelButton = event.target.closest("[data-model-action]");
      if (modelButton) {
        if (modelButton.dataset.modelAction === "discover") {
          runMutation(
            "/models/reload",
            {
              waitForResult: (result) => waitForModelReload(result.request_id),
              successMessage: () => "Models updated.",
            },
            modelButton,
          );
          return;
        }
        modelAction(
          modelButton.dataset.modelId,
          modelButton.dataset.modelAction,
          modelButton,
        );
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
        const replacement = Array.from(
          root.querySelectorAll("[data-expand]"),
        ).find((button) => button.dataset.expand === key);
        replacement?.focus();
      }
    });

    $("#view").addEventListener("input", (event) => {
      const policyField = event.target.closest("[data-policy-field]");
      if (policyField && state.route === "models") {
        const field = policyField.dataset.policyField;
        state.policyEditor[field] = policyField.type === "checkbox" ? policyField.checked : policyField.value;
        state.policyEditor.dirty = true;
        updatePolicyPreview();
        return;
      }
      const providerField = event.target.closest("[data-provider-field]");
      if (providerField && state.route === "providers") {
        state.providerDraft[providerField.dataset.providerField] = providerField.value;
        return;
      }
      const accountNewField = event.target.closest("[data-account-new-field]");
      if (accountNewField && (state.route === "accounts" || state.route === "providers")) {
        state.accountDraft[accountNewField.dataset.accountNewField] = accountNewField.value;
        if (["provider", "authKind"].includes(accountNewField.dataset.accountNewField)) {
          renderCurrentViewIfVisible();
        }
        return;
      }
      const poolField = event.target.closest("[data-pool-field]");
      if (poolField && state.route === "pools") {
        state.poolDraft[poolField.dataset.poolField] = poolField.value;
        if (poolField.dataset.poolField === "provider") state.poolDraft.accounts = [];
        return;
      }
      const modelSelection = event.target.closest("[data-model-selection-id]");
      if (modelSelection) {
        const selected = new Set(state.onboarding.selectedModels);
        if (modelSelection.checked) selected.add(modelSelection.dataset.modelSelectionId);
        else selected.delete(modelSelection.dataset.modelSelectionId);
        state.onboarding.selectedModels = selected;
        state.onboarding.modelsInitialized = true;
        return;
      }
      const requestFilter = event.target.closest("[data-request-filter]");
      if (requestFilter && state.route === "requests") {
        state.requestExplorer[requestFilter.dataset.requestFilter] =
          requestFilter.value;
        return;
      }
      const accountDraftField = event.target.closest(
        "[data-account-draft-field]",
      );
      if (accountDraftField && state.route === "accounts") {
        state.accountDraft[accountDraftField.dataset.accountDraftField] =
          accountDraftField.value;
        return;
      }
      const configField = event.target.closest("[data-config-field]");
      if (configField && state.route === "configuration") {
        state.configuration[configField.dataset.configField] =
          configField.value;
        state.configuration.confirmationToken = "";
        return;
      }
    });
    $("#view").addEventListener("change", (event) => {
      const providerField = event.target.closest("[data-provider-field]");
      if (providerField && state.route === "providers") {
        state.providerDraft[providerField.dataset.providerField] = providerField.value;
        if (providerField.dataset.providerField === "template") {
          state.providerDraft.name = "";
          state.providerDraft.origin = "";
          state.providerDraft.clientId = "";
          renderProviders($("#view"));
        }
        return;
      }
      const targetPriority = event.target.closest("[data-target-priority]");
      if (targetPriority) {
        setTargetPriority(targetPriority.dataset.targetModel, targetPriority.dataset.targetId, targetPriority.value);
        return;
      }
      const policyField = event.target.closest("[data-policy-field]");
      if (policyField && state.route === "models") {
        state.policyEditor[policyField.dataset.policyField] = policyField.type === "checkbox" ? policyField.checked : policyField.value;
        state.policyEditor.dirty = true;
        return;
      }
      const accountNewField = event.target.closest("[data-account-new-field]");
      if (accountNewField && state.route === "accounts") {
        const field = accountNewField.dataset.accountNewField;
        state.accountDraft[field] = accountNewField.value;
        if (field === "provider") state.onboarding.provider = accountNewField.value;
        if (field === "provider" || field === "authKind") renderCurrentViewIfVisible();
        return;
      }
      const poolField = event.target.closest("[data-pool-field]");
      if (poolField && state.route === "pools") {
        state.poolDraft[poolField.dataset.poolField] = poolField.value;
        if (poolField.dataset.poolField === "provider") state.poolDraft.accounts = [];
        renderCurrentViewIfVisible();
        return;
      }
      const poolAccount = event.target.closest("[data-pool-account]");
      if (poolAccount && state.route === "pools") {
        const selected = new Set(state.poolDraft.accounts);
        if (poolAccount.checked) selected.add(poolAccount.dataset.poolAccount);
        else selected.delete(poolAccount.dataset.poolAccount);
        state.poolDraft.accounts = [...selected];
        return;
      }
      const accountDraftField = event.target.closest(
        "[data-account-draft-field]",
      );
      if (
        accountDraftField &&
        state.route === "accounts" &&
        accountDraftField.tagName === "SELECT"
      ) {
        state.accountDraft[accountDraftField.dataset.accountDraftField] =
          accountDraftField.value;
        renderAccounts($("#view"));
        return;
      }
      const configField = event.target.closest("[data-config-field]");
      if (
        configField &&
        state.route === "configuration" &&
        configField.tagName === "SELECT"
      ) {
        state.configuration[configField.dataset.configField] =
          configField.value;
        if (configField.dataset.configField === "operation") {
          state.configuration.section =
            configField.value === "replace" ? "catalog" : "models";
        }
        state.configuration.confirmationToken = "";
        renderConfiguration($("#view"));
        return;
      }
    });

    $("#view").addEventListener("keydown", (event) => {
      const row = event.target.closest("[data-target-row]");
      if (!row || !event.altKey) return;
      const model = graphModels().find((item) => item.id === row.dataset.targetModel);
      const targets = model ? modelTargets(model) : [];
      const index = targets.findIndex((target) => targetBindingId(target) === row.dataset.targetId);
      if (index < 0) return;
      const destination = event.key === "ArrowUp" ? index - 1 : event.key === "ArrowDown" ? index + 1 : event.key === "Home" ? 0 : event.key === "End" ? targets.length - 1 : null;
      if (destination === null) return;
      event.preventDefault();
      moveTarget(row.dataset.targetModel, row.dataset.targetId, destination);
    });

    $("#banner-area").addEventListener("click", (event) => {
      if (event.target.closest("[data-open-session]")) openSessionDialog();
    });
  }

  function handleViewAction(action, trigger) {
    if (action === "reload-config") {
      runMutation(
        "/reload",
        {
          confirm: {
            title: "Reload configuration?",
            copy: "The serving process rereads and compiles the configured source. Invalid candidates leave the active generation unchanged.",
            acceptLabel: "Reload",
          },
          queuedMessage: (result) =>
            `Reload request ${result.request_id} accepted. Follow its final outcome in Reload history.`,
          successMessage: () => "Reload requested.",
        },
        trigger,
      );
    } else if (action === "reload-models") {
      runMutation(
        "/models/reload",
        {
          queuedMessage: (result) =>
            `Catalog refresh request ${result.request_id} accepted. Follow its final outcome in Reload history.`,
        },
        trigger,
      );
    } else if (action === "export") {
      const path = "/export";
      if (state.pending.has(path)) return;
      state.pending.add(path);
      trigger.disabled = true;
      trigger.setAttribute("aria-busy", "true");
      const sessionGeneration = state.sessionGeneration;
      downloadExport(sessionGeneration)
        .then((downloaded) => {
          if (downloaded && sessionGeneration === state.sessionGeneration)
            notify("success", "Export downloaded.");
        })
        .catch((error) => {
          if (sessionGeneration !== state.sessionGeneration) return;
          if (error.status === 401) authRequired();
          else notify("error", error.message);
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
    if (
      document.visibilityState === "visible" &&
      state.authState !== "required"
    ) {
      refreshCurrentView({ polling: true });
    }
  });

  bindStaticChrome();
  navigate();
})();
