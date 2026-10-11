const app = document.getElementById("app");
const config = window.AURONTRA_CONFIG || {};
const STORAGE_KEYS = {
  state: "aurontra.oidc.state",
  verifier: "aurontra.oidc.verifier",
  nonce: "aurontra.oidc.nonce",
};
const state = {
  accessToken: null,
  expiresAt: 0,
  activeTab: "overview",
  loading: false,
  authError: "",
  data: { organization: null, devices: null, tickets: null, threats: null, events: null },
  errors: {},
  lastRefreshed: null,
};

function element(tag, text = "", className = "", attrs = {}) {
  const el = document.createElement(tag);
  if (text !== undefined && text !== null) el.textContent = String(text);
  if (className) el.className = className;
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null) continue;
    if (key === "text") continue;
    if (key === "disabled") el.disabled = Boolean(value);
    else if (key === "ariaSelected") el.setAttribute("aria-selected", String(value));
    else if (key === "tabIndex") el.tabIndex = Number(value);
    else el.setAttribute(key, String(value));
  }
  return el;
}

function append(parent, ...children) {
  for (const child of children) if (child) parent.append(child);
  return parent;
}

function actionButton(label, className, handler, disabled = false) {
  const button = element("button", label, className, { type: "button", disabled });
  button.addEventListener("click", handler);
  return button;
}

function configIsReady() {
  return Boolean(
    typeof config.apiBaseUrl === "string" &&
    typeof config.oidcIssuer === "string" &&
    typeof config.oidcClientId === "string" &&
    typeof config.oidcRedirectUri === "string" &&
    config.apiBaseUrl &&
    config.oidcIssuer &&
    config.oidcClientId &&
    config.oidcRedirectUri
  );
}

function safeUrl(value, { allowHttpTest = false } = {}) {
  const url = new URL(value);
  const testHttp = allowHttpTest &&
    config.environment === "test" &&
    url.protocol === "http:" &&
    (url.hostname.endsWith(".test") || url.hostname === "127.0.0.1" || url.hostname === "localhost");
  if (url.protocol !== "https:" && !testHttp) throw new Error("HTTPS endpoint required.");
  if (url.username || url.password || url.search || url.hash) throw new Error("Endpoint URL is not canonical.");
  return url;
}

function randomBase64Url(byteCount = 32) {
  const bytes = crypto.getRandomValues(new Uint8Array(byteCount));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function pkceChallenge(verifier) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  let binary = "";
  for (const byte of new Uint8Array(digest)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function decodeBase64Url(segment) {
  const base64 = String(segment).replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

function parseJwtSegment(segment) {
  return JSON.parse(new TextDecoder().decode(decodeBase64Url(segment)));
}

async function verifyIdToken(token, metadata, expectedNonce) {
  const parts = String(token).split(".");
  if (parts.length !== 3) throw new Error("Invalid identity token.");
  const header = parseJwtSegment(parts[0]);
  if (header.alg !== "RS256" || typeof header.kid !== "string") {
    throw new Error("Unsupported identity-token signature.");
  }
  const jwksUrl = safeUrl(metadata.jwks_uri);
  if (jwksUrl.origin !== new URL(config.oidcIssuer).origin) {
    throw new Error("Identity provider key endpoint origin mismatch.");
  }
  const { response, body } = await fetchJson(jwksUrl.href);
  if (!response.ok || !Array.isArray(body?.keys)) throw new Error("Identity provider keys unavailable.");
  const jwk = body.keys.find(key =>
    key.kid === header.kid &&
    key.kty === "RSA" &&
    key.use !== "enc" &&
    (!key.alg || key.alg === "RS256")
  );
  if (!jwk) throw new Error("No matching identity-token verification key.");
  const publicKey = await crypto.subtle.importKey(
    "jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]
  );
  const validSignature = await crypto.subtle.verify(
    { name: "RSASSA-PKCS1-v1_5" },
    publicKey,
    decodeBase64Url(parts[2]),
    new TextEncoder().encode(parts[0] + "." + parts[1])
  );
  if (!validSignature) throw new Error("Identity-token signature is invalid.");

  const claims = parseJwtSegment(parts[1]);
  const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  const now = Date.now() / 1000;
  if (
    claims.iss !== config.oidcIssuer ||
    !audience.includes(config.oidcClientId) ||
    (audience.length > 1 && claims.azp !== config.oidcClientId) ||
    claims.nonce !== expectedNonce ||
    typeof claims.sub !== "string" || !claims.sub ||
    !Number.isFinite(claims.exp) || claims.exp <= now ||
    !Number.isFinite(claims.iat) || claims.iat > now + 60 ||
    (claims.nbf !== undefined && (!Number.isFinite(claims.nbf) || claims.nbf > now))
  ) {
    throw new Error("Identity-token claims did not match the OIDC transaction.");
  }
  return claims;
}

function withTimeout(ms = 10000) {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), ms);
  return { signal: controller.signal, clear: () => window.clearTimeout(timer) };
}

async function fetchJson(url, options = {}) {
  const timeout = withTimeout();
  try {
    const response = await fetch(url, {
      ...options,
      signal: timeout.signal,
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      referrerPolicy: "no-referrer",
      headers: { Accept: "application/json", ...(options.headers || {}) },
    });
    const body = await response.json().catch(() => null);
    return { response, body };
  } finally {
    timeout.clear();
  }
}

async function discoverOidc() {
  const issuer = safeUrl(config.oidcIssuer);
  const discoveryUrl = new URL(".well-known/openid-configuration", issuer.href.endsWith("/") ? issuer.href : issuer.href + "/");
  const { response, body } = await fetchJson(discoveryUrl.href);
  if (!response.ok || !body || body.issuer !== config.oidcIssuer) {
    throw new Error("Identity provider discovery failed.");
  }
  if (!Array.isArray(body.id_token_signing_alg_values_supported) || !body.id_token_signing_alg_values_supported.includes("RS256")) {
    throw new Error("Identity provider must support RS256 ID-token signatures.");
  }
  for (const key of ["authorization_endpoint", "token_endpoint", "jwks_uri"]) {
    const endpoint = safeUrl(body[key]);
    if (endpoint.origin !== issuer.origin) {
      throw new Error("Identity provider endpoints must share the configured issuer origin.");
    }
  }
  return body;
}

async function signIn() {
  state.authError = "";
  if (!configIsReady()) {
    state.authError = "Console authentication is not configured. Contact your administrator.";
    render();
    return;
  }
  try {
    const metadata = await discoverOidc();
    const verifier = randomBase64Url(48);
    const challenge = await pkceChallenge(verifier);
    const oidcState = randomBase64Url(32);
    const nonce = randomBase64Url(32);
    sessionStorage.setItem(STORAGE_KEYS.state, oidcState);
    sessionStorage.setItem(STORAGE_KEYS.verifier, verifier);
    sessionStorage.setItem(STORAGE_KEYS.nonce, nonce);

    const authorization = new URL(metadata.authorization_endpoint);
    authorization.searchParams.set("response_type", "code");
    authorization.searchParams.set("client_id", config.oidcClientId);
    authorization.searchParams.set("redirect_uri", config.oidcRedirectUri);
    authorization.searchParams.set("scope", "openid profile email");
    authorization.searchParams.set("state", oidcState);
    authorization.searchParams.set("nonce", nonce);
    authorization.searchParams.set("code_challenge", challenge);
    authorization.searchParams.set("code_challenge_method", "S256");
    if (config.oidcAudience) authorization.searchParams.set("audience", config.oidcAudience);
    window.location.assign(authorization.href);
  } catch {
    state.authError = "Unable to reach the configured identity provider. Try again or contact your administrator.";
    render();
  }
}

function clearOidcTransaction() {
  for (const key of Object.values(STORAGE_KEYS)) sessionStorage.removeItem(key);
}

async function handleOidcCallback() {
  const url = new URL(window.location.href);
  const code = url.searchParams.get("code");
  const returnedState = url.searchParams.get("state");
  const providerError = url.searchParams.get("error");
  if (!code && !returnedState && !providerError) return false;

  // Remove authorization response parameters before rendering or making API calls.
  history.replaceState(null, document.title, url.pathname);
  if (providerError) {
    clearOidcTransaction();
    state.authError = "The identity provider did not complete sign-in.";
    render();
    return true;
  }

  const expectedState = sessionStorage.getItem(STORAGE_KEYS.state);
  const verifier = sessionStorage.getItem(STORAGE_KEYS.verifier);
  const nonce = sessionStorage.getItem(STORAGE_KEYS.nonce);
  if (!code || !returnedState || !expectedState || returnedState !== expectedState || !verifier || !nonce) {
    clearOidcTransaction();
    state.authError = "Sign-in could not be validated. Please start again.";
    render();
    return true;
  }

  try {
    const metadata = await discoverOidc();
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: config.oidcClientId,
      code,
      redirect_uri: config.oidcRedirectUri,
      code_verifier: verifier,
    });
    const { response, body: tokenResponse } = await fetchJson(metadata.token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
    if (!response.ok || !tokenResponse || typeof tokenResponse.access_token !== "string" ||
        tokenResponse.token_type?.toLowerCase() !== "bearer" ||
        !Number.isFinite(tokenResponse.expires_in) || tokenResponse.expires_in <= 0 ||
        typeof tokenResponse.id_token !== "string") {
      throw new Error("Token exchange failed.");
    }

    await verifyIdToken(tokenResponse.id_token, metadata, nonce);

    // Access token stays in this page's memory; it is never persisted to browser storage.
    state.accessToken = tokenResponse.access_token;
    state.expiresAt = Date.now() + Math.min(tokenResponse.expires_in, 3600) * 1000;
    state.authError = "";
    clearOidcTransaction();
    await loadDashboard();
    render();
  } catch {
    clearOidcTransaction();
    state.accessToken = null;
    state.expiresAt = 0;
    state.authError = "Sign-in could not be completed. Verify your identity-provider configuration and try again.";
    render();
  }
  return true;
}

function errorMessage(code, status) {
  const known = {
    TENANT_DATA_PLANE_NOT_READY: "The business API is disabled until durable tenant isolation is enabled.",
    AUTH_PROVIDER_NOT_CONFIGURED: "The API identity provider is not configured.",
    AUTH_PROVIDER_UNAVAILABLE: "The API identity provider is temporarily unavailable.",
    AUTHENTICATION_REQUIRED: "Your session was not accepted. Sign in again.",
    INVALID_TOKEN: "Your session expired or is invalid. Sign in again.",
    AUTHORIZATION_DENIED: "Your role does not permit this operation.",
    REQUEST_BODY_TOO_LARGE: "The API rejected an oversized request.",
  };
  if (known[code]) return known[code];
  if (status === 401) return "Your session was not accepted. Sign in again.";
  if (status === 403) return "Your role does not permit this operation.";
  if (status === 503) return "The business API is currently unavailable.";
  return "This section could not be loaded.";
}

async function apiGet(path) {
  if (!state.accessToken || Date.now() >= state.expiresAt) {
    state.accessToken = null;
    state.expiresAt = 0;
    throw Object.assign(new Error("Session expired."), { code: "INVALID_TOKEN", status: 401 });
  }
  const apiOrigin = safeUrl(config.apiBaseUrl, { allowHttpTest: true });
  const endpoint = new URL(path.replace(/^\//, ""), apiOrigin.href.endsWith("/") ? apiOrigin.href : apiOrigin.href + "/");
  const { response, body } = await fetchJson(endpoint.href, {
    method: "GET",
    headers: { Authorization: "Bearer " + state.accessToken },
  });
  if (!response.ok) {
    const code = typeof body?.code === "string" ? body.code : "";
    if (response.status === 401) {
      state.accessToken = null;
      state.expiresAt = 0;
    }
    throw Object.assign(new Error(errorMessage(code, response.status)), {
      code,
      status: response.status,
      userMessage: errorMessage(code, response.status),
    });
  }
  if (!body || typeof body !== "object") throw new Error("Invalid API response.");
  return body;
}

function isArrayField(value) {
  return Array.isArray(value) ? value : null;
}

async function loadDashboard() {
  if (!state.accessToken || Date.now() >= state.expiresAt) {
    state.accessToken = null;
    state.expiresAt = 0;
    render();
    return;
  }
  state.loading = true;
  state.errors = {};
  render();
  const requests = [
    ["organization", "/organizations/me", body => body],
    ["devices", "/devices/", body => isArrayField(body.devices) ? body.devices : null],
    ["tickets", "/tickets/", body => isArrayField(body.tickets) ? body.tickets : null],
    ["threats", "/threats/", body => body],
    ["events", "/threats/events?limit=50", body => isArrayField(body.events) ? body.events : null],
  ];
  await Promise.all(requests.map(async ([key, path, select]) => {
    try {
      const body = await apiGet(path);
      const value = select(body);
      if (value === null) throw new Error("The API response did not match the expected contract.");
      state.data[key] = value;
    } catch (error) {
      state.data[key] = null;
      const code = error && typeof error.code === "string" ? error.code : "";
      const status = error && Number.isFinite(error.status) ? error.status : 0;
      state.errors[key] = {
        code,
        status,
        message: error && typeof error.userMessage === "string"
          ? error.userMessage
          : (status ? errorMessage(code, status) : "Unable to reach the API. Check connectivity and configuration."),
      };
    }
  }));
  state.loading = false;
  state.lastRefreshed = new Date().toISOString();
  if (!state.accessToken) {
    state.data = { organization: null, devices: null, tickets: null, threats: null, events: null };
  }
  render();
}

function signOut() {
  state.accessToken = null;
  state.expiresAt = 0;
  state.activeTab = "overview";
  state.loading = false;
  state.authError = "";
  state.data = { organization: null, devices: null, tickets: null, threats: null, events: null };
  state.errors = {};
  state.lastRefreshed = null;
  render();
}

function errorNotice(message, code = "") {
  const notice = element("div", "", "notice notice-error", { role: "alert" });
  append(notice,
    element("span", "!", "notice-mark", { "aria-hidden": "true" }),
    element("div", "", "notice-copy")
  );
  notice.querySelector(".notice-copy").append(
    element("strong", code === "TENANT_DATA_PLANE_NOT_READY" ? "Business data plane unavailable" : "Data unavailable", ""),
    element("p", message, "")
  );
  return notice;
}

function metric(label, value, detail) {
  const card = element("article", "", "metric-card");
  append(card,
    element("p", label, "metric-label"),
    element("p", value, "metric-value"),
    element("p", detail, "metric-detail")
  );
  return card;
}

function sectionHeading(title, detail) {
  const wrap = element("div", "", "section-heading");
  append(wrap, element("h2", title, ""), element("p", detail, "muted"));
  return wrap;
}

function emptyState(title, detail) {
  const box = element("div", "", "empty-state");
  append(box, element("h3", title, ""), element("p", detail, "muted"));
  return box;
}

function statusPill(value, variant = "neutral") {
  return element("span", value, "status-pill status-" + variant);
}

function tableShell(headers, rows, emptyTitle, emptyDetail) {
  const wrap = element("div", "", "table-shell");
  if (!rows || rows.length === 0) {
    wrap.append(emptyState(emptyTitle, emptyDetail));
    return wrap;
  }
  const table = element("table", "", "data-table");
  const thead = element("thead");
  const tr = element("tr");
  for (const header of headers) tr.append(element("th", header, "", { scope: "col" }));
  thead.append(tr);
  const tbody = element("tbody");
  for (const row of rows) tbody.append(row);
  append(table, thead, tbody);
  wrap.append(table);
  return wrap;
}

function dataUnavailable(key) {
  const error = state.errors[key];
  if (!error) return null;
  return errorNotice(error.message, error.code);
}

function deviceRows() {
  if (state.data.devices === null) return null;
  return state.data.devices.map(device => {
    const row = element("tr");
    const name = element("td", "", "");
    append(name,
      element("strong", device.name || "Unnamed device", "cell-title"),
      element("span", device.id || "ID unavailable", "cell-subtitle")
    );
    const platform = element("td", [device.os_type, device.device_type].filter(Boolean).join(" · ") || "Not reported", "");
    const activity = element("td", "", "");
    activity.append(statusPill(device.is_active === true ? "Active" : device.is_active === false ? "Inactive" : "Unknown",
      device.is_active === true ? "good" : device.is_active === false ? "warning" : "neutral"));
    const score = Number.isFinite(device.resilience_score) ? Math.round(device.resilience_score) + "/100" : "Not scored";
    const lastSeen = device.last_seen_at ? new Date(device.last_seen_at).toLocaleString() : "No telemetry timestamp";
    append(row, name, platform, activity, element("td", score, "numeric"), element("td", lastSeen, "muted"));
    return row;
  });
}

function ticketRows() {
  if (state.data.tickets === null) return null;
  return state.data.tickets.map(ticket => {
    const row = element("tr");
    const title = element("td", "", "");
    append(title,
      element("strong", ticket.title || "Untitled ticket", "cell-title"),
      element("span", ticket.id || "ID unavailable", "cell-subtitle")
    );
    const priority = String(ticket.priority || "unknown").toLowerCase();
    const priorityCell = element("td", "", "");
    priorityCell.append(statusPill(priority, priority === "critical" || priority === "high" ? "warning" : "neutral"));
    const status = String(ticket.status || "unknown").toLowerCase();
    const statusCell = element("td", "", "");
    statusCell.append(statusPill(status, status === "resolved" ? "good" : status === "escalated" ? "danger" : "neutral"));
    const ai = ticket.ai_resolved === true ? "AI resolution recorded" : ticket.escalated === true ? "Escalated" : "No AI resolution recorded";
    append(row, title, priorityCell, statusCell, element("td", ai, "muted"));
    return row;
  });
}

function threatRows() {
  if (state.data.events === null) return null;
  return state.data.events.map(event => {
    const row = element("tr");
    const identity = element("td", "", "");
    append(identity,
      element("strong", event.event_id || event.id || "Event ID unavailable", "cell-title"),
      element("span", event.src_ip || "Source not reported", "cell-subtitle")
    );
    const level = String(event.threat_level || "unknown").toLowerCase();
    const levelCell = element("td", "", "");
    levelCell.append(statusPill(level, level === "critical" || level === "high" ? "danger" : level === "medium" ? "warning" : "neutral"));
    const assessment = element("td", event.assessment || event.decision_status || "No assessment detail", "");
    const verified = event.containment_verified === true;
    const verificationCell = element("td", "", "");
    verificationCell.append(statusPill(verified ? "Verified" : "Not verified", verified ? "good" : "warning"));
    const timestamp = event.received_at || event.observed_at || event.created_at;
    append(row, identity, levelCell, assessment, verificationCell, element("td", timestamp ? new Date(timestamp).toLocaleString() : "Not timestamped", "muted"));
    return row;
  });
}

function metricValue(data, key, selector) {
  if (!Array.isArray(data)) return "—";
  return selector ? selector(data) : data.length;
}

function renderOverview(content) {
  content.append(sectionHeading("Operational overview", "Counts are derived from authenticated API responses only."));
  const devices = state.data.devices;
  const tickets = state.data.tickets;
  const events = state.data.events;
  const openTickets = Array.isArray(tickets)
    ? tickets.filter(ticket => ["open", "in_progress", "escalated"].includes(String(ticket.status || "").toLowerCase())).length
    : "—";
  const verified = Array.isArray(events) ? events.filter(event => event.containment_verified === true).length : "—";
  const findings = Array.isArray(events)
    ? events.length
    : state.data.threats && Number.isFinite(state.data.threats.total_events)
      ? state.data.threats.total_events
      : "—";
  const scored = Array.isArray(devices) ? devices.filter(device => Number.isFinite(device.resilience_score)) : null;
  const averageScore = scored && scored.length
    ? Math.round(scored.reduce((sum, device) => sum + device.resilience_score, 0) / scored.length) + "/100"
    : "—";
  const metrics = element("div", "", "metric-grid");
  append(metrics,
    metric("Registered devices", metricValue(devices, "devices"), "Tenant-scoped inventory"),
    metric("Open tickets", openTickets, "Open, in progress, or escalated"),
    metric("Threat findings", findings, "Assessment is not enforcement"),
    metric("Verified containment", verified, "Only server-verified outcomes"),
    metric("Average resilience", averageScore, scored ? scored.length + " scored devices" : "Inventory unavailable")
  );
  content.append(metrics);

  const unavailable = Object.entries(state.errors)
    .filter(([, error]) => error.code === "TENANT_DATA_PLANE_NOT_READY")
    .map(([, error]) => error.message);
  if (unavailable.length) content.append(errorNotice("The business API is disabled until durable tenant isolation is enabled. No data is simulated or substituted.", "TENANT_DATA_PLANE_NOT_READY"));

  const grid = element("div", "", "overview-grid");
  const devicePanel = element("section", "", "panel");
  append(devicePanel, sectionHeading("Device inventory", "Current records returned by the API."));
  if (dataUnavailable("devices")) devicePanel.append(dataUnavailable("devices"));
  else devicePanel.append(tableShell(["Device", "Platform", "State", "Resilience", "Last seen"], (deviceRows() || []).slice(0, 5), "No devices recorded", "No device records were returned for this tenant."));
  const ticketPanel = element("section", "", "panel");
  append(ticketPanel, sectionHeading("Ticket queue", "Current records returned by the API."));
  if (dataUnavailable("tickets")) ticketPanel.append(dataUnavailable("tickets"));
  else ticketPanel.append(tableShell(["Ticket", "Priority", "Status", "Resolution"], (ticketRows() || []).slice(0, 5), "No tickets recorded", "No ticket records were returned for this tenant."));
  append(grid, devicePanel, ticketPanel);
  content.append(grid);

  const evidence = element("section", "", "panel");
  append(evidence, sectionHeading("Threat evidence", "A finding never implies successful containment."));
  if (dataUnavailable("events")) evidence.append(dataUnavailable("events"));
  else evidence.append(tableShell(["Event", "Threat level", "Assessment", "Containment", "Received"], (threatRows() || []).slice(0, 5), "No findings recorded", "No threat findings were returned for this tenant."));
  content.append(evidence);
}

function renderDevices(content) {
  content.append(sectionHeading("Devices", "Tenant-scoped inventory and reported resilience scores."));
  if (dataUnavailable("devices")) content.append(dataUnavailable("devices"));
  else content.append(tableShell(["Device", "Platform", "State", "Resilience", "Last seen"], deviceRows(), "No devices recorded", "The API returned an empty device inventory."));
}

function renderTickets(content) {
  content.append(sectionHeading("Tickets", "Ticket status and AI-resolution flags as recorded by the API."));
  if (dataUnavailable("tickets")) content.append(dataUnavailable("tickets"));
  else content.append(tableShell(["Ticket", "Priority", "Status", "Resolution"], ticketRows(), "No tickets recorded", "The API returned an empty ticket queue."));
}

function renderThreats(content) {
  content.append(sectionHeading("Threat evidence", "Detection and analysis are separate from enforcement."));
  const note = element("p", "Containment is counted only when the server provides explicit verifier evidence. An assessment, alert, or decision to monitor is not a blocked threat.", "evidence-note");
  content.append(note);
  if (dataUnavailable("events")) content.append(dataUnavailable("events"));
  else content.append(tableShell(["Event", "Threat level", "Assessment", "Containment", "Received"], threatRows(), "No findings recorded", "The API returned an empty findings list."));
}

function renderLogin() {
  const shell = element("main", "", "auth-shell", { id: "main-content" });
  const brand = element("div", "", "brand-lockup");
  append(brand, element("span", "A", "brand-mark"), element("span", "AURONTRA", "brand-name"));
  const card = element("section", "", "auth-card", { "aria-labelledby": "auth-title" });
  append(card,
    element("p", "SECURE OPERATIONS CONSOLE", "eyebrow"),
    element("h1", "Operational clarity, grounded in evidence.", "", { id: "auth-title" }),
    element("p", "Sign in through your organization’s identity provider to view tenant-scoped devices, tickets, and threat evidence.", "auth-description")
  );
  if (state.authError) card.append(errorNotice(state.authError));
  if (!configIsReady()) {
    card.append(errorNotice("Console authentication is not configured. An administrator must set the OIDC issuer, public client ID, redirect URI, and API origin."));
  }
  card.append(actionButton("Sign in securely", "button button-primary button-wide", signIn, !configIsReady()));
  append(card,
    element("p", "Access tokens remain in memory and are not persisted in browser storage.", "auth-footnote"),
    element("p", "No sample customer data is displayed.", "auth-footnote")
  );
  append(shell, brand, card, element("p", "AURONTRA · Tenant-scoped operations · Governed by your identity provider", "auth-footer"));
  app.replaceChildren(shell);
}

function renderDashboard() {
  const shell = element("div", "", "console-shell");
  const sidebar = element("aside", "", "sidebar", { "aria-label": "Primary navigation" });
  const brand = element("div", "", "brand-lockup");
  append(brand, element("span", "A", "brand-mark"), element("span", "AURONTRA", "brand-name"));
  sidebar.append(brand);
  sidebar.append(element("p", "WORKSPACE", "sidebar-label"));
  const nav = element("nav", "", "side-nav", { role: "tablist", "aria-label": "Console sections", "aria-orientation": "vertical" });
  const tabs = [
    ["overview", "Overview", "OV"],
    ["devices", "Devices", "DV"],
    ["tickets", "Tickets", "TK"],
    ["threats", "Threat evidence", "TE"],
  ];
  for (const [key, label, short] of tabs) {
    const tab = actionButton("", "nav-tab" + (state.activeTab === key ? " is-active" : ""), () => {
      state.activeTab = key;
      render();
    });
    tab.setAttribute("role", "tab");
    tab.setAttribute("aria-selected", String(state.activeTab === key));
    tab.setAttribute("aria-controls", "console-panel");
    tab.tabIndex = state.activeTab === key ? 0 : -1;
    append(tab, element("span", short, "nav-glyph"), element("span", label, "nav-label"));
    nav.append(tab);
  }
  sidebar.append(nav);
  const sidebarFooter = element("div", "", "sidebar-footer");
  append(sidebarFooter,
    element("span", "AUTHENTICATED SESSION", "eyebrow"),
    element("span", "Bearer token held in memory", "muted small")
  );
  sidebar.append(sidebarFooter);

  const main = element("main", "", "main-area", { id: "main-content" });
  const topbar = element("header", "", "topbar");
  const heading = element("div", "", "topbar-heading");
  append(heading,
    element("p", "AURONTRA / CUSTOMER CONSOLE", "eyebrow"),
    element("h1", state.data.organization?.name || "Operational workspace", "topbar-title")
  );
  const actions = element("div", "", "topbar-actions");
  if (state.lastRefreshed) actions.append(element("span", "Updated " + new Date(state.lastRefreshed).toLocaleTimeString(), "muted small"));
  actions.append(actionButton(state.loading ? "Refreshing…" : "Refresh", "button button-secondary", loadDashboard, state.loading));
  actions.append(actionButton("Sign out", "button button-quiet", signOut));
  append(topbar, heading, actions);
  main.append(topbar);

  const statusLine = element("div", "", "status-line");
  append(statusLine,
    element("span", "", "status-indicator" + (state.loading ? " is-loading" : "")),
    element("span", state.loading ? "Refreshing authenticated API data" : "Authenticated · API data only", "status-text"),
    element("span", "No synthetic activity feed", "muted small")
  );
  main.append(statusLine);
  if (state.authError) main.append(errorNotice(state.authError));
  if (Object.keys(state.errors).length && !Object.values(state.errors).some(error => error.code === "TENANT_DATA_PLANE_NOT_READY")) {
    const firstError = Object.values(state.errors)[0];
    main.append(errorNotice(firstError.message, firstError.code));
  }

  const content = element("section", "", "content-panel", { id: "console-panel", role: "tabpanel", "aria-label": tabs.find(item => item[0] === state.activeTab)?.[1] || "Overview" });
  if (state.activeTab === "devices") renderDevices(content);
  else if (state.activeTab === "tickets") renderTickets(content);
  else if (state.activeTab === "threats") renderThreats(content);
  else renderOverview(content);
  main.append(content);
  const footer = element("footer", "", "console-footer");
  append(footer,
    element("span", "AURONTRA · Evidence over assumptions", ""),
    element("span", "Containment is never inferred from detection", "muted")
  );
  main.append(footer);
  append(shell, sidebar, main);
  app.replaceChildren(shell);
}

function render() {
  if (!state.accessToken || Date.now() >= state.expiresAt) renderLogin();
  else renderDashboard();
}

async function start() {
  const handled = await handleOidcCallback();
  if (!handled) render();
}

start().catch(() => {
  state.authError = "The console could not initialize. Check configuration and reload.";
  renderLogin();
});
