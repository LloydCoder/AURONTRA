import { expect, test, type Page, type Route } from "@playwright/test";
import { generateKeyPairSync, sign } from "node:crypto";

const APP_ORIGIN = "http://127.0.0.1:4173";
const API_ORIGIN = "http://api.test";
const ISSUER = "https://identity.test";
const CLIENT_ID = "aurontra-e2e-client";

const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const publicJwk = {
  ...publicKey.export({ format: "jwk" }),
  kid: "aurontra-e2e-rsa-key",
  alg: "RS256",
  use: "sig",
};

function idToken(nonce: string): string {
  const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT", kid: "aurontra-e2e-rsa-key" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({
    iss: ISSUER,
    aud: CLIENT_ID,
    sub: "e2e-subject",
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
    nonce,
  })).toString("base64url");
  const signingInput = `${header}.${payload}`;
  const signature = sign("RSA-SHA256", Buffer.from(signingInput), privateKey).toString("base64url");
  return `${signingInput}.${signature}`;
}

async function jsonResponse(route: Route, body: unknown, status = 200): Promise<void> {
  await route.fulfill({
    status,
    contentType: "application/json",
    headers: {
      "Access-Control-Allow-Origin": APP_ORIGIN,
      "Access-Control-Allow-Headers": "Authorization, Accept, Content-Type",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Cache-Control": "no-store",
    },
    body: JSON.stringify(body),
  });
}

async function installOidcRoutes(page: Page, invalidSignature = false): Promise<void> {
  let nonce = "";
  await page.route(`${ISSUER}/.well-known/openid-configuration`, route =>
    jsonResponse(route, {
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/authorize`,
      token_endpoint: `${ISSUER}/oauth/token`,
      jwks_uri: `${ISSUER}/.well-known/jwks.json`,
      response_types_supported: ["code"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      code_challenge_methods_supported: ["S256"],
    })
  );
  await page.route(`${ISSUER}/.well-known/jwks.json`, route =>
    jsonResponse(route, { keys: [publicJwk] })
  );
  await page.route(`${ISSUER}/authorize**`, async route => {
    const authorization = new URL(route.request().url());
    nonce = authorization.searchParams.get("nonce") || "";
    const oidcState = authorization.searchParams.get("state") || "";
    const redirectUri = authorization.searchParams.get("redirect_uri") || APP_ORIGIN + "/";
    expect(authorization.searchParams.get("code_challenge_method")).toBe("S256");
    expect(authorization.searchParams.get("code_challenge")).toBeTruthy();
    await route.fulfill({
      status: 302,
      headers: { Location: `${redirectUri}?code=one-time-test-code&state=${encodeURIComponent(oidcState)}` },
    });
  });
  await page.route(`${ISSUER}/oauth/token`, async route => {
    const form = new URLSearchParams(route.request().postData() || "");
    expect(form.get("grant_type")).toBe("authorization_code");
    expect(form.get("code_verifier")).toBeTruthy();
    expect(form.get("client_id")).toBe(CLIENT_ID);
    await jsonResponse(route, {
      access_token: "e2e-only-access-token",
      token_type: "Bearer",
      expires_in: 900,
      id_token: invalidSignature ? idToken(nonce).replace(/[^.]+$/, "invalid-signature") : idToken(nonce),
    });
  });
}

async function installApiRoutes(page: Page, mode: "success" | "disabled" = "success"): Promise<string[]> {
  const authorizationHeaders: string[] = [];
  await page.route(`${API_ORIGIN}/**`, async route => {
    if (route.request().method() === "OPTIONS") {
      await route.fulfill({
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": APP_ORIGIN,
          "Access-Control-Allow-Headers": "Authorization, Accept, Content-Type",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        },
      });
      return;
    }
    if (mode === "disabled") {
      await jsonResponse(route, {
        code: "TENANT_DATA_PLANE_NOT_READY",
        detail: "The tenant-isolated data plane is not enabled.",
      }, 503);
      return;
    }
    authorizationHeaders.push(route.request().headers().authorization || "");
    const path = new URL(route.request().url()).pathname;
    if (path === "/organizations/me") {
      await jsonResponse(route, { id: "org-e2e", name: "Test Organization", status: "active" });
    } else if (path === "/devices/") {
      await jsonResponse(route, {
        devices: [{
          id: "device-e2e-01",
          name: "device-e2e-01",
          is_active: true,
          os_type: "Linux",
          device_type: "server",
          resilience_score: 87,
          last_seen_at: "2026-10-11T09:00:00Z",
        }],
        total: 1,
      });
    } else if (path === "/tickets/") {
      await jsonResponse(route, {
        tickets: [{
          id: "ticket-e2e-01",
          title: "Test ticket from API fixture",
          status: "open",
          priority: "high",
          ai_resolved: false,
          escalated: false,
          source: "e2e",
        }],
        total: 1,
      });
    } else if (path === "/threats/") {
      await jsonResponse(route, {
        status: "ok",
        total_events: 1,
        contained: 0,
        containment_enabled: false,
        note: "Detection and analysis do not establish successful containment.",
      });
    } else if (path === "/threats/events") {
      await jsonResponse(route, {
        events: [{
          id: "finding-e2e-01",
          event_id: "finding-e2e-01",
          src_ip: "192.0.2.40",
          threat_level: "high",
          assessment: "suspicious",
          decision_status: "monitor",
          containment_verified: false,
          received_at: "2026-10-11T09:00:00Z",
        }],
        source: "aurontra_durable_evidence",
        containment_verified: false,
      });
    } else {
      await jsonResponse(route, { code: "NOT_FOUND" }, 404);
    }
  });
  return authorizationHeaders;
}

async function authenticate(page: Page, mode: "success" | "disabled" = "success"): Promise<string[]> {
  await installOidcRoutes(page);
  const authorizationHeaders = await installApiRoutes(page, mode);
  await page.goto("/");
  await page.getByRole("button", { name: "Sign in securely" }).click();
  await expect(page.getByRole("tablist", { name: "Console sections" })).toBeVisible();
  return authorizationHeaders;
}

test("build contains no seeded customer records and unauthenticated users see sign-in", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Operational clarity, grounded in evidence." })).toBeVisible();
  await expect(page.getByRole("button", { name: "Sign in securely" })).toBeVisible();
  await expect(page.getByText("prod-server-01")).toHaveCount(0);
  await expect(page.getByText("No sample customer data is displayed.")).toBeVisible();
});

test("PKCE authentication calls tenant APIs and only labels verifier-backed containment", async ({ page }) => {
  const headers = await authenticate(page);
  await expect(page.getByText("Test Organization")).toBeVisible();
  await expect(page.getByText("device-e2e-01")).toBeVisible();
  await expect(page.getByText("Test ticket from API fixture")).toBeVisible();
  await expect(page.getByText("finding-e2e-01")).toBeVisible();
  await expect(page.getByText("Verified containment", { exact: true })).toBeVisible();
  await expect(page.getByText("Not verified", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Threats blocked", { exact: true })).toHaveCount(0);
  expect(headers.length).toBeGreaterThanOrEqual(4);
  expect(headers.every(value => value === "Bearer e2e-only-access-token")).toBe(true);
  expect(await page.evaluate(() => localStorage.length + sessionStorage.length)).toBe(0);

  await page.getByRole("tab", { name: "Threat evidence" }).click();
  await expect(page.getByText("Containment is counted only when the server provides explicit verifier evidence.")).toBeVisible();
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("button", { name: "Sign in securely" })).toBeVisible();
  await expect(page.getByText("device-e2e-01")).toHaveCount(0);
});

test("disabled tenant data plane fails closed without fabricated records", async ({ page }) => {
  await installOidcRoutes(page);
  await installApiRoutes(page, "disabled");
  await page.goto("/");
  await page.getByRole("button", { name: "Sign in securely" }).click();
  await expect(page.getByText("Business data plane unavailable")).toBeVisible();
  await expect(page.getByText("No data is simulated or substituted.")).toBeVisible();
  await expect(page.getByText("prod-server-01")).toHaveCount(0);
});

test("invalid ID-token signature is rejected before any API request", async ({ page }) => {
  let apiCalls = 0;
  await installOidcRoutes(page, true);
  await page.route(API_ORIGIN + "/**", async route => {
    apiCalls += 1;
    await jsonResponse(route, { code: "SHOULD_NOT_BE_CALLED" }, 500);
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Sign in securely" }).click();
  await expect(page.getByText("Sign-in could not be completed. Verify your identity-provider configuration and try again.")).toBeVisible();
  expect(apiCalls).toBe(0);
});

test("OIDC callback with missing or mismatched state is rejected before API access", async ({ page }) => {
  let apiCalls = 0;
  await page.route(`${API_ORIGIN}/**`, async route => {
    apiCalls += 1;
    await jsonResponse(route, { code: "SHOULD_NOT_BE_CALLED" }, 500);
  });
  await page.goto("/?code=bad-code&state=attacker-state");
  await expect(page.getByRole("alert")).toBeVisible();
  await expect(page.getByText("Sign-in could not be validated. Please start again.")).toBeVisible();
  expect(apiCalls).toBe(0);
});
