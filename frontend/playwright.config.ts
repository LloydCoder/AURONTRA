import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? "line" : "list",
  use: {
    baseURL: "http://127.0.0.1:4173",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    ...devices["Desktop Chrome"],
  },
  webServer: {
    command: "python3 build.py && python3 -m http.server 4173 --directory dist",
    cwd: ".",
    url: "http://127.0.0.1:4173",
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
    env: {
      AURONTRA_ENVIRONMENT: "test",
      AURONTRA_API_BASE_URL: "http://api.test",
      AURONTRA_OIDC_ISSUER: "https://identity.test",
      AURONTRA_OIDC_CLIENT_ID: "aurontra-e2e-client",
      AURONTRA_OIDC_REDIRECT_URI: "http://127.0.0.1:4173/",
      AURONTRA_OIDC_AUDIENCE: "aurontra-api-test",
    },
  },
});
