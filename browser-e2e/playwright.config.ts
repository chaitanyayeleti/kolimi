import { defineConfig } from "@playwright/test";

const port = Number(process.env.KOLIMI_E2E_PORT ?? "18085");
const baseURL = process.env.KOLIMI_E2E_URL ?? `http://localhost:${port}`;

export default defineConfig({
  testDir: "./tests",
  timeout: 90_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["list"], ["github"]] : [["list"]],
  use: {
    baseURL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  webServer: {
    command: "cd .. && bash scripts/browser-e2e-server.sh",
    url: `${baseURL}/healthz`,
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
  },
});
