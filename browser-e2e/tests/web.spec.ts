import { expect, test, type Page } from "@playwright/test";

const PASS = "browser-e2e-pass-123";
const E2EE_PASS = "browser-e2ee-pass-123";
const BASE = process.env.KOLIMI_E2E_URL ?? "http://localhost:18085";
const AUTH = {
  Authorization: "Basic " + Buffer.from(`alice:${PASS}`).toString("base64"),
};

test.describe.configure({ mode: "serial" });

test.beforeAll(async ({ request }) => {
  // Playwright treats /healthz as "ready" before the fixture has created
  // users and the legacy share; wait for the actual scenario.
  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    const response = await request.get(`${BASE}/api/shares/owned`, {
      headers: AUTH,
    });
    if (response.status() === 200) {
      const body = await response.json();
      if (Array.isArray(body.shares) && body.shares.length > 0) {
        return;
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error("browser-e2e fixture did not create the legacy share");
});

async function login(page: Page, username = "alice") {
  await page.goto(`${BASE}/app/`);
  await page.getByLabel("Username", { exact: true }).fill(username);
  await page.getByLabel("Password", { exact: true }).fill(PASS);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  // The first-login Vault suggestion is independent of the keyring state;
  // dismiss it and let the Settings flow decide whether encryption exists.
  await page
    .getByRole("button", { name: "Later", exact: true })
    .click({ timeout: 4_000 })
    .catch(() => {});
  await expect(
    page.getByRole("button", { name: "Files", exact: true }),
  ).toBeVisible();
}

async function upload(page: Page, name: string, body = "browser e2e") {
  await page.locator('input[type="file"]').setInputFiles({
    name,
    mimeType: "text/plain",
    buffer: Buffer.from(body),
  });
  await expect(page.getByText(name, { exact: true }).first()).toBeVisible();
}

async function row(page: Page, name: string) {
  return page.locator("li.file", { hasText: name }).first();
}

test("web settings tabs and the passkeys shortcut", async ({ page }) => {
  await login(page);
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  const modal = page.locator(".modal");

  await expect(
    modal.getByRole("tab", { name: "Encryption", exact: true }),
  ).toBeVisible();
  await modal.getByRole("tab", { name: "Passkeys", exact: true }).click();
  await expect(
    modal.getByRole("heading", { name: "Passkeys", exact: true }),
  ).toBeVisible();
  await expect(modal.getByText("Two-factor (TOTP)", { exact: true })).toBeVisible();

  await modal.getByRole("button", { name: "Close", exact: true }).click();
  await page.getByRole("button", { name: "Passkeys", exact: true }).click();
  const shortcut = page.locator(".modal");
  await expect(
    shortcut.getByRole("heading", { name: "Passkeys", exact: true }),
  ).toBeVisible();
  await expect(
    shortcut.getByLabel("Passphrase", { exact: true }),
  ).toHaveCount(0);
});

test("web rename and delete", async ({ page }) => {
  await login(page);
  const original = `browser-e2e-${Date.now()}.txt`;
  const renamed = `browser-renamed-${Date.now()}.txt`;
  await upload(page, original);

  page.once("dialog", (dialog) => dialog.accept(renamed));
  await (await row(page, original)).getByTitle("Rename").click();
  await expect(page.getByText(renamed, { exact: true }).first()).toBeVisible();

  page.once("dialog", (dialog) => dialog.accept());
  await (await row(page, renamed)).getByTitle("Delete").click();
  await expect(page.getByText(renamed, { exact: true })).toHaveCount(0);
});

test("web share and revoke", async ({ page }) => {
  await login(page);
  const name = `browser-share-${Date.now()}.txt`;
  await upload(page, name);

  await (await row(page, name)).getByTitle("Share").click();
  const modal = page.locator(".modal");
  await expect(modal.getByRole("heading", { name: /^Share/ })).toBeVisible();
  await modal
    .getByRole("combobox", { name: "Type", exact: true })
    .selectOption("user");
  await modal
    .getByRole("combobox", { name: "Recipient", exact: true })
    .fill("bob");
  await modal.locator(".share-form button.primary").click();
  await expect(modal.getByText("user → bob (read)")).toBeVisible();

  await modal.getByRole("button", { name: "Revoke", exact: true }).click();
  await expect(modal.getByText("user → bob (read)")).toHaveCount(0);
  await modal.getByRole("button", { name: "Close" }).click();
});

test("upload progress and context menu avoid inline-style CSP violations", async ({
  page,
}) => {
  await login(page);
  const csp: string[] = [];
  page.on("console", (msg) => {
    if (msg.text().includes("Content Security Policy")) {
      csp.push(msg.text());
    }
  });

  // Slow the upload enough that the progress bar stays visible while we
  // inspect it; localhost otherwise completes before the first frame.
  const client = await page.context().newCDPSession(page);
  await client.send("Network.enable");
  await client.send("Network.emulateNetworkConditions", {
    offline: false,
    latency: 50,
    downloadThroughput: 5 * 1024 * 1024,
    uploadThroughput: 500 * 1024,
  });

  const name = `browser-csp-${Date.now()}.bin`;
  await page.locator('input[type="file"]').setInputFiles({
    name,
    mimeType: "application/octet-stream",
    buffer: Buffer.alloc(2 * 1024 * 1024, 97),
  });

  const bar = page.locator(".upload-bar-fill").first();
  await bar.waitFor({ state: "attached" });
  await page.waitForTimeout(1_000);
  const width = await bar.evaluate((el) =>
    Number.parseFloat(getComputedStyle(el).width),
  );
  expect(width).toBeGreaterThan(0);

  await page.getByText(name, { exact: true }).first().waitFor({
    timeout: 60_000,
  });

  await (await row(page, name)).click({ button: "right" });
  const menu = page.locator(".ctx-menu");
  await expect(menu).toBeVisible();
  await expect(menu).not.toHaveCSS("left", "auto");
  expect(csp).toEqual([]);
});

test("web migration upgrades a legacy folder share and reset clears state", async ({
  page,
  request,
}) => {
  const owned = await request.get(`${BASE}/api/shares/owned`, {
    headers: AUTH,
  });
  expect(owned.status()).toBe(200);
  const shares = (await owned.json()).shares as Array<{ path: string }>;
  const path = shares.find((share) => share.path.length > 0)?.path;
  expect(path, "the fixture must create one legacy share").toBeTruthy();
  const groupUrl = `${BASE}/api/mls/group?path=${encodeURIComponent(path!)}`;

  expect((await request.get(groupUrl, { headers: AUTH })).status()).toBe(404);

  await login(page);
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  const modal = page.locator(".modal");
  await modal
    .getByLabel("Passphrase", { exact: true })
    .fill(E2EE_PASS);
  await modal.getByRole("button", { name: "Unlock", exact: true }).click();
  await expect(
    modal.getByText("Keyring unlocked for this browser."),
  ).toBeVisible();

  // The Devices tab hosts the extracted MLS device roster.
  await modal.getByRole("tab", { name: "Devices", exact: true }).click();
  await expect(
    modal.getByRole("heading", { name: "MLS devices", exact: true }),
  ).toBeVisible();
  await expect(modal.getByText("this device", { exact: true })).toBeVisible();

  await modal.getByRole("tab", { name: "Sharing", exact: true }).click();
  await modal
    .getByRole("button", { name: "Upgrade shares to MLS", exact: true })
    .click();
  await expect(modal.getByText(/Upgraded \d+ folder share/)).toBeVisible();
  expect((await request.get(groupUrl, { headers: AUTH })).status()).toBe(200);

  page.once("dialog", (dialog) => dialog.accept());
  await modal
    .getByRole("button", {
      name: "Reset this browser's MLS state",
      exact: true,
    })
    .click();
  await expect(modal.getByText(/MLS state cleared|had no stored/)).toBeVisible();
});
