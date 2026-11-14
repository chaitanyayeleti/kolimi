import { readFile } from "node:fs/promises";
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

async function unlock(page: Page) {
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  const modal = page.locator(".modal");
  await modal.getByRole("tab", { name: "Encryption", exact: true }).click();
  await modal.getByLabel("Passphrase", { exact: true }).fill(E2EE_PASS);
  await modal.getByRole("button", { name: "Unlock", exact: true }).click();
  await expect(
    modal.getByText("Keyring unlocked for this browser."),
  ).toBeVisible();
  await modal.getByRole("button", { name: "Close", exact: true }).click();
}

async function openFolder(page: Page, name: string) {
  await (await row(page, name)).locator(".file-open").click();
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

test("web settings tabs and the passkeys panel", async ({ page }) => {
  await login(page);

  // Passkeys live only in Settings; the sidebar has no duplicate entry.
  await expect(
    page.locator(".sidebar").getByRole("button", {
      name: "Passkeys",
      exact: true,
    }),
  ).toHaveCount(0);

  await page.getByRole("button", { name: "Settings", exact: true }).click();
  const modal = page.locator(".modal");

  await expect(
    modal.getByRole("tab", { name: "Encryption", exact: true }),
  ).toBeVisible();

  await modal.getByRole("tab", { name: "Account", exact: true }).click();
  await expect(
    modal.getByRole("heading", { name: "Account", exact: true }),
  ).toBeVisible();
  await expect(
    modal.getByText("Active sessions", { exact: true }),
  ).toBeVisible();
  await expect(modal.getByText("this device", { exact: true })).toBeVisible();

  await modal.getByRole("tab", { name: "Passkeys", exact: true }).click();
  await expect(
    modal.getByRole("heading", { name: "Passkeys", exact: true }),
  ).toBeVisible();
  await expect(modal.getByText("Two-factor (TOTP)", { exact: true })).toBeVisible();
  await expect(
    modal.getByLabel("Passphrase", { exact: true }),
  ).toHaveCount(0);
});

test("web admin page lists and inspects users", async ({ page }) => {
  await login(page);
  await page.getByRole("button", { name: "Admin", exact: true }).click();

  await expect(
    page.getByRole("heading", { name: "Users", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Create user", exact: true }),
  ).toBeVisible();

  const bob = page.locator("main.content li.row", { hasText: "bob" }).first();
  await bob.getByRole("button", { name: "Manage", exact: true }).click();
  const modal = page.locator(".modal");
  await expect(
    modal.getByRole("heading", { name: "User — bob", exact: true }),
  ).toBeVisible();
  await expect(
    modal.getByText("Sign-in factors", { exact: true }),
  ).toBeVisible();
  await expect(
    modal.getByText("Storage quota", { exact: true }),
  ).toBeVisible();
  await modal.getByRole("button", { name: "Close", exact: true }).click();

  await page.getByRole("button", { name: "Create user", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Create user", exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
});

test("web admin creates and deletes a user", async ({ page }) => {
  await login(page);
  await page.getByRole("button", { name: "Admin", exact: true }).click();

  const username = `e2e-user-${Date.now()}`;
  await page.getByRole("button", { name: "Create user", exact: true }).click();
  const create = page.locator(".modal");
  await create.getByLabel("Username", { exact: true }).fill(username);
  await create.getByLabel("Initial password", { exact: true }).fill("e2e-password-123");
  await create.getByLabel("Confirm password", { exact: true }).fill("e2e-password-123");
  await create.getByRole("button", { name: "Create user", exact: true }).click();

  const row = page.locator("main.content li.row", { hasText: username }).first();
  await expect(row).toBeVisible();
  await row.getByRole("button", { name: "Manage", exact: true }).click();

  const detail = page.locator(".modal");
  await expect(
    detail.getByRole("heading", { name: `User — ${username}`, exact: true }),
  ).toBeVisible();
  await detail.getByLabel("Username", { exact: true }).fill(username);
  await detail.getByRole("button", { name: "Delete user", exact: true }).click();
  await expect(page.getByText(username, { exact: true })).toHaveCount(0);
});

test("web admin manages groups and members", async ({ page }) => {
  await login(page);
  await page.getByRole("button", { name: "Admin", exact: true }).click();
  await page.getByRole("tab", { name: "Groups", exact: true }).click();

  await expect(
    page.getByRole("heading", { name: "Groups", exact: true }),
  ).toBeVisible();

  const name = `e2e-group-${Date.now()}`;
  await page.getByRole("button", { name: "Create group", exact: true }).click();
  const create = page.locator(".modal");
  await create.getByLabel("Name", { exact: true }).fill(name);
  await create.getByRole("button", { name: "Create group", exact: true }).click();

  const group = page.locator("main.content li.row", { hasText: name }).first();
  await expect(group).toBeVisible();
  await group.getByRole("button", { name: "Manage", exact: true }).click();

  const detail = page.locator(".modal");
  await expect(
    detail.getByRole("heading", { name: `Group — ${name}`, exact: true }),
  ).toBeVisible();
  await expect(
    detail.getByText("Changing membership does not rotate MLS keys", {
      exact: false,
    }),
  ).toBeVisible();

  await detail.getByLabel("Add member", { exact: true }).fill("bob");
  await detail.getByRole("button", { name: "Add", exact: true }).click();
  await expect(detail.getByText("Added bob.", { exact: true })).toBeVisible();
  await expect(detail.locator("li.row", { hasText: "bob" })).toBeVisible();
  await detail
    .locator("li.row", { hasText: "bob" })
    .getByRole("button", { name: "Remove", exact: true })
    .click();
  await expect(detail.getByText("Removed bob.", { exact: true })).toBeVisible();

  await detail.getByLabel("Group name", { exact: true }).fill(name);
  await detail.getByRole("button", { name: "Delete group", exact: true }).click();
  await expect(page.getByText(name, { exact: true })).toHaveCount(0);
});

test("web admin filters and verifies the audit log", async ({ page }) => {
  await login(page);
  await page.getByRole("button", { name: "Admin", exact: true }).click();
  await page.getByRole("tab", { name: "Audit", exact: true }).click();

  await expect(
    page.getByRole("heading", { name: "Audit", exact: true }),
  ).toBeVisible();

  const filter = page.locator("main.content form");
  await filter.getByLabel("Action", { exact: true }).fill("user.add");
  await filter.getByRole("button", { name: "Apply", exact: true }).click();

  const entry = page.locator("main.content li.row", { hasText: "user.add" }).first();
  await expect(entry).toBeVisible();
  await entry.locator("summary").click();
  await expect(entry.locator("dt").first()).toBeVisible();

  await page.getByRole("button", { name: "Verify chain", exact: true }).click();
  await expect(
    page.getByText(/Audit chain verified \(\d+ entries\)\./),
  ).toBeVisible();
});

test("web passkey add requires re-authentication", async ({ page }) => {
  await login(page);
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  const modal = page.locator(".modal");
  await modal.getByRole("tab", { name: "Passkeys", exact: true }).click();

  // The name prompt is followed by a password confirmation, not an
  // immediate WebAuthn ceremony.
  const click = modal
    .getByRole("button", { name: "Add passkey", exact: true })
    .click();
  const dialog = await page.waitForEvent("dialog");
  await dialog.accept("browser-test-key");
  await click;
  await expect(
    modal.getByText(/Confirm your account password/),
  ).toBeVisible();

  // A virtual authenticator completes the ceremony only after re-auth.
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
    },
  });

  await modal.getByLabel("Account password", { exact: true }).fill(PASS);
  await modal.getByRole("button", { name: "Confirm", exact: true }).click();
  await expect(
    modal.getByText("browser-test-key", { exact: true }),
  ).toBeVisible();
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

test("web E2EE upload stays ciphertext and decrypts in the browser", async ({
  page,
  request,
}) => {
  await login(page);
  await unlock(page);
  await openFolder(page, "Private");
  await openFolder(page, "Team");
  await expect(page.getByText("note.txt", { exact: true }).first()).toBeVisible();

  const beforeResponse = await request.get(`${BASE}/api/sync/tree?limit=1000`, {
    headers: AUTH,
  });
  const beforeEntries = (await beforeResponse.json()).entries as Array<{
    path: string;
    kind: string;
  }>;
  const beforePaths = new Set(beforeEntries.map((entry) => entry.path));
  const teamPath = beforeEntries.find(
    (entry) => entry.kind === "dir" && entry.path.startsWith("/Private/"),
  )?.path;
  expect(teamPath, "the encrypted Team folder must exist").toBeTruthy();

  const name = `browser-e2ee-${Date.now()}.txt`;
  const marker = `E2EE-BROWSER-MARKER-${Date.now()}`;
  await upload(page, name, marker);

  // The folder name is encrypted (`k1_…`), so resolve the new node from the
  // server tree instead of guessing the path from the display name. The row
  // is optimistic, so wait for the commit to land.
  type TreeEntry = { path: string; kind: string; encrypted: boolean };
  let entries: TreeEntry[] = [];
  let uploaded: TreeEntry | undefined;
  for (let attempt = 0; attempt < 40 && !uploaded; attempt++) {
    const afterResponse = await request.get(
      `${BASE}/api/sync/tree?limit=1000`,
      { headers: AUTH },
    );
    entries = (await afterResponse.json()).entries as TreeEntry[];
    uploaded = entries.find(
      (entry) =>
        entry.kind === "file" &&
        entry.path.startsWith("/Private/") &&
        !beforePaths.has(entry.path),
    );
    if (!uploaded) {
      await page.waitForTimeout(250);
    }
  }
  expect(
    uploaded,
    `new encrypted file must appear in the server tree: ${JSON.stringify(entries)}`,
  ).toBeTruthy();
  expect(uploaded!.encrypted).toBe(true);
  const path = uploaded!.path;
  const encoded = encodeURIComponent(path);
  const info = await request.get(`${BASE}/api/files/info?path=${encoded}`, {
    headers: AUTH,
  });
  expect(info.status()).toBe(200);
  expect((await info.json()).encrypted).toBe(true);

  // The plaintext DAV surface must refuse the encrypted node.
  const davPath = path
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/");
  const dav = await request.get(`${BASE}/dav${davPath}`, { headers: AUTH });
  expect(dav.status()).toBe(403);

  // Every stored chunk is ciphertext: the marker must not appear.
  const manifestResponse = await request.get(
    `${BASE}/api/files/manifest?path=${encoded}`,
    { headers: AUTH },
  );
  expect(manifestResponse.status()).toBe(200);
  const manifest = (await manifestResponse.json()) as {
    chunks: Array<{ hash: string }>;
  };
  let stored = Buffer.alloc(0);
  for (const chunk of manifest.chunks) {
    const response = await request.get(
      `${BASE}/api/chunks/${chunk.hash}?path=${encoded}`,
      { headers: AUTH },
    );
    expect(response.status()).toBe(200);
    stored = Buffer.concat([stored, Buffer.from(await response.body())]);
  }
  expect(stored.includes(Buffer.from(marker))).toBe(false);

  // And the browser decrypts it again end-to-end.
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    (await row(page, name)).getByTitle("Download & decrypt").click(),
  ]);
  const downloaded = await download.path();
  expect(downloaded).not.toBeNull();
  expect(await readFile(downloaded!, "utf8")).toBe(marker);

  // Keep the shared fixture deterministic for the recipient test below.
  const deleted = await request.delete(`${BASE}/dav${davPath}`, {
    headers: AUTH,
  });
  expect(deleted.status()).toBe(204);
});

test("web E2EE recipient decrypts a shared file", async ({ page }) => {
  await login(page, "bob");
  await unlock(page);

  // Unlocking must refresh the already-rendered folder, so the wrapped
  // mount name ("Team") replaces the stored `k1_…` label without navigating.
  await expect(page.getByText("Team", { exact: true }).first()).toBeVisible();
  await openFolder(page, "Team");
  await expect(page.getByText("note.txt", { exact: true }).first()).toBeVisible();

  const [download] = await Promise.all([
    page.waitForEvent("download"),
    (await row(page, "note.txt")).getByTitle("Download & decrypt").click(),
  ]);
  const downloaded = await download.path();
  expect(downloaded).not.toBeNull();
  expect(await readFile(downloaded!, "utf8")).toBe("legacy encrypted folder\n");
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
