import { readFile } from "node:fs/promises";
import { createHmac } from "node:crypto";
import { AxeBuilder } from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const PASS = "browser-e2e-pass-123";
const E2EE_PASS = "browser-e2ee-pass-123";
const BASE = process.env.KOLIMI_E2E_URL ?? "http://localhost:18085";
const AUTH = {
  Authorization: "Basic " + Buffer.from(`alice:${PASS}`).toString("base64"),
};

type SyncTreeEntry = {
  id: number;
  path: string;
  kind: string;
  encrypted: boolean;
};

async function syncTreeEntries(
  request: import("@playwright/test").APIRequestContext,
): Promise<SyncTreeEntry[]> {
  const entries: SyncTreeEntry[] = [];
  let after = 0;
  for (;;) {
    const response = await request.get(
      `${BASE}/api/sync/tree?after_id=${after}&limit=1000`,
      { headers: AUTH },
    );
    expect(response.status()).toBe(200);
    const body = (await response.json()) as {
      entries: SyncTreeEntry[];
      has_more: boolean;
      last_id: number;
    };
    entries.push(...body.entries);
    if (!body.has_more || body.last_id <= after) {
      return entries;
    }
    after = body.last_id;
  }
}

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

async function submitLogin(
  page: Page,
  username = "alice",
  password = PASS,
) {
  await page.goto(`${BASE}/app/`);
  await page.getByLabel("Username", { exact: true }).fill(username);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
}

async function login(
  page: Page,
  username = "alice",
  password = PASS,
) {
  await submitLogin(page, username, password);
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
  const settings = page.locator(".settings-page");
  await settings.getByRole("tab", { name: "Encryption", exact: true }).click();
  await settings.getByLabel("Passphrase", { exact: true }).fill(E2EE_PASS);
  await settings.getByRole("button", { name: "Unlock", exact: true }).click();
  await expect(
    settings.getByText("Keyring unlocked for this browser."),
  ).toBeVisible();
  await settings.getByRole("button", { name: "Back to files" }).click();
}

function base32Decode(input: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const character of input.toUpperCase().replace(/=+$/, "")) {
    const index = alphabet.indexOf(character);
    if (index < 0) continue;
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function totp(secret: string): string {
  const key = base32Decode(secret);
  const counter = Math.floor(Date.now() / 30_000);
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac("sha1", key).update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  return String(binary % 1_000_000).padStart(6, "0");
}

async function completeMfa(page: Page) {
  await expect(
    page.getByRole("heading", { name: "Secure your account", exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Set up authenticator", exact: true }).click();
  const secret = await page.locator(".totp-enroll code").textContent();
  expect(secret).toBeTruthy();
  await page.getByLabel("Code from the app", { exact: true }).fill(totp(secret!));
  await page.getByRole("button", { name: "Confirm and enable", exact: true }).click();
  await expect(page.getByText(/Recovery codes/)).toBeVisible();
  await page.getByRole("button", { name: "Continue to Kolimi", exact: true }).click();
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

test("web login shows the product panel", async ({ page }) => {
  await page.setViewportSize({ width: 1200, height: 820 });
  await page.goto(`${BASE}/app/`);
  await expect(
    page.getByText("Your files. Your server. Your keys.", { exact: true }),
  ).toBeVisible();
  await expect(page.getByLabel("Username", { exact: true })).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Sign in with a passkey", exact: true }),
  ).toBeVisible();
});

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
  const settings = page.locator(".settings-page");

  await expect(
    settings.getByRole("tab", { name: "Encryption", exact: true }),
  ).toBeVisible();

  await settings.getByRole("tab", { name: "Account", exact: true }).click();
  await expect(
    settings.getByRole("heading", { name: "Account", exact: true }),
  ).toBeVisible();
  await expect(
    settings.getByText("Active sessions", { exact: true }),
  ).toBeVisible();
  await expect(settings.getByText("this device", { exact: true })).toBeVisible();
  await settings
    .getByRole("button", { name: "Rename", exact: true })
    .first()
    .click();
  await settings
    .getByLabel("Session label", { exact: true })
    .fill("E2E laptop");
  await settings.getByRole("button", { name: "Save", exact: true }).click();
  await expect(settings.getByText("E2E laptop", { exact: false })).toBeVisible();

  await settings.getByRole("tab", { name: "Passkeys", exact: true }).click();
  await expect(
    settings.getByRole("heading", { name: "Passkeys", exact: true }),
  ).toBeVisible();
  await expect(
    settings.getByText("Two-factor (TOTP)", { exact: true }),
  ).toBeVisible();
  await expect(
    settings.getByLabel("Passphrase", { exact: true }),
  ).toHaveCount(0);
});

test("web phase 0 polish: dialog keyboard and mobile toolbar", async ({
  page,
}) => {
  await login(page);

  await page.getByRole("button", { name: "Admin", exact: true }).click();
  await page.getByRole("button", { name: "Create user", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Create user", exact: true });
  await expect(dialog).toBeVisible();

  for (let i = 0; i < 8; i += 1) {
    await page.keyboard.press("Tab");
  }
  expect(
    await dialog.evaluate((element) => element.contains(document.activeElement)),
  ).toBe(true);

  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Create user", exact: true }),
  ).toBeFocused();

  await page.getByRole("button", { name: "Files", exact: true }).click();
  await page.setViewportSize({ width: 390, height: 844 });
  const search = page.getByLabel("Search files", { exact: true });
  await expect(search).toBeVisible();
  const searchBox = await search.boundingBox();
  expect(searchBox).not.toBeNull();
  if (searchBox) {
    expect(searchBox.x).toBeGreaterThanOrEqual(0);
    expect(searchBox.x + searchBox.width).toBeLessThanOrEqual(390);
  }

  const upload = page.locator("label.button.primary");
  await expect(upload).toBeVisible();
  const uploadBox = await upload.boundingBox();
  expect(uploadBox).not.toBeNull();
  if (uploadBox) {
    expect(uploadBox.x).toBeGreaterThanOrEqual(0);
    expect(uploadBox.x + uploadBox.width).toBeLessThanOrEqual(390);
  }
});

test("web large folders load in pages", async ({ page, request }) => {
  const folder = `paged-${Date.now()}`;
  const created = await request.fetch(`${BASE}/dav/${folder}`, {
    method: "MKCOL",
    headers: AUTH,
  });
  expect(created.status()).toBe(201);
  for (let start = 0; start < 1001; start += 50) {
    const batch = Array.from(
      { length: Math.min(50, 1001 - start) },
      (_, offset) => start + offset,
    );
    await Promise.all(
      batch.map((index) =>
        request.put(
          `${BASE}/dav/${folder}/p-${String(index).padStart(4, "0")}.txt`,
          {
            headers: { ...AUTH, "content-type": "text/plain" },
            data: "x",
          },
        ),
      ),
    );
  }

  await login(page);
  await openFolder(page, folder);
  await expect(page.getByText("1000+ items", { exact: false })).toBeVisible();
  await page.getByRole("button", { name: "Load more", exact: true }).click();
  await expect(page.getByText("1001 items", { exact: true })).toBeVisible();
  await expect(page.getByText("p-1000.txt", { exact: true })).toBeVisible();
  await request.delete(`${BASE}/dav/${folder}`, { headers: AUTH });
});

test("web empty folder offers upload and new folder actions", async ({
  page,
  request,
}) => {
  await login(page);

  page.once("dialog", (dialog) => dialog.accept("empty-phase0"));
  await page
    .locator(".topbar")
    .getByRole("button", { name: "New folder", exact: true })
    .click();
  await expect(page.getByText("empty-phase0", { exact: true })).toBeVisible();

  await (await row(page, "empty-phase0")).locator(".file-open").click();
  await expect(
    page.getByText("This folder is empty", { exact: true }),
  ).toBeVisible();

  const empty = page.locator(".empty");
  await expect(
    empty.getByRole("button", { name: "Upload", exact: true }),
  ).toBeVisible();
  await expect(
    empty.getByRole("button", { name: "New folder", exact: true }),
  ).toBeVisible();

  const chooser = page.waitForEvent("filechooser");
  await empty.getByRole("button", { name: "Upload", exact: true }).click();
  await chooser;

  await request.delete(`${BASE}/dav/empty-phase0`, { headers: AUTH });
});

test("web file list sorts, filters, selects, and shows details", async ({
  page,
  request,
}) => {
  await login(page);
  const folder = `phase1-${Date.now()}`;

  page.once("dialog", (dialog) => dialog.accept(folder));
  await page
    .locator(".topbar")
    .getByRole("button", { name: "New folder", exact: true })
    .click();
  await (await row(page, folder)).locator(".file-open").click();
  await expect(page).toHaveURL(/#\/files/);

  await page.goBack();
  await expect(page.getByText(folder, { exact: true })).toBeVisible();
  await (await row(page, folder)).locator(".file-open").click();
  await expect(
    page.getByText("This folder is empty", { exact: true }),
  ).toBeVisible();

  await upload(page, "alpha.txt", "alpha");
  await upload(page, "beta.txt", "beta");

  const names = page.locator("main.content li.file .file-name");
  await expect(names).toHaveText(["alpha.txt", "beta.txt"]);
  await expect(page.locator("main.content li.file .file-icon.text")).toHaveCount(2);

  await page.getByRole("button", { name: "Sort descending" }).click();
  await expect(names).toHaveText(["beta.txt", "alpha.txt"]);

  await page.getByLabel("Filter files").selectOption("folders");
  await expect(page.getByText("No files match this filter")).toBeVisible();
  await page.getByRole("button", { name: "Clear filter" }).click();
  await expect(names).toHaveText(["beta.txt", "alpha.txt"]);

  await page.locator("main.content li.file .file-check").nth(0).check();
  await page.locator("main.content li.file .file-check").nth(1).check();
  await expect(page.getByText("2 selected", { exact: true })).toBeVisible();

  await (await row(page, "alpha.txt"))
    .getByRole("button", { name: "Actions", exact: true })
    .click();
  await page.getByRole("button", { name: "Details", exact: true }).click();
  const details = page.getByRole("dialog", { name: /^Details/ });
  await expect(details).toBeVisible();
  await expect(details.getByText("alpha.txt", { exact: true })).toBeVisible();
  await details.getByRole("button", { name: "Done", exact: true }).click();
  await expect(details).toHaveCount(0);

  await request.delete(`${BASE}/dav/${folder}`, { headers: AUTH });
});

test("web trash rows keep the file body and actions aligned", async ({
  page,
}) => {
  await login(page);
  const name = `trash-${Date.now()}.txt`;
  await upload(page, name, "send me to trash");

  await (await row(page, name))
    .getByRole("button", { name: "Actions", exact: true })
    .click();
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", { name: "Move to trash", exact: true }).click();
  await page.getByRole("button", { name: "Trash", exact: true }).click();

  const trashRow = page.locator("li.file.simple", { hasText: name }).first();
  await expect(trashRow).toBeVisible();
  await expect(
    trashRow.getByRole("button", { name: "Restore", exact: true }),
  ).toBeVisible();
  await expect(
    trashRow.getByRole("button", { name: "Delete forever", exact: true }),
  ).toBeVisible();

  const rowBox = await trashRow.boundingBox();
  const nameBox = await trashRow.locator(".file-name").boundingBox();
  const actionsBox = await trashRow.locator(".file-actions").boundingBox();
  expect(rowBox).not.toBeNull();
  expect(nameBox).not.toBeNull();
  expect(actionsBox).not.toBeNull();
  expect(nameBox!.width).toBeGreaterThan(150);
  expect(actionsBox!.x).toBeGreaterThan(nameBox!.x + 150);
  expect(actionsBox!.x + actionsBox!.width).toBeLessThanOrEqual(
    rowBox!.x + rowBox!.width + 1,
  );
  const columns = await trashRow.evaluate(
    (element) => getComputedStyle(element).gridTemplateColumns.split(" ").length,
  );
  expect(columns).toBe(2);

  page.once("dialog", (dialog) => dialog.accept());
  await trashRow
    .getByRole("button", { name: "Delete forever", exact: true })
    .dispatchEvent("click");
  await expect(trashRow).toHaveCount(0);
});

test("web app passwords can be created and revoked", async ({
  page,
  request,
}) => {
  await login(page);
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  const settings = page.locator(".settings-page");
  await settings.getByRole("tab", { name: "Passkeys", exact: true }).click();

  const name = `e2e-app-${Date.now()}`;
  await settings
    .getByPlaceholder("e.g. Laptop sync")
    .fill(name);
  await settings
    .getByRole("button", { name: "Create app password", exact: true })
    .click();
  await settings
    .getByLabel("Account password", { exact: true })
    .fill(PASS);
  await settings.getByRole("button", { name: "Confirm", exact: true }).click();

  await expect(
    settings.getByText("Copy this app password now", { exact: false }),
  ).toBeVisible();
  const token = (await settings.locator(".created code").last().textContent())!.trim();
  expect(token).toMatch(/^[0-9a-f]{64}$/);

  const auth = {
    Authorization: "Basic " + Buffer.from(`alice:${token}`).toString("base64"),
  };
  expect((await request.get(`${BASE}/api/me/usage`, { headers: auth })).status()).toBe(200);
  expect(
    (
      await request.delete(`${BASE}/api/me/app-passwords/current`, {
        headers: auth,
      })
    ).status(),
  ).toBe(204);
  expect((await request.get(`${BASE}/api/me/usage`, { headers: auth })).status()).toBe(401);
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

  const bob = page.locator("main.content tbody tr", { hasText: "bob" }).first();
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

  // Recovery requires typing the target username before confirmation.
  await modal.getByRole("button", { name: "Reset password", exact: true }).click();
  const reauth = modal.locator(".reauth");
  await reauth.getByLabel("Username", { exact: true }).fill("wrong");
  await expect(
    reauth.getByRole("button", { name: "Confirm", exact: true }),
  ).toBeDisabled();
  await reauth.getByRole("button", { name: "Cancel", exact: true }).click();
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
  await create.getByLabel("Your password", { exact: true }).fill(PASS);
  await create.getByRole("button", { name: "Create user", exact: true }).click();

  const row = page.locator("main.content tbody tr", { hasText: username }).first();
  await expect(row).toBeVisible();
  await row.getByRole("button", { name: "Manage", exact: true }).click();

  const detail = page.locator(".modal");
  await expect(
    detail.getByRole("heading", { name: `User — ${username}`, exact: true }),
  ).toBeVisible();
  await detail.getByLabel("Username", { exact: true }).fill(username);
  await detail.getByRole("button", { name: "Delete user", exact: true }).click();
  await detail.getByLabel("Your password", { exact: true }).fill(PASS);
  await detail.getByRole("button", { name: "Confirm", exact: true }).click();
  await expect(page.getByText(username, { exact: true })).toHaveCount(0);
});

test("web invite onboarding creates an account", async ({ page }) => {
  await login(page);
  await page.getByRole("button", { name: "Admin", exact: true }).click();
  await page.getByRole("tab", { name: "Invites", exact: true }).click();

  const username = `e2e-invite-${Date.now()}`;
  const password = "invite-e2e-pass-123";
  await page.getByRole("button", { name: "Create invite", exact: true }).click();
  const create = page.locator(".modal");
  await create.getByLabel("Username", { exact: true }).fill(username);
  await create.getByLabel("Display name", { exact: true }).fill("Invite Person");
  await create.getByLabel("Email", { exact: true }).fill("invite@example.test");
  await create.getByLabel("Your password", { exact: true }).fill(PASS);
  await create.getByRole("button", { name: "Create invite", exact: true }).click();

  await expect(
    page.getByText(`Invite link for ${username}. Shown once`, { exact: false }),
  ).toBeVisible();
  const link = await page.locator(".created code").textContent();
  expect(link).toContain("/invite#token=");

  // Accept the invite as a new visitor, not as the signed-in administrator.
  await page.context().clearCookies();
  await page.goto(link!);
  await expect(
    page.getByRole("heading", { name: "Join Kolimi", exact: true }),
  ).toBeVisible();
  await expect(page.getByText(username, { exact: true })).toBeVisible();
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByLabel("Confirm password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Create account", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Account ready", exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Go to sign in", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Sign in to Kolimi", exact: true }),
  ).toBeVisible();

  await submitLogin(page, username, password);
  await completeMfa(page);
  await expect(
    page.getByRole("button", { name: "Files", exact: true }),
  ).toBeVisible();
});

test("web forces a temporary password change", async ({ page }) => {
  await login(page);
  await page.getByRole("button", { name: "Admin", exact: true }).click();

  const username = `e2e-rotate-${Date.now()}`;
  const temporary = "temporary-e2e-pass-123";
  const replacement = "replacement-e2e-pass-123";
  await page.getByRole("button", { name: "Create user", exact: true }).click();
  const create = page.locator(".modal");
  await create.getByLabel("Username", { exact: true }).fill(username);
  await create.getByLabel("Initial password", { exact: true }).fill(temporary);
  await create.getByLabel("Confirm password", { exact: true }).fill(temporary);
  await create
    .getByLabel("Require password change at next sign-in", { exact: true })
    .check();
  await create.getByLabel("Your password", { exact: true }).fill(PASS);
  await create.getByRole("button", { name: "Create user", exact: true }).click();
  await expect(
    page.locator("main.content tbody tr", { hasText: username }).first(),
  ).toBeVisible();

  // A fresh browser context mimics a new sign-in with the temporary password.
  await page.context().clearCookies();
  await page.goto(`${BASE}/app/`);
  await page.getByLabel("Username", { exact: true }).fill(username);
  await page.getByLabel("Password", { exact: true }).fill(temporary);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();

  await expect(
    page.getByRole("heading", { name: "Change your password", exact: true }),
  ).toBeVisible();
  await page.getByLabel("Current password", { exact: true }).fill(temporary);
  await page.getByLabel("New password", { exact: true }).fill(replacement);
  await page.getByLabel("Confirm new password", { exact: true }).fill(replacement);
  await page.getByRole("button", { name: "Change password", exact: true }).click();

  await completeMfa(page);
  await expect(
    page.getByRole("button", { name: "Files", exact: true }),
  ).toBeVisible();
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
  await create.getByLabel("Your password", { exact: true }).fill(PASS);
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

  await detail.getByLabel("Your password", { exact: true }).fill(PASS);
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

  const entry = page.locator("main.content tbody tr", { hasText: "user.add" }).first();
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
  const settings = page.locator(".settings-page");
  await settings.getByRole("tab", { name: "Passkeys", exact: true }).click();

  // The name prompt is followed by a password confirmation, not an
  // immediate WebAuthn ceremony.
  const click = settings
    .getByRole("button", { name: "Add passkey", exact: true })
    .click();
  const dialog = await page.waitForEvent("dialog");
  await dialog.accept("browser-test-key");
  await click;
  await expect(
    settings.getByText(/Confirm your account password/),
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

  await settings.getByLabel("Account password", { exact: true }).fill(PASS);
  await settings.getByRole("button", { name: "Confirm", exact: true }).click();
  await expect(
    settings.getByText("browser-test-key", { exact: true }),
  ).toBeVisible();
});

test("web rename and delete", async ({ page }) => {
  await login(page);
  const original = `browser-e2e-${Date.now()}.txt`;
  const renamed = `browser-renamed-${Date.now()}.txt`;
  await upload(page, original);

  await (await row(page, original))
    .getByRole("button", { name: "Actions", exact: true })
    .click();
  page.once("dialog", (dialog) => dialog.accept(renamed));
  await page.getByRole("button", { name: "Rename", exact: true }).click();
  await expect(page.getByText(renamed, { exact: true }).first()).toBeVisible();

  await (await row(page, renamed))
    .getByRole("button", { name: "Actions", exact: true })
    .click();
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", { name: "Move to trash", exact: true }).click();
  await expect(page.getByText(renamed, { exact: true })).toHaveCount(0);
});

test("web share and revoke", async ({ page }) => {
  await login(page);
  const name = `browser-share-${Date.now()}.txt`;
  await upload(page, name);

  await (await row(page, name))
    .getByRole("button", { name: "Actions", exact: true })
    .click();
  await page.getByRole("button", { name: "Share", exact: true }).click();
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

test("web shared page lists, edits, and revokes created shares", async ({
  page,
}) => {
  await login(page);
  const name = `browser-shared-${Date.now()}.txt`;
  await upload(page, name);

  await (await row(page, name))
    .getByRole("button", { name: "Actions", exact: true })
    .click();
  await page.getByRole("button", { name: "Share", exact: true }).click();
  const modal = page.locator(".modal");
  await modal
    .getByRole("combobox", { name: "Type", exact: true })
    .selectOption("user");
  await modal
    .getByRole("combobox", { name: "Recipient", exact: true })
    .fill("bob");
  await modal.locator(".share-form button.primary").click();
  await expect(modal.getByText("user → bob (read)")).toBeVisible();
  await modal.getByRole("button", { name: "Close" }).click();

  await page.getByRole("button", { name: "Shared", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Shared", exact: true }),
  ).toBeVisible();
  await page.getByRole("tab", { name: /Shared by me/ }).click();
  const sharedRow = page.locator("li.row", { hasText: name }).first();
  await expect(sharedRow).toContainText("bob");
  await expect(sharedRow).toContainText("Can view");

  await sharedRow
    .getByRole("combobox", { name: "Access", exact: true })
    .selectOption("write");
  await expect(sharedRow).toContainText("Can edit");

  await sharedRow.getByRole("button", { name: "Revoke", exact: true }).click();
  await expect(page.locator("li.row", { hasText: name })).toHaveCount(0);
});

test("web file request link accepts an anonymous upload", async ({
  page,
  browser,
}) => {
  await login(page);
  const folder = `request-${Date.now()}`;
  page.once("dialog", (dialog) => dialog.accept(folder));
  await page
    .locator(".topbar")
    .getByRole("button", { name: "New folder", exact: true })
    .click();
  await (await row(page, folder)).getByRole("button", { name: "Actions" }).click();
  await page.getByRole("button", { name: "Share", exact: true }).click();

  const modal = page.locator(".modal");
  await modal
    .getByRole("combobox", { name: "Type", exact: true })
    .selectOption("link");
  await modal
    .getByRole("combobox", { name: "Link type", exact: true })
    .selectOption("write");
  await modal
    .getByRole("combobox", { name: "Password", exact: true })
    .selectOption("none");
  await modal.locator(".share-form button.primary").click();
  await expect(
    modal.getByText("File request created:", { exact: true }),
  ).toBeVisible();
  const link = await modal.locator(".created code").textContent();
  expect(link).toContain("/s/");
  await modal.getByRole("button", { name: "Close" }).click();

  const anonymous = await browser.newContext();
  const uploadPage = await anonymous.newPage();
  const csp: string[] = [];
  uploadPage.on("console", (message) => {
    if (message.text().includes("Content Security Policy")) {
      csp.push(message.text());
    }
  });
  await uploadPage.goto(link!);
  await expect(
    uploadPage.getByText("Files go to the owner's folder", { exact: false }),
  ).toBeVisible();
  const fileName = `anonymous-${Date.now()}.txt`;
  await uploadPage.locator('.drop-upload input[type="file"]').setInputFiles({
    name: fileName,
    mimeType: "text/plain",
    buffer: Buffer.from("uploaded through a file request"),
  });
  await expect(
    uploadPage.getByText("Uploaded in this session:", { exact: true }),
  ).toBeVisible();
  await expect(uploadPage.getByText(fileName, { exact: true })).toBeVisible();
  expect(csp, csp.join("\n")).toEqual([]);
  await anonymous.close();

  // The owner sees the upload in the target folder after a fresh load.
  await page.getByRole("button", { name: "Files", exact: true }).click();
  await openFolder(page, folder);
  await expect(page.getByText(fileName, { exact: true }).first()).toBeVisible();
});

test("web shared page has no accessibility violations", async ({ page }) => {
  await login(page);
  await page.getByRole("button", { name: "Shared", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Shared", exact: true }),
  ).toBeVisible();
  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations).toEqual([]);
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

  const beforeEntries = await syncTreeEntries(request);
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
    entries = await syncTreeEntries(request);
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
  const settings = page.locator(".settings-page");
  await settings.getByRole("tab", { name: "Encryption", exact: true }).click();
  await settings
    .getByLabel("Passphrase", { exact: true })
    .fill(E2EE_PASS);
  await settings.getByRole("button", { name: "Unlock", exact: true }).click();
  await expect(
    settings.getByText("Keyring unlocked for this browser."),
  ).toBeVisible();

  // The Devices tab hosts the extracted MLS device roster.
  await settings.getByRole("tab", { name: "Devices", exact: true }).click();
  await expect(
    settings.getByRole("heading", { name: "MLS devices", exact: true }),
  ).toBeVisible();
  await expect(settings.getByText("this device", { exact: true })).toBeVisible();

  const mlsRow = settings.locator(".mls-device").first();
  const mlsBox = await mlsRow.boundingBox();
  expect(mlsBox).not.toBeNull();
  expect(mlsBox!.width).toBeGreaterThan(500);
  expect(
    await mlsRow.evaluate(
      (element) => getComputedStyle(element).gridTemplateColumns.split(" ").length,
    ),
  ).toBe(2);

  await settings.getByRole("tab", { name: "Sharing", exact: true }).click();
  await settings
    .getByRole("button", { name: "Upgrade shares to MLS", exact: true })
    .click();
  await expect(
    settings.getByText(/Upgraded \d+ folder share/),
  ).toBeVisible();
  expect((await request.get(groupUrl, { headers: AUTH })).status()).toBe(200);

  page.once("dialog", (dialog) => dialog.accept());
  await settings
    .getByRole("button", {
      name: "Reset this browser's MLS state",
      exact: true,
    })
    .click();
  await expect(
    settings.getByText(/MLS state cleared|had no stored/),
  ).toBeVisible();
});

test("static assets are compressed and revalidate", async ({ request }) => {
  const shell = await request.get(`${BASE}/app/`);
  expect(shell.status()).toBe(200);
  const html = await shell.text();
  expect(html).toContain("Loading your workspace");
  expect(html).toContain("boot-spinner");

  const asset = await request.get(`${BASE}/app/app_bg.wasm`, {
    headers: { "Accept-Encoding": "br" },
  });
  expect(asset.status()).toBe(200);
  expect(asset.headers()["content-encoding"]).toBe("br");
  expect(asset.headers()["vary"]).toContain("Accept-Encoding");
  const etag = asset.headers()["etag"];
  expect(etag).toBeTruthy();

  const revalidated = await request.get(`${BASE}/app/app_bg.wasm`, {
    headers: { "Accept-Encoding": "br", "If-None-Match": etag },
  });
  expect(revalidated.status()).toBe(304);
});

test("mobile selection hides checkboxes until Select", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await login(page);

  const checkbox = page.locator("li.file .file-check").first();
  await expect(checkbox).toBeHidden();

  await page.getByRole("button", { name: "Select", exact: true }).click();
  await expect(checkbox).toBeVisible();
  await checkbox.check();
  await expect(page.locator(".bulk-bar")).toContainText("1 selected");

  await page.getByRole("button", { name: "Done", exact: true }).click();
  await expect(checkbox).toBeHidden();
  await expect(page.locator(".bulk-bar")).toHaveCount(0);
});

test("unlimited quota and settings unlock action", async ({ page }) => {
  await login(page);
  await expect(page.locator(".storage")).toContainText("Unlimited");
  await expect(page.locator(".storage")).toContainText("used");

  await page.getByRole("button", { name: "Settings", exact: true }).click();
  const settings = page.locator(".settings-page");
  await settings.getByRole("tab", { name: "Sharing", exact: true }).click();
  const unlock = settings.getByRole("button", {
    name: "Unlock encryption",
    exact: true,
  });
  await expect(unlock).toBeVisible();
  await unlock.click();
  await expect(
    settings.getByRole("tab", { name: "Encryption", exact: true }),
  ).toHaveAttribute("aria-selected", "true");
});

test("keyboard shortcuts focus search and select visible files", async ({
  page,
}) => {
  await login(page);
  await page.locator(".content").click({ position: { x: 700, y: 600 } });

  await page.keyboard.press("/");
  await expect(page.locator("#topbar-search")).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(page.locator("#topbar-search")).not.toBeFocused();

  await page.keyboard.press("Control+a");
  await expect(page.locator(".bulk-bar")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.locator(".bulk-bar")).toHaveCount(0);
});

test("main pages have no axe violations", async ({ page }) => {
  const audit = async () => {
    const results = await new AxeBuilder({ page }).analyze();
    expect(results.violations.map((violation) => violation.id)).toEqual([]);
  };

  await page.goto(`${BASE}/app/`);
  await expect(
    page.getByText("Your files. Your server. Your keys.", { exact: true }),
  ).toBeVisible();
  await audit();

  await login(page);
  await audit();

  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await audit();

  await page.getByRole("button", { name: "Admin", exact: true }).click();
  await audit();
});

test("metrics HTML dashboard renders for admins", async ({ page, request }) => {
  await login(page);

  const response = await page.goto(`${BASE}/metrics`);
  expect(response?.status()).toBe(200);
  expect(response?.headers()["content-type"]).toContain("text/html");
  expect(response?.headers()["vary"]).toContain("Accept");
  expect(response?.headers()["cache-control"]).toBe("no-store");

  await expect(
    page.getByRole("heading", { name: "Kolimi metrics", exact: true }),
  ).toBeVisible();
  await expect(
    page.locator(".metric h2", { hasText: "kolimi_build_info" }),
  ).toBeVisible();
  await expect(
    page.locator(".metric h2", { hasText: "kolimi_http_requests_total" }),
  ).toBeVisible();

  const text = await request.get(`${BASE}/metrics?format=text`, {
    headers: AUTH,
  });
  expect(text.status()).toBe(200);
  expect(await text.text()).toContain("kolimi_db_pool_connections");
});
