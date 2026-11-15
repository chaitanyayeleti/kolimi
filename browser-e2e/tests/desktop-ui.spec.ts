import { expect, test, type Page } from "@playwright/test";
import path from "node:path";
import { pathToFileURL } from "node:url";

const UI = pathToFileURL(
  path.resolve(process.cwd(), "../apps/kolimi-desktop/ui/index.html"),
).href;

type SyncStatus = {
  state: string;
  detail: string;
  synced_at: number | null;
  conflicts: number;
  errors: string[];
  offline: boolean;
  paused?: boolean;
  pairs?: Array<{
    server: string;
    username: string;
    local_dir: string;
    remote: string;
    last_synced_at: number | null;
  }>;
};

type DesktopOptions = {
  accounts?: Array<Record<string, unknown>>;
  totp?: boolean;
};

async function loadDesktop(
  page: Page,
  status: SyncStatus,
  options: DesktopOptions = {},
) {
  await page.addInitScript(
    ({ mockStatus, options }) => {
      const now = Date.now();
      const defaultAccount = {
        server: "https://cloud.example.com",
        username: "alice",
        signed_in: true,
        has_e2ee: true,
        e2ee_unlocked: true,
        auto_approve_devices: true,
        pairs: [
          {
            local_dir: "/home/alice/Kolimi",
            remote: "/",
            encrypted_roots: ["Private"],
            mls: true,
            last_synced_at: now - 120_000,
          },
        ],
      };
      let accounts = options.accounts ?? [defaultAccount];
      const state = {
        ...mockStatus,
        synced_at: mockStatus.synced_at ? now + mockStatus.synced_at : null,
        paused: mockStatus.paused ?? false,
        pairs: mockStatus.pairs ?? [
          {
            server: "https://cloud.example.com",
            username: "alice",
            local_dir: "/home/alice/Kolimi",
            remote: "/",
            last_synced_at: now - 120_000,
          },
        ],
      };
      (window as any).__TAURI__ = {
        core: {
          invoke: async (command: string, args?: Record<string, unknown>) => {
            if (command === "get_settings") {
              return { autostart: false, accounts };
            }
            if (command === "sign_in") {
              if (options.totp && !args?.code) {
                return { totp_required: true };
              }
              accounts = [
                {
                  ...defaultAccount,
                  username: String(args?.username ?? defaultAccount.username),
                  server: String(args?.server ?? defaultAccount.server),
                  pairs: [],
                },
              ];
              return { totp_required: false };
            }
            if (command === "link_web_session") {
              accounts = [{ ...defaultAccount, password: "", pairs: [] }];
              return {
                server: "https://cloud.example.com",
                username: "alice",
              };
            }
            if (command === "get_sync_status") return state;
            if (command === "set_sync_paused") {
              state.paused = Boolean(args?.paused);
              return state;
            }
            if (command === "e2ee_status") return "unlocked";
            if (
              command === "list_enrollments" ||
              command === "recipient_fingerprints"
            ) {
              return [];
            }
            return undefined;
          },
        },
      };
    },
    { mockStatus: status, options },
  );
  await page.goto(UI);
}

test("desktop Accounts & Sync shows status, timestamps, and pause", async ({
  page,
}) => {
  await loadDesktop(page, {
    state: "idle",
    detail: "Synced 1 folder: ↑2 ↓1",
    synced_at: -120_000,
    conflicts: 0,
    errors: [],
    offline: false,
  });

  await expect(
    page.getByRole("heading", { name: "Accounts & Sync", exact: true }),
  ).toBeVisible();
  await expect(page.getByText("Sync idle", { exact: true })).toBeVisible();
  await expect(page.getByText(/Synced 1 folder/)).toBeVisible();
  await expect(page.getByText("alice", { exact: true })).toBeVisible();
  await expect(page.getByText("/home/alice/Kolimi")).toBeVisible();
  await expect(page.getByText("1 folder", { exact: true })).toBeVisible();
  await expect(page.getByText("MLS", { exact: true })).toBeVisible();
  await expect(page.getByText(/Last synced 2m ago/)).toBeVisible();
  await expect(page.getByText(/Last sync 2m ago/)).toBeVisible();

  const pause = page.getByRole("button", { name: "Pause", exact: true });
  await pause.click();
  await expect(
    page.getByRole("button", { name: "Resume", exact: true }),
  ).toHaveAttribute("aria-pressed", "true");
});

test("desktop sign-in requests a 2FA code and forwards it", async ({
  page,
}) => {
  await loadDesktop(
    page,
    {
      state: "idle",
      detail: "No sync has run yet.",
      synced_at: null,
      conflicts: 0,
      errors: [],
      offline: false,
    },
    { accounts: [], totp: true },
  );

  await page.getByLabel("Server URL", { exact: true }).fill("https://cloud.example.com");
  await page.getByLabel("Username", { exact: true }).fill("alice");
  await page.getByLabel("Password or app password", { exact: true }).fill("pw");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(
    page.getByText(/Enter the two-factor or recovery code for alice/),
  ).toBeVisible();
  await expect(page.getByLabel("Two-factor / recovery code (if enabled)")).toBeFocused();

  await page.getByLabel("Two-factor / recovery code (if enabled)").fill("123456");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByText("Signed in to alice", { exact: true })).toBeVisible();
  await expect(page.getByText("alice", { exact: true })).toBeVisible();
});

test("desktop links a passkey-only web session", async ({ page }) => {
  await loadDesktop(
    page,
    {
      state: "idle",
      detail: "No sync has run yet.",
      synced_at: null,
      conflicts: 0,
      errors: [],
      offline: false,
    },
    { accounts: [] },
  );

  await page.getByRole("button", { name: "Use current web session" }).click();
  await expect(
    page.getByText("Linked alice on https://cloud.example.com", { exact: true }),
  ).toBeVisible();
  await expect(page.getByText("alice", { exact: true })).toBeVisible();
});

test("desktop Accounts & Sync surfaces an offline sync error", async ({
  page,
}) => {
  await loadDesktop(page, {
    state: "error",
    detail: "cannot reach server",
    synced_at: null,
    conflicts: 0,
    errors: ["alice@cloud.example.com: cannot reach server"],
    offline: true,
  });

  await expect(page.getByText("Server unreachable", { exact: true })).toBeVisible();
  await expect(
    page.getByText("cannot reach server", { exact: false }).first(),
  ).toBeVisible();
  await page.locator(".sync-errors summary").click();
  await expect(
    page.getByText("alice@cloud.example.com: cannot reach server"),
  ).toBeVisible();
});
