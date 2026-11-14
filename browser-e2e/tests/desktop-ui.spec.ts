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
};

async function loadDesktop(page: Page, status: SyncStatus) {
  await page.addInitScript((mockStatus) => {
    const now = Date.now();
    const settings = {
      autostart: false,
      accounts: [
        {
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
            },
          ],
        },
      ],
    };
    (window as any).__TAURI__ = {
      core: {
        invoke: async (command: string) => {
          if (command === "get_settings") return settings;
          if (command === "get_sync_status") {
            return {
              ...mockStatus,
              synced_at: mockStatus.synced_at
                ? now + mockStatus.synced_at
                : null,
            };
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
  }, status);
  await page.goto(UI);
}

test("desktop Accounts & Sync shows status and account cards", async ({
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
