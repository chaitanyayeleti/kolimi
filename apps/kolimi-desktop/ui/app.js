const { invoke } = window.__TAURI__.core;

const $ = (id) => document.getElementById(id);
const msg = $("msg");
const accountsEl = $("accounts");

const THEME_KEY = "kolimi-desktop-theme";
const ICON_ACCOUNT = `<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="8" r="3.4"/><path d="M5 20a7 7 0 0 1 14 0"/></svg>`;
const ICON_FOLDER = `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>`;
const ICON_LOCK = `<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>`;
const ICON_SUN = `<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M19.1 4.9l-1.4 1.4M6.3 17.7l-1.4 1.4"/></svg>`;
const ICON_MOON = `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 14.5A8.5 8.5 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5z"/></svg>`;

const E2EE = {
  none: { label: "E2EE not set up", kind: "muted" },
  locked: { label: "E2EE locked", kind: "warn" },
  unlocked: { label: "E2EE unlocked", kind: "ok" },
  signed_out: { label: "E2EE unavailable", kind: "muted" },
  unknown: { label: "E2EE unknown", kind: "muted" },
};

let msgTimer;
function setMsg(text, kind) {
  clearTimeout(msgTimer);
  msg.textContent = text || "";
  msg.className = "toast" + (text ? " show" : "") + (kind ? " " + kind : "");
  if (text) {
    msgTimer = setTimeout(() => setMsg(""), kind === "err" ? 9000 : 5000);
  }
}

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (value === undefined || value === null) continue;
    if (value === false) {
      if (["checked", "disabled", "open", "selected"].includes(key)) node[key] = false;
      continue;
    }
    if (key.startsWith("on") && typeof value === "function") {
      node.addEventListener(key.slice(2), value);
    } else if (key === "class") {
      node.className = value;
    } else if (key === "html") {
      node.innerHTML = value;
    } else if (key === "text") {
      node.textContent = value;
    } else if (["checked", "disabled", "open", "selected", "value"].includes(key)) {
      node[key] = value;
    } else {
      node.setAttribute(key, value);
    }
  }
  if (tag === "button" && !(props && "type" in props)) node.type = "button";
  for (const child of children.flat(Infinity)) {
    if (child === undefined || child === null || child === false) continue;
    node.append(child);
  }
  return node;
}

function btn(label, cls = "", onclick = null, attrs = {}) {
  return el("button", { class: `btn ${cls}`.trim(), type: "button", onclick, ...attrs }, label);
}

function field(labelText, input, cls = "") {
  return el("label", { class: `field ${cls}`.trim() }, el("span", {}, labelText), input);
}

function badge(text, kind) {
  return el("span", { class: "badge " + kind }, text);
}

function emptyRow(text) {
  return el("li", { class: "empty-row" }, text);
}

function switchControl(input, label) {
  return el("label", { class: "switch", "aria-label": label }, input, el("span", { class: "switch-track", "aria-hidden": "true" }));
}

function closeMenus() {
  document.querySelectorAll("details.menu[open]").forEach((menu) => {
    menu.open = false;
  });
}

function emptyState() {
  return el("div", { class: "card empty-state" },
    el("span", { class: "empty-icon", html: ICON_ACCOUNT }),
    el("h2", {}, "No accounts yet"),
    el("p", { class: "muted" }, "Add a Kolimi server below to start syncing folders."),
    btn("Add your first account", "primary", () => {
      $("add-account").open = true;
      $("new-server").focus();
    }));
}

function renderPair(account, pair, editable) {
  const li = el("li", { class: "pair" });
  let menu;

  async function share() {
    closeMenus();
    const path = prompt("Relative path to share (e.g. Private/Team)");
    if (!path) return;
    const target = prompt("Recipient username, or group:<name>");
    if (!target) return;
    const write = confirm("Allow the recipient to write (MLS write share)?");
    const group = target.startsWith("group:");
    try {
      const wrapped = await invoke("share_mls", {
        server: account.server,
        username: account.username,
        dir: pair.local_dir,
        path,
        kind: group ? "group" : "user",
        recipient: group ? target.slice(6) : target,
        write,
      });
      setMsg("Shared " + path + " (" + wrapped + " legacy wraps)", "ok");
      refresh();
    } catch (error) {
      setMsg(String(error), "err");
    }
  }

  async function unshare() {
    closeMenus();
    const path = prompt("Relative path to unshare");
    if (!path) return;
    const target = prompt("Recipient username, or group:<name>");
    if (!target) return;
    const group = target.startsWith("group:");
    try {
      await invoke("unshare_mls", {
        server: account.server,
        username: account.username,
        dir: pair.local_dir,
        path,
        kind: group ? "group" : "user",
        recipient: group ? target.slice(6) : target,
      });
      setMsg("Revoked " + path + " for " + target, "ok");
      refresh();
    } catch (error) {
      setMsg(String(error), "err");
    }
  }

  async function mlsStatus() {
    closeMenus();
    const path = prompt("Relative path to inspect");
    if (!path) return;
    try {
      const status = await invoke("mls_status", {
        server: account.server,
        username: account.username,
        dir: pair.local_dir,
        path,
      });
      setMsg(status ? "MLS epoch " + status.epoch + ": " + status.members.join(", ") : "No MLS group", "ok");
    } catch (error) {
      setMsg(String(error), "err");
    }
  }

  async function migrate() {
    closeMenus();
    try {
      const paths = await invoke("migrate_mls", {
        server: account.server,
        username: account.username,
        dir: pair.local_dir,
      });
      setMsg(paths.length ? "Migrated " + paths.length + " share(s) to MLS" : "Nothing to migrate", "ok");
      refresh();
    } catch (error) {
      setMsg(String(error), "err");
    }
  }

  async function remove() {
    closeMenus();
    if (!confirm("Remove " + pair.local_dir + " from sync?")) return;
    try {
      await invoke("remove_pair", {
        server: account.server,
        username: account.username,
        dir: pair.local_dir,
      });
      setMsg("Removed " + pair.local_dir, "ok");
      refresh();
    } catch (error) {
      setMsg(String(error), "err");
    }
  }

  function display() {
    li.classList.remove("editing");
    const roots = pair.encrypted_roots || [];
    const chips = roots.length
      ? roots.map((root) => el("span", { class: "chip" }, root))
      : [el("span", { class: "chip muted" }, "not encrypted")];
    const main = el("div", { class: "pair-main" },
      el("span", { class: "pair-icon", html: ICON_FOLDER }),
      el("div", { class: "pair-text" },
        el("div", { class: "pair-local" }, pair.local_dir),
        el("div", { class: "pair-remote" }, "→ ", pair.remote),
        el("div", { class: "chips" }, ...chips)));
    li.replaceChildren(
      main,
      editable ? el("div", { class: "pair-actions" },
        btn("Edit", "small ghost", edit),
        menu) : null);
  }

  function edit() {
    li.classList.add("editing");
    const dirInput = el("input", { value: pair.local_dir });
    const remoteInput = el("input", { value: pair.remote });
    const rootsInput = el("input", {
      value: (pair.encrypted_roots || []).join(", "),
      placeholder: "e.g. Private, Photos (blank = no encryption)",
    });
    li.replaceChildren(
      el("div", { class: "form-grid" },
        field("Local folder", dirInput),
        field("Remote folder", remoteInput),
        field("Encrypted folders (relative, comma-separated)", rootsInput, "span-2")),
      el("div", { class: "form-actions end" },
        btn("Cancel", "ghost", display),
        btn("Save", "primary", async () => {
          try {
            await invoke("update_pair", {
              server: account.server,
              username: account.username,
              dir: pair.local_dir,
              newDir: dirInput.value,
              remote: remoteInput.value || "/",
              encryptedRoots: rootsInput.value.split(",").map((value) => value.trim()).filter(Boolean),
            });
            setMsg("Updated " + dirInput.value, "ok");
            refresh();
          } catch (error) {
            setMsg(String(error), "err");
          }
        })));
  }

  menu = el("details", { class: "menu" },
    el("summary", { class: "icon-btn", title: "Folder actions", "aria-label": "Folder actions" }, "⋯"),
    el("div", { class: "menu-panel" },
      btn("Share", "ghost", share),
      btn("Unshare", "ghost", unshare),
      btn("MLS status", "ghost", mlsStatus),
      btn("Migrate MLS", "ghost", migrate),
      el("div", { class: "menu-sep" }),
      btn("Remove from sync", "danger", remove)));

  display();
  return li;
}

function renderAccount(account, status) {
  const card = el("article", { class: "card account" });
  const e2ee = E2EE[status] || E2EE.unknown;
  const initial = (account.username.trim()[0] || "?").toUpperCase();
  const open = account.signed_in
    ? btn("Open", "small ghost", () => invoke("open_account", { server: account.server }).catch((error) => setMsg(String(error), "err")))
    : null;

  const head = el("header", { class: "account-head" },
    el("span", { class: "avatar", "aria-hidden": "true" }, initial),
    el("div", { class: "account-id" },
      el("h2", { class: "who" }, account.username),
      el("div", { class: "host" }, account.server)),
    el("div", { class: "account-meta" },
      badge(account.signed_in ? "Signed in" : "Signed out", account.signed_in ? "ok" : "muted"),
      badge(e2ee.label, e2ee.kind)));
  if (open) head.append(open);
  card.append(head);

  if (!account.signed_in) {
    const password = el("input", {
      type: "password",
      placeholder: "Password",
      autocomplete: "current-password",
    });
    const form = el("form", {
      class: "inline-form",
      onsubmit: async (event) => {
        event.preventDefault();
        try {
          await invoke("sign_in", {
            server: account.server,
            username: account.username,
            password: password.value,
          });
          setMsg("Signed in to " + account.username, "ok");
          refresh();
        } catch (error) {
          setMsg(String(error), "err");
        }
      },
    }, password, el("button", { class: "btn primary", type: "submit" }, "Sign in"));
    card.append(el("div", { class: "signed-out" },
      el("p", { class: "muted" }, "Sign in again to resume sync and manage encryption."),
      form));
  }

  const count = account.pairs.length;
  card.append(el("div", { class: "section-head" },
    el("h3", {}, "Synced folders"),
    el("span", { class: "muted" }, count + (count === 1 ? " folder" : " folders"))));

  const pairs = el("ul", { class: "pairs" });
  if (!count) pairs.append(emptyRow("No synced folders yet."));
  for (const pair of account.pairs) pairs.append(renderPair(account, pair, account.signed_in));
  card.append(pairs);

  const e2eeBody = el("div", { class: "section-body" });
  if (status === "none") {
    const pass = el("input", {
      type: "password",
      placeholder: "New passphrase",
      autocomplete: "new-password",
    });
    const confirmPass = el("input", {
      type: "password",
      placeholder: "Repeat passphrase",
      autocomplete: "new-password",
    });
    const recovery = el("div");
    e2eeBody.append(
      el("p", { class: "muted" }, "Encryption is not set up for this account yet. Choose a passphrase — it never leaves this computer."),
      el("div", { class: "form-grid" },
        field("New passphrase", pass),
        field("Repeat passphrase", confirmPass)),
      el("div", { class: "form-actions" },
        btn("Set up encryption", "primary", async () => {
          if (pass.value !== confirmPass.value) {
            setMsg("Passphrases do not match", "err");
            return;
          }
          try {
            const code = await invoke("setup_e2ee", {
              server: account.server,
              username: account.username,
              passphrase: pass.value,
            });
            recovery.replaceChildren(
              el("p", { class: "muted" }, "Recovery phrase — 24 words, save them now, shown once:"),
              el("code", { class: "recovery-code" }, code),
              el("div", { class: "form-actions" },
                btn("I saved it", "primary", () => {
                  recovery.replaceChildren();
                  setMsg("Encryption set up", "ok");
                  refresh();
                })));
            setMsg("Save your recovery phrase (24 words), then click “I saved it”.", "ok");
          } catch (error) {
            setMsg(String(error), "err");
          }
        })),
      recovery);
  } else if (status === "locked") {
    const pass = el("input", {
      type: "password",
      placeholder: "Encryption passphrase",
      autocomplete: "off",
    });
    e2eeBody.append(
      el("p", { class: "muted" }, "Encryption is locked. Enter your passphrase to sync encrypted folders and approve new devices."),
      field("Encryption passphrase", pass),
      el("div", { class: "form-actions" },
        btn("Unlock", "primary", async () => {
          try {
            await invoke("set_e2ee_passphrase", {
              server: account.server,
              username: account.username,
              passphrase: pass.value,
            });
            setMsg("Encryption unlocked", "ok");
            refresh();
          } catch (error) {
            setMsg(String(error), "err");
          }
        })));
  } else if (status === "unlocked") {
    const autoApprove = el("input", {
      type: "checkbox",
      checked: account.auto_approve_devices !== false,
    });
    autoApprove.addEventListener("change", async () => {
      try {
        await invoke("set_auto_approve", {
          server: account.server,
          username: account.username,
          enabled: autoApprove.checked,
        });
        setMsg(autoApprove.checked
          ? "New devices will be approved automatically"
          : "New devices need manual approval", "ok");
      } catch (error) {
        setMsg(String(error), "err");
      }
    });
    e2eeBody.append(
      el("p", { class: "muted" }, "Encryption is unlocked — encrypted folders sync, and you can approve new devices."),
      el("div", { class: "setting-row compact" },
        el("div", { class: "setting-copy" },
          el("strong", {}, "Automatically approve new devices"),
          el("small", {}, "Uncheck if you don't fully trust the server.")),
        switchControl(autoApprove, "Automatically approve new devices")),
      el("div", { class: "form-actions" },
        btn("Forget passphrase", "ghost", async () => {
          if (!confirm("Forget the encryption passphrase? Encrypted folders will stay locked until you unlock again.")) return;
          try {
            await invoke("set_e2ee_passphrase", {
              server: account.server,
              username: account.username,
              passphrase: "",
            });
            setMsg("Encryption passphrase forgotten", "ok");
            refresh();
          } catch (error) {
            setMsg(String(error), "err");
          }
        })));
  } else {
    e2eeBody.append(el("p", { class: "muted" }, "Sign in to manage encryption."));
  }

  card.append(el("details", { class: "section" },
    el("summary", {},
      el("span", { class: "section-icon", html: ICON_LOCK }),
      "End-to-end encryption",
      badge(e2ee.label, e2ee.kind)),
    e2eeBody));

  if (account.signed_in && status !== "none") {
    const deviceName = el("input", { placeholder: "e.g. this laptop" });
    const enrollOut = el("div");
    const pendingList = el("ul", { class: "pairs" });
    const pinsList = el("ul", { class: "pairs" });

    async function refreshDevices() {
      try {
        const list = await invoke("list_enrollments", {
          server: account.server,
          username: account.username,
        });
        if (!list.length) {
          pendingList.replaceChildren(emptyRow("No pending enrollments"));
        } else {
          pendingList.replaceChildren(...list.map((enrollment) => {
            const codeInput = el("input", {
              placeholder: "Optional: type the code shown on the new device to verify it",
            });
            return el("li", { class: "stack-item" },
              el("div", { class: "pair-local" }, enrollment.name),
              el("div", { class: "pair-remote" }, "enrollment " + enrollment.id),
              codeInput,
              el("div", { class: "form-actions" },
                btn("Approve", "primary", async () => {
                  try {
                    const name = await invoke("approve_device", {
                      server: account.server,
                      username: account.username,
                      id: enrollment.id,
                      code: codeInput.value,
                    });
                    setMsg("Approved " + name + (codeInput.value.trim() ? " (code verified)" : ""), "ok");
                    refreshDevices();
                  } catch (error) {
                    setMsg(String(error), "err");
                  }
                })));
          }));
        }
      } catch (error) {
        // Listing needs a signed-in account; leave the empty state in place.
      }
      try {
        const pins = await invoke("recipient_fingerprints", {
          server: account.server,
          username: account.username,
        });
        if (!pins.length) {
          pinsList.replaceChildren(emptyRow("No recipient keys pinned yet"));
        } else {
          pinsList.replaceChildren(...pins.map((pin) =>
            el("li", { class: "stack-item" },
              el("div", { class: "pair-local" }, pin.member),
              el("div", { class: "path" }, pin.fingerprint))));
        }
      } catch (error) {
        // Ignore: pins are informational.
      }
    }

    const devicesBody = el("div", { class: "section-body" },
      el("p", { class: "muted" }, "Enroll this machine so it can sync encrypted folders without the passphrase, and review the keys pinned for people you share with."),
      status === "unlocked"
        ? null
        : el("p", { class: "error" }, "Unlock encryption above first — approving a device needs your master key."),
      field("Device name", deviceName),
      el("div", { class: "form-actions" },
        btn("Start enrollment", "primary", async () => {
          try {
            const view = await invoke("enroll_device", {
              server: account.server,
              username: account.username,
              name: deviceName.value,
            });
            enrollOut.replaceChildren(
              el("p", { class: "muted" }, "Enrollment " + view.id + " — compare this code on an approving device:"),
              el("div", { class: "path" }, view.code, " ", el("span", { class: "muted" }, "key " + view.fingerprint)),
              el("div", { class: "form-actions" },
                btn("Finish (wait for approval)", "ghost", async () => {
                  try {
                    await invoke("finish_enrollment", {
                      server: account.server,
                      username: account.username,
                    });
                    setMsg("This machine is enrolled", "ok");
                    enrollOut.replaceChildren();
                    refresh();
                  } catch (error) {
                    setMsg(String(error), "err");
                  }
                })));
          } catch (error) {
            setMsg(String(error), "err");
          }
        }),
        btn("Refresh", "ghost", refreshDevices)),
      enrollOut,
      el("div", { class: "section-subhead" }, "Pending enrollments"),
      pendingList,
      el("div", { class: "section-subhead" }, "Pinned recipient keys"),
      pinsList);
    card.append(el("details", { class: "section" },
      el("summary", {},
        el("span", { class: "section-icon", html: ICON_ACCOUNT }),
        "Devices & keys"),
      devicesBody));
    refreshDevices();
  }

  if (account.signed_in) {
    const dirInput = el("input", { placeholder: "~/Kolimi" });
    const remoteInput = el("input", { placeholder: "/" });
    const rootsInput = el("input", { placeholder: "e.g. Private, Photos (blank = no encryption)" });
    card.append(el("details", { class: "section" },
      el("summary", {},
        el("span", { class: "section-icon", html: ICON_FOLDER }),
        "Add synced folder"),
      el("div", { class: "section-body" },
        el("div", { class: "form-grid" },
          field("Local folder", dirInput),
          field("Remote folder (optional; default /)", remoteInput),
          field("Encrypted folders (relative, comma-separated)", rootsInput, "span-2")),
        el("div", { class: "form-actions" },
          btn("Add folder", "primary", async () => {
            try {
              await invoke("add_pair", {
                server: account.server,
                username: account.username,
                dir: dirInput.value,
                remote: remoteInput.value || "/",
                encryptedRoots: rootsInput.value.split(",").map((value) => value.trim()).filter(Boolean),
              });
              setMsg("Added " + dirInput.value, "ok");
              refresh();
            } catch (error) {
              setMsg(String(error), "err");
            }
          })))));
  }

  const foot = el("footer", { class: "account-foot" });
  if (account.signed_in) {
    foot.append(btn("Sign out", "ghost", async () => {
      try {
        await invoke("sign_out", {
          server: account.server,
          username: account.username,
        });
        setMsg("Signed out of " + account.username, "ok");
        refresh();
      } catch (error) {
        setMsg(String(error), "err");
      }
    }));
  }
  foot.append(btn("Remove account", "danger", async () => {
    if (!confirm("Remove " + account.username + " and its synced directories?")) return;
    try {
      await invoke("remove_account", {
        server: account.server,
        username: account.username,
      });
      setMsg("Removed " + account.username, "ok");
      refresh();
    } catch (error) {
      setMsg(String(error), "err");
    }
  }));
  card.append(foot);

  return card;
}

async function refresh() {
  const settings = await invoke("get_settings");
  $("autostart").checked = Boolean(settings.autostart);
  const statuses = await Promise.all(settings.accounts.map(async (account) => {
    if (!account.signed_in) return "signed_out";
    try {
      return await invoke("e2ee_status", {
        server: account.server,
        username: account.username,
      });
    } catch (error) {
      return "unknown";
    }
  }));
  const cards = settings.accounts.map((account, index) => renderAccount(account, statuses[index]));
  if (!cards.length) cards.push(emptyState());
  accountsEl.replaceChildren(...cards);
  const count = settings.accounts.length;
  $("account-count").textContent = count + (count === 1 ? " account" : " accounts");
  if (!count) $("add-account").open = true;
}

function currentTheme() {
  const explicit = document.documentElement.dataset.theme;
  if (explicit === "light" || explicit === "dark") return explicit;
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function updateThemeButton() {
  const button = $("theme");
  const dark = currentTheme() === "dark";
  button.innerHTML = dark ? ICON_SUN : ICON_MOON;
  const label = dark ? "Switch to light theme" : "Switch to dark theme";
  button.title = label;
  button.setAttribute("aria-label", label);
}

function applyTheme(theme) {
  if (theme === "light" || theme === "dark") {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem(THEME_KEY, theme);
  } else {
    delete document.documentElement.dataset.theme;
    localStorage.removeItem(THEME_KEY);
  }
  updateThemeButton();
}

$("signin-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const server = $("new-server").value;
  const username = $("new-username").value;
  const password = $("new-password").value;
  setMsg("Signing in…");
  try {
    await invoke("sign_in", { server, username, password });
    $("new-password").value = "";
    setMsg("Signed in to " + username, "ok");
    $("add-account").open = false;
    refresh();
  } catch (error) {
    setMsg(String(error), "err");
  }
});

$("autostart").addEventListener("change", async (event) => {
  try {
    await invoke("set_autostart_enabled", { enabled: event.target.checked });
  } catch (error) {
    setMsg(String(error), "err");
  }
});

$("sync-now").addEventListener("click", async () => {
  const button = $("sync-now");
  button.disabled = true;
  try {
    await invoke("sync_now");
    setMsg("Sync started — see the tray for status", "ok");
  } catch (error) {
    setMsg(String(error), "err");
  } finally {
    setTimeout(() => {
      button.disabled = false;
    }, 600);
  }
});

$("theme").addEventListener("click", () => {
  applyTheme(currentTheme() === "dark" ? "light" : "dark");
});

window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
  if (!localStorage.getItem(THEME_KEY)) updateThemeButton();
});

document.addEventListener("click", (event) => {
  if (!event.target.closest("details.menu")) closeMenus();
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeMenus();
});

const savedTheme = localStorage.getItem(THEME_KEY);
if (savedTheme === "light" || savedTheme === "dark") {
  document.documentElement.dataset.theme = savedTheme;
}
updateThemeButton();

refresh().catch((error) => setMsg(String(error), "err"));
