// Initialises the WebAssembly UI. Loaded as an external module because
// the served Content-Security-Policy (script-src 'self') forbids inline
// scripts; the generated app.js resolves app_bg.wasm relative to itself.
import init from "./app.js";

// Theme: restore the saved choice before first paint. The WASM app toggles
// the `.dark` / `.light` classes on <html> itself.
try {
  const saved = localStorage.getItem("kolimi-theme");
  if (saved === "light" || saved === "dark") {
    document.documentElement.classList.add(saved);
  }
} catch (_) {
  /* localStorage may be unavailable; fall back to the OS preference. */
}

init();
