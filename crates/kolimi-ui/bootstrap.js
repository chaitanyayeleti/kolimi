// Initialises the WebAssembly UI. Loaded as an external module because
// the served Content-Security-Policy (script-src 'self') forbids inline
// scripts; the generated app.js resolves app_bg.wasm relative to itself.
import init from "./app.js";

init();
