// Web Worker: derive the passphrase KEK off the main thread.
// The wasm module is built by scripts/build-ui.sh (kdf.js + kdf_bg.wasm).
import init, { derive_kek } from "./kdf.js";

const ready = init();

self.onmessage = async (event) => {
  const { passphrase, salt, m_cost, t_cost, p_cost } = event.data;
  try {
    await ready;
    const kek = derive_kek(passphrase, salt, m_cost, t_cost, p_cost);
    self.postMessage({ kek }, [kek.buffer]);
  } catch (error) {
    self.postMessage({ error: String(error) });
  }
};
