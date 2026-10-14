//! Sandboxed WebAssembly plugin host (component model).
//!
//! Plugins are `.wasm` components built against `wit/plugin.wit`. The
//! sandbox is the import list: a plugin can only call the host functions
//! in `kolimi:plugin/host` (logging, a private key-value store, the
//! clock). There is no filesystem, network, process, or clock-namespace
//! access, and every call runs with a fuel budget and a memory cap, so a
//! runaway or hostile plugin cannot take the server down.
//!
//! Layout on disk:
//!
//! ```text
//! plugins/
//!   hello.wasm     the component
//!   hello.json     { "name", "version", "description", "enabled" }
//!   hello.kv.json  plugin-private key-value store (created on demand)
//! ```

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use wasmtime::component::{Component, HasSelf, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

wasmtime::component::bindgen!({
    path: "wit",
    world: "plugin",
});

/// Fuel budget per plugin call (roughly hundreds of millions of
/// instructions; a runaway loop traps instead of hanging the server).
pub const FUEL_PER_CALL: u64 = 500_000_000;
/// Memory cap per plugin instance.
pub const MEMORY_LIMIT: usize = 16 * 1024 * 1024;

/// Plugin metadata (`<name>.json` next to the component).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMeta {
    /// Unique name (also the route segment).
    pub name: String,
    /// Free-form version.
    #[serde(default)]
    pub version: String,
    /// Human-readable description.
    #[serde(default)]
    pub description: String,
    /// Whether the plugin may be invoked.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// A request handed to a plugin.
#[derive(Debug, Clone)]
pub struct PluginRequest {
    /// HTTP method.
    pub method: String,
    /// Sub-path under `/plugins/<name>`.
    pub path: String,
    /// Authenticated username.
    pub user: String,
    /// Request body (capped by the caller).
    pub body: Vec<u8>,
}

/// A response produced by a plugin.
#[derive(Debug, Clone)]
pub struct PluginResponse {
    /// HTTP status suggested by the plugin.
    pub status: u16,
    /// Content type.
    pub content_type: String,
    /// Body bytes.
    pub body: Vec<u8>,
}

/// Errors from the plugin host.
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    /// No plugin with that name.
    #[error("unknown plugin: {0}")]
    Unknown(String),
    /// The plugin is installed but disabled.
    #[error("plugin is disabled: {0}")]
    Disabled(String),
    /// The plugin trapped (fuel exhausted, panic, bad memory access).
    #[error("plugin trapped: {0}")]
    Trap(String),
    /// Loading or host-side failure.
    #[error("plugin host: {0}")]
    Internal(String),
}

struct Loaded {
    meta: PluginMeta,
    component: Component,
    kv: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    kv_path: PathBuf,
}

struct StoreData {
    plugin: String,
    kv: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    kv_path: PathBuf,
    limits: StoreLimits,
    /// WASI with *zero* capabilities: no preopened directories, no
    /// sockets, no environment, no arguments.
    wasi: WasiCtx,
    table: ResourceTable,
}

impl WasiView for StoreData {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

impl kolimi::plugin::host::Host for StoreData {
    fn log(&mut self, level: String, message: String) {
        match level.as_str() {
            "error" => tracing::error!(plugin = %self.plugin, "{message}"),
            "warn" => tracing::warn!(plugin = %self.plugin, "{message}"),
            "debug" => tracing::debug!(plugin = %self.plugin, "{message}"),
            _ => tracing::info!(plugin = %self.plugin, "{message}"),
        }
    }

    fn now_millis(&mut self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0)
    }

    fn kv_get(&mut self, key: String) -> Option<Vec<u8>> {
        self.kv.lock().ok()?.get(&key).cloned()
    }

    fn kv_set(&mut self, key: String, value: Vec<u8>) {
        let Ok(mut map) = self.kv.lock() else {
            return;
        };
        map.insert(key, value);
        if let Ok(json) = serde_json::to_vec(&*map)
            && let Err(error) = std::fs::write(&self.kv_path, json)
        {
            tracing::warn!(plugin = %self.plugin, %error, "could not persist plugin kv");
        }
    }
}

/// The plugin host: one engine, all loaded components.
pub struct PluginHost {
    engine: Engine,
    linker: Linker<StoreData>,
    plugins: BTreeMap<String, Loaded>,
}

impl PluginHost {
    /// Loads every `<name>.wasm` + `<name>.json` pair from `dir`.
    ///
    /// A missing directory means "no plugins". Broken plugins are logged
    /// and skipped: one bad component must not stop the server.
    pub fn load(dir: &Path) -> Result<Self, PluginError> {
        let mut config = Config::new();
        config.consume_fuel(true);
        let engine =
            Engine::new(&config).map_err(|error| PluginError::Internal(error.to_string()))?;

        let mut plugins = BTreeMap::new();
        if dir.is_dir() {
            let entries =
                std::fs::read_dir(dir).map_err(|error| PluginError::Internal(error.to_string()))?;
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|ext| ext.to_str()) != Some("wasm") {
                    continue;
                }
                let stem = path
                    .file_stem()
                    .map(|stem| stem.to_string_lossy().to_string())
                    .unwrap_or_default();
                let meta_path = dir.join(format!("{stem}.json"));
                let meta: PluginMeta = match std::fs::read(&meta_path)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                {
                    Some(meta) => meta,
                    None => {
                        tracing::warn!(plugin = %stem, "plugin has no valid metadata; skipped");
                        continue;
                    }
                };
                let bytes = match std::fs::read(&path) {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        tracing::warn!(plugin = %stem, %error, "cannot read plugin; skipped");
                        continue;
                    }
                };
                let component = match Component::from_binary(&engine, &bytes) {
                    Ok(component) => component,
                    Err(error) => {
                        tracing::warn!(plugin = %stem, %error, "invalid component; skipped");
                        continue;
                    }
                };
                // The guest std needs the WASI filesystem/clock/io imports, but
                // nothing needs the network: refuse any component that imports
                // wasi:sockets, so the linked sockets surface stays unused.
                let wants_network = component
                    .component_type()
                    .imports(&engine)
                    .any(|(import, _)| import.to_string().contains("sockets"));
                if wants_network {
                    tracing::warn!(plugin = %stem, "plugin imports wasi:sockets; skipped");
                    continue;
                }
                let kv_path = dir.join(format!("{stem}.kv.json"));
                let kv = std::fs::read(&kv_path).ok().and_then(|bytes| {
                    serde_json::from_slice::<BTreeMap<String, Vec<u8>>>(&bytes).ok()
                });
                let kv = match kv {
                    Some(kv) => kv,
                    None => {
                        tracing::warn!(plugin = %meta.name, path = %kv_path.display(), "KV file missing or corrupted; starting with empty store");
                        BTreeMap::new()
                    }
                };
                tracing::info!(plugin = %meta.name, version = %meta.version, "plugin loaded");
                if plugins.contains_key(&meta.name) {
                    tracing::warn!(plugin = %meta.name, "duplicate plugin name; previous plugin overwritten");
                }
                plugins.insert(
                    meta.name.clone(),
                    Loaded {
                        meta,
                        component,
                        kv: Arc::new(Mutex::new(kv)),
                        kv_path,
                    },
                );
            }
        }
        // Build the linker once: it is immutable and shared by every call.
        let mut linker = Linker::new(&engine);
        kolimi::plugin::host::add_to_linker::<StoreData, HasSelf<StoreData>>(&mut linker, |data| {
            data
        })
        .map_err(|error| PluginError::Internal(error.to_string()))?;
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker)
            .map_err(|error| PluginError::Internal(error.to_string()))?;
        Ok(Self {
            engine,
            linker,
            plugins,
        })
    }

    /// Metadata for all loaded plugins.
    pub fn list(&self) -> Vec<PluginMeta> {
        self.plugins
            .values()
            .map(|loaded| loaded.meta.clone())
            .collect()
    }

    /// The component's import names (the sandbox surface).
    pub fn imports(&self, name: &str) -> Vec<String> {
        let Some(loaded) = self.plugins.get(name) else {
            return Vec::new();
        };
        let mut names = Vec::new();
        for (import, _) in loaded.component.component_type().imports(&self.engine) {
            names.push(import.to_string());
        }
        names
    }

    /// Invokes a plugin. Blocking (fuel-bounded): callers should run it
    /// on a blocking thread.
    pub fn invoke(
        &self,
        name: &str,
        request: &PluginRequest,
    ) -> Result<PluginResponse, PluginError> {
        let Some(loaded) = self.plugins.get(name) else {
            return Err(PluginError::Unknown(name.to_string()));
        };
        if !loaded.meta.enabled {
            return Err(PluginError::Disabled(name.to_string()));
        }

        let mut store = Store::new(
            &self.engine,
            StoreData {
                plugin: name.to_string(),
                kv: loaded.kv.clone(),
                kv_path: loaded.kv_path.clone(),
                limits: StoreLimitsBuilder::new()
                    .memory_size(MEMORY_LIMIT)
                    .instances(4)
                    .tables(4)
                    .build(),
                wasi: WasiCtxBuilder::new().build(),
                table: ResourceTable::new(),
            },
        );
        store
            .set_fuel(FUEL_PER_CALL)
            .map_err(|error| PluginError::Internal(error.to_string()))?;
        store.limiter(|data| &mut data.limits);

        let bindings = Plugin::instantiate(&mut store, &loaded.component, &self.linker)
            .map_err(|error| PluginError::Trap(error.to_string()))?;
        let request = exports::kolimi::plugin::api::Request {
            method: request.method.clone(),
            path: request.path.clone(),
            user: request.user.clone(),
            body: request.body.clone(),
        };
        let response = bindings
            .kolimi_plugin_api()
            .call_handle(&mut store, &request)
            .map_err(|error| {
                let out_of_fuel = matches!(
                    error.downcast_ref::<wasmtime::Trap>(),
                    Some(wasmtime::Trap::OutOfFuel)
                );
                if out_of_fuel {
                    PluginError::Trap(format!("{name}: fuel exhausted"))
                } else {
                    PluginError::Trap(format!("{name}: {error}"))
                }
            })?;
        Ok(PluginResponse {
            status: response.status,
            content_type: response.content_type,
            body: response.body,
        })
    }
}
