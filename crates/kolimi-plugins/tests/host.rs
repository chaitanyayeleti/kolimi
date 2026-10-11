//! Plugin host tests against the committed example fixtures.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use kolimi_plugins::{PluginError, PluginHost, PluginRequest};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn setup() -> (tempfile::TempDir, PluginHost) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("hello.wasm"), fixture("hello.wasm")).unwrap();
    std::fs::write(
        dir.path().join("hello.json"),
        r#"{"name":"hello","version":"0.1.0","description":"greeting + kv counter","enabled":true}"#,
    )
    .unwrap();
    std::fs::write(dir.path().join("spin.wasm"), fixture("spin.wasm")).unwrap();
    std::fs::write(dir.path().join("spin.json"), r#"{"name":"spin"}"#).unwrap();
    std::fs::write(dir.path().join("off.wasm"), fixture("hello.wasm")).unwrap();
    std::fs::write(
        dir.path().join("off.json"),
        r#"{"name":"off","enabled":false}"#,
    )
    .unwrap();
    let host = PluginHost::load(dir.path()).unwrap();
    (dir, host)
}

fn request(path: &str, body: &[u8]) -> PluginRequest {
    PluginRequest {
        method: "POST".to_string(),
        path: path.to_string(),
        user: "alice".to_string(),
        body: body.to_vec(),
    }
}

#[test]
fn hello_plugin_greets_echoes_and_counts() {
    let (_dir, host) = setup();
    assert_eq!(host.list().len(), 3);

    let response = host.invoke("hello", &request("/", b"")).unwrap();
    assert_eq!(response.status, 200);
    let text = String::from_utf8(response.body).unwrap();
    assert!(text.contains("hello from plugin, alice"), "{text}");

    let response = host.invoke("hello", &request("/echo", b"ping")).unwrap();
    assert_eq!(response.body, b"ping");

    // The plugin-private KV store persists across calls.
    let first = host.invoke("hello", &request("/counter", b"")).unwrap();
    assert!(String::from_utf8(first.body).unwrap().contains("hits: 1"));
    let second = host.invoke("hello", &request("/counter", b"")).unwrap();
    assert!(String::from_utf8(second.body).unwrap().contains("hits: 2"));
}

#[test]
fn kv_store_persists_across_reloads() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("hello.wasm"), fixture("hello.wasm")).unwrap();
    std::fs::write(dir.path().join("hello.json"), r#"{"name":"hello"}"#).unwrap();

    let host = PluginHost::load(dir.path()).unwrap();
    let first = host.invoke("hello", &request("/counter", b"")).unwrap();
    assert!(String::from_utf8(first.body).unwrap().contains("hits: 1"));
    drop(host);

    let host = PluginHost::load(dir.path()).unwrap();
    let second = host.invoke("hello", &request("/counter", b"")).unwrap();
    assert!(String::from_utf8(second.body).unwrap().contains("hits: 2"));
    assert!(dir.path().join("hello.kv.json").is_file());
}

#[test]
fn fuel_limit_stops_runaway_plugins() {
    let (_dir, host) = setup();
    let started = std::time::Instant::now();
    let error = host.invoke("spin", &request("/", b"")).unwrap_err();
    assert!(
        matches!(error, PluginError::Trap(ref message) if message.contains("fuel")),
        "{error}"
    );
    // Fuel burns fast enough that this is a fraction of a second.
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

#[test]
fn unknown_and_disabled_plugins() {
    let (_dir, host) = setup();
    assert!(matches!(
        host.invoke("nope", &request("/", b"")),
        Err(PluginError::Unknown(_))
    ));
    assert!(matches!(
        host.invoke("off", &request("/", b"")),
        Err(PluginError::Disabled(_))
    ));
}

#[test]
fn sandbox_surface_is_capability_scoped() {
    let (_dir, host) = setup();
    let imports = host.imports("hello");
    // The plugin interface is present...
    assert!(
        imports
            .iter()
            .any(|name| name.contains("kolimi:plugin/host")),
        "{imports:?}"
    );
    // ...the guest's std links WASI (filesystem/preopens interfaces are
    // in the import list) but the context is empty, which the /read test
    // proves behaviorally. No sockets are linked at all.
    assert!(
        !imports.iter().any(|name| name.contains("sockets")),
        "{imports:?}"
    );
}

#[test]
fn plugin_cannot_read_the_host_filesystem() {
    let (_dir, host) = setup();
    let response = host.invoke("hello", &request("/read", b"")).unwrap();
    let text = String::from_utf8(response.body).unwrap();
    assert!(text.starts_with("denied:"), "{text}");
}

#[test]
fn broken_plugins_are_skipped_not_fatal() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("broken.wasm"), b"not wasm at all").unwrap();
    std::fs::write(dir.path().join("broken.json"), r#"{"name":"broken"}"#).unwrap();
    std::fs::write(dir.path().join("hello.wasm"), fixture("hello.wasm")).unwrap();
    std::fs::write(dir.path().join("hello.json"), r#"{"name":"hello"}"#).unwrap();

    let host = PluginHost::load(dir.path()).unwrap();
    assert_eq!(host.list().len(), 1);
    assert_eq!(host.list()[0].name, "hello");
    assert!(host.invoke("hello", &request("/", b"")).is_ok());
}

#[test]
fn missing_directory_is_no_plugins() {
    let dir = tempfile::tempdir().unwrap();
    let host = PluginHost::load(&dir.path().join("does-not-exist")).unwrap();
    assert!(host.list().is_empty());
}

fn _unused(_: &Path) {}
