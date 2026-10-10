//! Kolimi web UI: a Leptos client-side application compiled to WebAssembly
//! and embedded in the server binary.
//!
//! The whole crate is wasm-only: on non-wasm targets it compiles to an
//! empty library so workspace lint/test runs stay fast.

#![cfg(target_arch = "wasm32")]

mod api;
mod app;
mod public;

use leptos::mount::mount_to_body;
use leptos::prelude::view;
use wasm_bindgen::prelude::wasm_bindgen;

/// Entry point invoked by `wasm-bindgen` on instantiation.
#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
    let pathname = web_sys::window()
        .and_then(|window| window.location().pathname().ok())
        .unwrap_or_default();
    if let Some(token) = pathname.strip_prefix("/s/") {
        let token = token.trim_matches('/').to_string();
        mount_to_body(move || view! { <public::PublicApp token=token.clone()/> });
    } else {
        mount_to_body(app::App);
    }
}
