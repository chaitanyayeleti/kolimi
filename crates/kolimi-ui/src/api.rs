//! Fetch helpers: JSON API calls and raw WebDAV requests.

use gloo_net::http::Request;
use serde_json::Value;
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use wasm_bindgen_futures::JsFuture;
use web_sys::{RequestCredentials, RequestInit};

/// A JSON response with its status code.
pub struct ApiResponse {
    /// HTTP status.
    pub status: u16,
    /// Parsed body (`Null` when not JSON).
    pub body: Value,
}

impl ApiResponse {
    /// The `error` field of the body, if any.
    pub fn error(&self) -> Option<&str> {
        self.body.get("error").and_then(Value::as_str)
    }
}

fn csrf_token() -> Option<String> {
    let document = web_sys::window()?.document()?;
    let html: web_sys::HtmlDocument = document.dyn_into().ok()?;
    let cookies = html.cookie().ok()?;
    for pair in cookies.split(';') {
        if let Some(value) = pair.trim().strip_prefix("kolimi_csrf=") {
            return Some(value.to_string());
        }
    }
    None
}

async fn to_api(response: gloo_net::http::Response) -> Result<ApiResponse, String> {
    let status = response.status();
    let text = response.text().await.map_err(|e| e.to_string())?;
    let body = serde_json::from_str(&text).unwrap_or(Value::Null);
    Ok(ApiResponse { status, body })
}

/// GET a JSON endpoint.
pub async fn get(url: &str) -> Result<ApiResponse, String> {
    let response = Request::get(url).send().await.map_err(|e| e.to_string())?;
    to_api(response).await
}

/// GET a raw binary endpoint (E2EE ciphertext chunks).
pub async fn get_bytes(url: &str) -> Result<Vec<u8>, String> {
    let response = Request::get(url).send().await.map_err(|e| e.to_string())?;
    if response.status() != 200 {
        return Err(format!("HTTP {}", response.status()));
    }
    response.binary().await.map_err(|e| e.to_string())
}

/// POST/PATCH a JSON endpoint with a CSRF token.
pub async fn send_json(method: &str, url: &str, value: &Value) -> Result<ApiResponse, String> {
    let mut builder = match method {
        "PATCH" => Request::patch(url),
        "PUT" => Request::put(url),
        _ => Request::post(url),
    };
    if let Some(token) = csrf_token() {
        builder = builder.header("X-CSRF-Token", &token);
    }
    let request = builder.json(value).map_err(|e| e.to_string())?;
    let response = request.send().await.map_err(|e| e.to_string())?;
    to_api(response).await
}

/// DELETE a JSON endpoint with a CSRF token.
pub async fn delete(url: &str) -> Result<ApiResponse, String> {
    let mut builder = Request::delete(url);
    if let Some(token) = csrf_token() {
        builder = builder.header("X-CSRF-Token", &token);
    }
    let request = builder.build().map_err(|e| e.to_string())?;
    let response = request.send().await.map_err(|e| e.to_string())?;
    to_api(response).await
}

/// A raw WebDAV response.
pub struct DavResponse {
    /// HTTP status.
    pub status: u16,
}

/// A raw `fetch` for WebDAV methods (PUT, MKCOL, MOVE, DELETE).
pub async fn dav(
    method: &str,
    url: &str,
    body: Option<Vec<u8>>,
    headers: &[(&str, &str)],
) -> Result<DavResponse, String> {
    let window = web_sys::window().ok_or("no window")?;
    let init = RequestInit::new();
    init.set_method(method);
    init.set_credentials(RequestCredentials::SameOrigin);
    if let Some(bytes) = &body {
        init.set_body(&js_sys::Uint8Array::from(bytes.as_slice()));
    }
    let header_map = web_sys::Headers::new().map_err(|e| format!("{e:?}"))?;
    for (name, value) in headers {
        header_map.set(name, value).map_err(|e| format!("{e:?}"))?;
    }
    // Cookie-authenticated unsafe DAV methods need the double-submit token.
    if let Some(token) = csrf_token() {
        header_map
            .set("X-CSRF-Token", &token)
            .map_err(|e| format!("{e:?}"))?;
    }
    init.set_headers(&header_map);
    let request =
        web_sys::Request::new_with_str_and_init(url, &init).map_err(|e| format!("{e:?}"))?;
    let response = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| format!("{e:?}"))?;
    let response: web_sys::Response = response.dyn_into().map_err(|e| format!("{e:?}"))?;
    Ok(DavResponse {
        status: response.status(),
    })
}

/// Uploads `bytes` to `url` via `XMLHttpRequest`, reporting upload progress
/// (0..=100) and then the HTTP status. Used for the upload tray, where
/// `fetch` cannot report upload progress.
pub fn upload(
    url: &str,
    bytes: Vec<u8>,
    on_progress: impl Fn(u8) + 'static,
    on_done: impl FnOnce(Result<(u16, Option<u8>), String>) + 'static,
) {
    use std::cell::RefCell;
    use std::rc::Rc;

    let Ok(xhr) = web_sys::XmlHttpRequest::new() else {
        on_done(Err("could not create the request".to_string()));
        return;
    };
    if xhr.open("PUT", url).is_err() {
        on_done(Err("could not open the request".to_string()));
        return;
    }
    xhr.set_with_credentials(true);
    if let Some(token) = csrf_token() {
        let _ = xhr.set_request_header("X-CSRF-Token", &token);
    }

    if let Ok(upload) = xhr.upload() {
        let progress = Rc::new(on_progress);
        let handler = Closure::<dyn FnMut(web_sys::ProgressEvent)>::new(
            move |event: web_sys::ProgressEvent| {
                if event.length_computable() {
                    let total = event.total();
                    if total > 0.0 {
                        let pct = ((event.loaded() / total) * 100.0).round().clamp(0.0, 100.0);
                        progress(pct as u8);
                    }
                }
            },
        );
        upload.set_onprogress(Some(handler.as_ref().unchecked_ref()));
        handler.forget();
    }

    let done = Rc::new(RefCell::new(Some(on_done)));
    let onload_done = done.clone();
    let xhr_for_load = xhr.clone();
    let onload = Closure::<dyn FnMut()>::new(move || {
        if let Some(callback) = onload_done.borrow_mut().take() {
            let status = xhr_for_load.status().unwrap_or(0);
            let warning = xhr_for_load
                .get_response_header("x-kolimi-quota-warning")
                .ok()
                .flatten()
                .and_then(|value| value.parse::<u8>().ok());
            callback(Ok((status, warning)));
        }
    });
    xhr.set_onload(Some(onload.as_ref().unchecked_ref()));
    onload.forget();

    let onerror_done = done.clone();
    let onerror = Closure::<dyn FnMut()>::new(move || {
        if let Some(callback) = onerror_done.borrow_mut().take() {
            callback(Err("upload failed".to_string()));
        }
    });
    xhr.set_onerror(Some(onerror.as_ref().unchecked_ref()));
    onerror.forget();

    let onabort_done = done.clone();
    let onabort = Closure::<dyn FnMut()>::new(move || {
        if let Some(callback) = onabort_done.borrow_mut().take() {
            callback(Err("upload cancelled".to_string()));
        }
    });
    xhr.set_onabort(Some(onabort.as_ref().unchecked_ref()));
    onabort.forget();

    let ontimeout_done = done.clone();
    let ontimeout = Closure::<dyn FnMut()>::new(move || {
        if let Some(callback) = ontimeout_done.borrow_mut().take() {
            callback(Err("upload timed out".to_string()));
        }
    });
    xhr.set_ontimeout(Some(ontimeout.as_ref().unchecked_ref()));
    ontimeout.forget();

    let array = js_sys::Uint8Array::from(bytes.as_slice());
    let _ = xhr.send_with_opt_buffer_source(Some(array.as_ref()));
}

/// Reads a file input's bytes.
pub async fn read_file(file: &web_sys::File) -> Result<Vec<u8>, String> {
    let buffer = JsFuture::from(file.array_buffer())
        .await
        .map_err(|e| format!("{e:?}"))?;
    let array = buffer
        .dyn_into::<js_sys::ArrayBuffer>()
        .map_err(|_| "not an ArrayBuffer".to_string())?;
    Ok(js_sys::Uint8Array::new(&array).to_vec())
}

/// Copies text to the clipboard.
pub async fn copy_to_clipboard(text: &str) {
    if let Some(window) = web_sys::window() {
        let clipboard = window.navigator().clipboard();
        let _ = JsFuture::from(clipboard.write_text(text)).await;
    }
}

/// Prompts for a single line of text.
pub fn prompt(message: &str, default: &str) -> Option<String> {
    let window = web_sys::window()?;
    window
        .prompt_with_message_and_default(message, default)
        .ok()
        .flatten()
}

/// Confirms a destructive action.
pub fn confirm(message: &str) -> bool {
    web_sys::window()
        .and_then(|window| window.confirm_with_message(message).ok())
        .unwrap_or(false)
}
