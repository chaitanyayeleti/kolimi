//! Fetch helpers: JSON API calls and raw WebDAV requests.

use gloo_net::http::Request;
use serde_json::Value;
use wasm_bindgen::JsCast;
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

/// A raw WebDAV response: status plus the near-quota warning, if any.
pub struct DavResponse {
    /// HTTP status.
    pub status: u16,
    /// Quota-usage percentage when the server warns (at or above 90%).
    pub quota_warning: Option<u8>,
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
    let status = response.status();
    let quota_warning = response
        .headers()
        .get("x-kolimi-quota-warning")
        .ok()
        .flatten()
        .and_then(|value| value.parse::<u8>().ok());
    Ok(DavResponse {
        status,
        quota_warning,
    })
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
