//! Plugin routes: `/plugins/{name}[/{path}]` and `/api/plugins`.
//!
//! Plugin calls run on blocking threads (wasmtime is synchronous) and
//! every call is fuel- and memory-bounded by the host.

use axum::{
    Extension, Json,
    body::{Body, to_bytes},
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use kolimi_auth::CurrentUser;
use kolimi_plugins::{PluginError, PluginRequest};
use serde_json::json;

use crate::{AppState, api, audit};

/// Maximum request body forwarded to a plugin.
const MAX_PLUGIN_BODY: usize = 1024 * 1024;

/// `GET /api/plugins` — installed plugins.
pub async fn list(
    State(state): State<AppState>,
    Extension(_user): Extension<CurrentUser>,
) -> Response {
    Json(json!({ "plugins": state.plugins.list() })).into_response()
}

/// `GET|POST /plugins/{name}` — root path.
pub async fn handle_root(
    state: State<AppState>,
    user: Extension<CurrentUser>,
    Path(name): Path<String>,
    method: axum::http::Method,
    body: Body,
) -> Response {
    invoke(state, user, name, String::new(), method, body).await
}

/// `GET|POST /plugins/{name}/{*rest}` — sub-paths.
pub async fn handle_path(
    state: State<AppState>,
    user: Extension<CurrentUser>,
    Path((name, rest)): Path<(String, String)>,
    method: axum::http::Method,
    body: Body,
) -> Response {
    invoke(state, user, name, rest, method, body).await
}

async fn invoke(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    name: String,
    rest: String,
    method: axum::http::Method,
    body: Body,
) -> Response {
    let body = match to_bytes(body, MAX_PLUGIN_BODY).await {
        Ok(bytes) => bytes.to_vec(),
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let request = PluginRequest {
        method: method.as_str().to_string(),
        path: format!("/{rest}"),
        user: user.username.clone(),
        body,
    };
    let host = state.plugins.clone();
    let plugin_name = name.clone();
    let result = tokio::task::spawn_blocking(move || host.invoke(&plugin_name, &request)).await;

    match result {
        Ok(Ok(response)) => {
            let status =
                StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let mut http = Response::new(Body::from(response.body));
            *http.status_mut() = status;
            let content_type = HeaderValue::from_str(&response.content_type)
                .unwrap_or_else(|_| HeaderValue::from_static("text/plain"));
            http.headers_mut()
                .insert(header::CONTENT_TYPE, content_type);
            http
        }
        Ok(Err(error)) => plugin_error(&state, &user, &name, error).await,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn plugin_error(
    state: &AppState,
    user: &CurrentUser,
    name: &str,
    error: PluginError,
) -> Response {
    match error {
        PluginError::Unknown(_) | PluginError::Disabled(_) => api::not_found(),
        PluginError::Trap(message) | PluginError::Internal(message) => {
            tracing::error!(plugin = %name, %message, "plugin call failed");
            audit(
                state,
                Some(user.user_id),
                Some(&user.username),
                "plugin.error",
                name,
                json!({ "message": message }),
            )
            .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "plugin failed" })),
            )
                .into_response()
        }
    }
}
