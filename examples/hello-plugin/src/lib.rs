//! Example Kolimi plugin.
//!
//! `GET /plugins/hello/`            → a greeting for the signed-in user
//! `POST /plugins/hello/echo`       → echoes the request body
//! `GET /plugins/hello/counter`     → increments a value in the plugin's
//!                                    private key-value store

#[allow(warnings)]
mod bindings;

use bindings::exports::kolimi::plugin::api::{Guest, Request, Response};
use bindings::kolimi::plugin::host;

struct Component;

impl Guest for Component {
    fn handle(request: Request) -> Response {
        match request.path.as_str() {
            "/echo" => Response {
                status: 200,
                content_type: "text/plain".to_string(),
                body: request.body,
            },
            "/counter" => {
                let current = host::kv_get("hits")
                    .and_then(|bytes| String::from_utf8(bytes).ok())
                    .and_then(|text| text.parse::<u64>().ok())
                    .unwrap_or(0);
                let next = current + 1;
                host::kv_set("hits", next.to_string().as_bytes());
                Response {
                    status: 200,
                    content_type: "text/plain".to_string(),
                    body: format!("hits: {next}\nuser: {}\n", request.user).into_bytes(),
                }
            }
            // Sandbox proof: with no preopened directories this fails.
            "/read" => {
                let body = match std::fs::read_to_string("/etc/hostname") {
                    Ok(text) => format!("unexpectedly read {} bytes", text.len()),
                    Err(error) => format!("denied: {error}"),
                };
                Response {
                    status: 200,
                    content_type: "text/plain".to_string(),
                    body: body.into_bytes(),
                }
            }
            _ => {
                host::log(
                    "info",
                    &format!("hello-plugin got {} {}", request.method, request.path),
                );
                Response {
                    status: 200,
                    content_type: "text/plain".to_string(),
                    body: format!("hello from plugin, {}!\n", request.user).into_bytes(),
                }
            }
        }
    }
}

bindings::export!(Component with_types_in bindings);
