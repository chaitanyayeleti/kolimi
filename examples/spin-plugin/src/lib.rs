//! Test fixture: a plugin that never returns, proving the fuel limit
//! stops runaway plugins.

#[allow(warnings)]
mod bindings;

use bindings::exports::kolimi::plugin::api::{Guest, Request, Response};

struct Component;

impl Guest for Component {
    fn handle(_request: Request) -> Response {
        let mut counter: u64 = 0;
        loop {
            counter = counter.wrapping_add(1);
            std::hint::black_box(counter);
        }
    }
}

bindings::export!(Component with_types_in bindings);
