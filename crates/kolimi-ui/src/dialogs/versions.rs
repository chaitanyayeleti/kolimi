use leptos::prelude::*;
use leptos::task::spawn_local;
use serde_json::{Value, json};

use crate::api;
use crate::app::{encode, human_size, relative_time};
use crate::components::Icon;

#[component]
pub(crate) fn VersionsDialog(
    path: String,
    name: String,
    on_close: Callback<()>,
    on_restored: Callback<()>,
) -> impl IntoView {
    let versions = RwSignal::new(Vec::<Value>::new());
    let error = RwSignal::new(String::new());
    let busy = RwSignal::new(false);

    let load = {
        let path = path.clone();
        Callback::new(move |_: ()| {
            let path = path.clone();
            spawn_local(async move {
                match api::get(&format!("/api/versions?path={}", encode(&path))).await {
                    Ok(r) if r.status == 200 => {
                        versions.set(r.body.as_array().cloned().unwrap_or_default());
                    }
                    Ok(r) => error.set(r.error().unwrap_or("Could not load versions").to_string()),
                    Err(e) => error.set(e),
                }
            });
        })
    };
    Effect::new(move |_| load.run(()));

    let restore = {
        let path = path.clone();
        Callback::new(move |id: i64| {
            let path = path.clone();
            busy.set(true);
            spawn_local(async move {
                match api::send_json(
                    "POST",
                    &format!("/api/versions/{id}/restore"),
                    &json!({ "path": path }),
                )
                .await
                {
                    Ok(r) if r.status == 200 => {
                        busy.set(false);
                        load.run(());
                        on_restored.run(());
                    }
                    Ok(r) => {
                        busy.set(false);
                        error.set(r.error().unwrap_or("Restore failed").to_string());
                    }
                    Err(e) => {
                        busy.set(false);
                        error.set(e);
                    }
                }
            });
        })
    };

    let close = move |_| on_close.run(());

    view! {
        <div class="backdrop">
            <div class="card modal">
                <div class="modal-head">
                    <h2>{format!("Versions of “{name}”")}</h2>
                    <button class="icon-btn" aria-label="Close" on:click=close>
                        <Icon name="x"/>
                    </button>
                </div>
                <p class="muted">"Restoring a version makes it current; the replaced content is kept as a version too."</p>
                <ul class="shares">
                    <For
                        each=move || versions.get()
                        key=|v| v["id"].as_i64().unwrap_or(0)
                        children=move |v| {
                            let id = v["id"].as_i64().unwrap_or(0);
                            let size = v["size"].as_u64().unwrap_or(0);
                            let when = v["created_at"].as_i64().unwrap_or(0);
                            view! {
                                <li class="row">
                                    <span class="name">
                                        <span class="lead-icon">
                                            <Icon name="history"/>
                                        </span>
                                        {format!("{} · {}", human_size(size), relative_time(when))}
                                    </span>
                                    <span class="row-actions">
                                        <button
                                            class="ghost"
                                            disabled=move || busy.get()
                                            on:click=move |_| restore.run(id)
                                        >
                                            "Restore"
                                        </button>
                                    </span>
                                </li>
                            }
                        }
                    />
                    <Show when=move || versions.get().is_empty()>
                        <li class="row muted">"No older versions."</li>
                    </Show>
                </ul>
                <p class="error">{move || error.get()}</p>
            </div>
        </div>
    }
}
