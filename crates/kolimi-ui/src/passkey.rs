//! WebAuthn ceremonies for the browser UI (register + sign-in).
//!
//! The server speaks `webauthn-rs`'s wire format: base64url strings for
//! every binary field. The browser needs `ArrayBuffer`s, so this module
//! converts options on the way in and credentials on the way out.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

use crate::api;

fn decode(value: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| format!("bad base64url: {error}"))
}

fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn to_js(value: &Value) -> Result<JsValue, String> {
    let text = serde_json::to_string(value).map_err(|error| error.to_string())?;
    js_sys::JSON::parse(&text).map_err(|error| format!("{error:?}"))
}

fn set_buffer(object: &JsValue, field: &str, encoded: &str) -> Result<(), String> {
    let bytes = decode(encoded)?;
    let array = js_sys::Uint8Array::from(bytes.as_slice());
    js_sys::Reflect::set(object, &JsValue::from_str(field), &array)
        .map_err(|error| format!("{error:?}"))?;
    Ok(())
}

fn array_item(array: &JsValue, index: usize) -> Result<JsValue, String> {
    js_sys::Array::from(array)
        .get(index as u32)
        .dyn_into::<JsValue>()
        .map_err(|error| format!("{error:?}"))
}

/// Converts base64url option fields (`challenge`, `user.id`,
/// `excludeCredentials[].id`, `allowCredentials[].id`) into buffers.
fn prepare_options(options: &Value, descriptor_field: &str) -> Result<JsValue, String> {
    let public_key = options.get("publicKey").ok_or("missing publicKey")?;
    let js = to_js(public_key)?;
    let challenge = public_key["challenge"]
        .as_str()
        .ok_or("missing challenge")?;
    set_buffer(&js, "challenge", challenge)?;

    if let Some(user) = public_key.get("user") {
        let user_js =
            js_sys::Reflect::get(&js, &JsValue::from_str("user")).map_err(|e| format!("{e:?}"))?;
        let id = user["id"].as_str().ok_or("missing user id")?;
        set_buffer(&user_js, "id", id)?;
    }

    if let Some(list) = public_key.get(descriptor_field).and_then(Value::as_array) {
        let list_js = js_sys::Reflect::get(&js, &JsValue::from_str(descriptor_field))
            .map_err(|e| format!("{e:?}"))?;
        for (index, descriptor) in list.iter().enumerate() {
            let Some(id) = descriptor["id"].as_str() else {
                continue;
            };
            let item = array_item(&list_js, index)?;
            set_buffer(&item, "id", id)?;
        }
    }
    Ok(js)
}

async fn ceremony(method: &str, public_key: JsValue) -> Result<JsValue, String> {
    let window = web_sys::window().ok_or("no window")?;
    let navigator = window.navigator();
    let credentials = js_sys::Reflect::get(&navigator, &JsValue::from_str("credentials"))
        .map_err(|error| format!("{error:?}"))?;
    if credentials.is_undefined() || credentials.is_null() {
        return Err("this browser does not support WebAuthn".to_string());
    }
    let function = js_sys::Reflect::get(&credentials, &JsValue::from_str(method))
        .map_err(|error| format!("{error:?}"))?;
    let function: js_sys::Function = function
        .dyn_into()
        .map_err(|_| "credentials method missing".to_string())?;
    let argument = js_sys::Object::new();
    js_sys::Reflect::set(&argument, &JsValue::from_str("publicKey"), &public_key)
        .map_err(|error| format!("{error:?}"))?;
    let promise = function
        .call1(&credentials, &argument)
        .map_err(|error| format!("{error:?}"))?;
    JsFuture::from(js_sys::Promise::from(promise))
        .await
        .map_err(|error| {
            error
                .dyn_ref::<js_sys::Error>()
                .and_then(|error| error.message().as_string())
                .unwrap_or_else(|| "the passkey ceremony was cancelled".to_string())
        })
}

fn buffer_of(object: &JsValue, field: &str) -> Result<Vec<u8>, String> {
    let value = js_sys::Reflect::get(object, &JsValue::from_str(field))
        .map_err(|error| format!("{error:?}"))?;
    let buffer: js_sys::ArrayBuffer = value
        .dyn_into()
        .map_err(|_| format!("{field} is not an ArrayBuffer"))?;
    Ok(js_sys::Uint8Array::new(&buffer).to_vec())
}

fn serialize_attestation(credential: &JsValue) -> Result<Value, String> {
    let raw_id = buffer_of(credential, "rawId")?;
    let response = js_sys::Reflect::get(credential, &JsValue::from_str("response"))
        .map_err(|error| format!("{error:?}"))?;
    Ok(json!({
        "id": encode(&raw_id),
        "rawId": encode(&raw_id),
        "type": "public-key",
        "response": {
            "attestationObject": encode(&buffer_of(&response, "attestationObject")?),
            "clientDataJSON": encode(&buffer_of(&response, "clientDataJSON")?),
        },
        "clientExtensionResults": {},
    }))
}

fn serialize_assertion(credential: &JsValue) -> Result<Value, String> {
    let raw_id = buffer_of(credential, "rawId")?;
    let response = js_sys::Reflect::get(credential, &JsValue::from_str("response"))
        .map_err(|error| format!("{error:?}"))?;
    let mut value = json!({
        "id": encode(&raw_id),
        "rawId": encode(&raw_id),
        "type": "public-key",
        "response": {
            "authenticatorData": encode(&buffer_of(&response, "authenticatorData")?),
            "clientDataJSON": encode(&buffer_of(&response, "clientDataJSON")?),
            "signature": encode(&buffer_of(&response, "signature")?),
        },
        "clientExtensionResults": {},
    });
    let handle = js_sys::Reflect::get(&response, &JsValue::from_str("userHandle"))
        .map_err(|error| format!("{error:?}"))?;
    if !handle.is_null() && !handle.is_undefined() {
        value["response"]["userHandle"] = json!(encode(&buffer_of(&response, "userHandle")?));
    }
    Ok(value)
}

/// Registers a new passkey for the signed-in user.
pub async fn register(name: &str) -> Result<(), String> {
    let begin = api::send_json("POST", "/api/passkeys/register/begin", &json!({})).await?;
    if begin.status != 200 {
        return Err(begin
            .error()
            .unwrap_or("could not start passkey registration")
            .to_string());
    }
    let challenge_id = begin.body["challenge_id"]
        .as_str()
        .ok_or("missing challenge id")?
        .to_string();
    let options = prepare_options(&begin.body["options"], "excludeCredentials")?;
    let credential = ceremony("create", options).await?;
    let serialized = serialize_attestation(&credential)?;
    let finish = api::send_json(
        "POST",
        "/api/passkeys/register/finish",
        &json!({ "challenge_id": challenge_id, "name": name, "credential": serialized }),
    )
    .await?;
    if finish.status != 201 {
        return Err(finish
            .error()
            .unwrap_or("passkey registration failed")
            .to_string());
    }
    Ok(())
}

/// Signs in with a passkey (the username must be filled in).
pub async fn login(username: &str) -> Result<(), String> {
    let begin = api::send_json(
        "POST",
        "/api/passkeys/login/begin",
        &json!({ "username": username }),
    )
    .await?;
    if begin.status != 200 {
        return Err(begin
            .error()
            .unwrap_or("no passkey is registered for this account")
            .to_string());
    }
    let challenge_id = begin.body["challenge_id"]
        .as_str()
        .ok_or("missing challenge id")?
        .to_string();
    let options = prepare_options(&begin.body["options"], "allowCredentials")?;
    let credential = ceremony("get", options).await?;
    let serialized = serialize_assertion(&credential)?;
    let finish = api::send_json(
        "POST",
        "/api/passkeys/login/finish",
        &json!({ "challenge_id": challenge_id, "username": username, "credential": serialized }),
    )
    .await?;
    if finish.status != 200 {
        return Err(finish
            .error()
            .unwrap_or("passkey sign-in failed")
            .to_string());
    }
    Ok(())
}
