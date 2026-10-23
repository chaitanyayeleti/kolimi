# `kolimi-mls` — OpenMLS spike (RFC 9420)

This is a **spike**, not shipped code. It validates the protocol pieces for
Kolimi's group-E2EE milestone using `openmls` 0.9:

- a device credential + key package,
- group creation and an asynchronous `add` via Welcome,
- encrypted application messages,
- the epoch exporter (`kolimi-share-keyring-v1`) that will key the shared
  folder's file-key keyring,
- epoch rotation when a member is added.

It lives outside the main Cargo workspace on purpose: the audited release
does not pull `openmls` (MIT, large dependency tree) until the security
review and `cargo-vet` delta are ready.

Run:

```sh
cd spikes/mls
cargo test
cargo check --target wasm32-unknown-unknown   # web feasibility
```

Design: [`docs/rfc/0012-mls-groups.md`](../../docs/rfc/0012-mls-groups.md).
