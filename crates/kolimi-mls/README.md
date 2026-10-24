# `kolimi-mls` — OpenMLS spike (RFC 9420)

This crate is the MLS groundwork. It is not yet wired into the sync/desktop/web clients. It validates the protocol pieces for
Kolimi's group-E2EE milestone using `openmls` 0.9:

- a device credential + key package,
- group creation and an asynchronous `add` via Welcome,
- encrypted application messages,
- the epoch exporter (`kolimi-share-keyring-v1`) that will key the shared
  folder's file-key keyring,
- epoch rotation when a member is added.

It is now a workspace member (option A). `cargo-vet` exemptions for the
openmls tree are temporary and tracked in `docs/audit/mls-delta.md`.

Run:

```sh
cd crates/kolimi-mls
cargo test
cargo check --target wasm32-unknown-unknown   # web feasibility
```

Design: [`docs/rfc/0012-mls-groups.md`](../../docs/rfc/0012-mls-groups.md).
