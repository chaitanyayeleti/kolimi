# Kolimi container image: build from the repo root.
#   docker build -f packaging/docker/Dockerfile -t kolimi .
#   docker run -d -p 8080:8080 -v kolimi-data:/data kolimi
#
# The web UI is compiled to WebAssembly and embedded into the server
# binary (rust-embed), so the image serves /app/ with no extra files.
# The wasm-bindgen CLI version is read from Cargo.lock.
FROM rust:1-bookworm AS build
WORKDIR /src
RUN rustup target add wasm32-unknown-unknown
# Install the matching wasm-bindgen CLI first so source edits do not
# invalidate this (slow) layer.
COPY Cargo.lock ./
RUN set -eux; \
    WB="$(sed -n '/name = "wasm-bindgen"/{n;s/^version = "\(.*\)"/\1/p;}' Cargo.lock | head -1)"; \
    test -n "$WB"; \
    cargo install wasm-bindgen-cli --version "$WB" --locked
COPY . .
# Stage the UI before compiling the server: rust-embed embeds the assets
# at compile time, so building the server without this step yields a
# blank /app/.
RUN bash scripts/build-ui.sh \
 && cargo build --release --locked -p kolimi-server -p kolimi-sync

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/kolimi-server /usr/local/bin/kolimi-server
COPY --from=build /src/target/release/kolimi-sync /usr/local/bin/kolimi-sync
# Create the data directory owned by the nonroot user so named volumes
# inherit the right ownership.
COPY --from=build --chown=nonroot:nonroot /src/README.md /data/.keep

ENV KOLIMI_DATA=/data \
    KOLIMI_BIND=0.0.0.0:8080 \
    KOLIMI_ORIGIN=http://localhost:8080 \
    RUST_LOG=info
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/kolimi-server", "serve"]
