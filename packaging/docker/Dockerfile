# syntax=docker/dockerfile:1

# Kolimi container image: build from the repo root.
#   docker build -f packaging/docker/Dockerfile -t kolimi .
#   docker run -d -p 8080:8080 -v kolimi-data:/data kolimi
#
# The web UI is compiled to WebAssembly and embedded into the server
# binary (rust-embed), so the image serves /app/ with no extra files.
#
# Dependency caching: BuildKit cache mounts keep the cargo registry and
# the target directory between builds, so changing source (or docs) only
# recompiles the affected crates instead of the whole graph. The first
# build is slow; later builds are seconds to a couple of minutes.
FROM rust:1-bookworm AS build
WORKDIR /src
RUN rustup target add wasm32-unknown-unknown

# The wasm-bindgen CLI, pinned to the version in Cargo.lock, cached
# separately from the project build.
COPY Cargo.lock ./
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/wasm-bindgen-target,sharing=locked \
    set -eux; \
    WB="$(sed -n '/name = "wasm-bindgen"/{n;s/^version = "\(.*\)"/\1/p;}' Cargo.lock | head -1)"; \
    test -n "$WB"; \
    CARGO_TARGET_DIR=/wasm-bindgen-target \
    cargo install wasm-bindgen-cli --version "$WB" --locked

# Stage the UI before compiling the server: rust-embed embeds the assets
# at compile time, so building the server without this step yields a
# blank /app/. Binaries are copied to /out because the target directory
# is a cache mount and does not become part of the image layer.
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    bash scripts/build-ui.sh \
 && cargo build --release --locked -p kolimi-server -p kolimi-sync \
 && mkdir -p /out \
 && cp target/release/kolimi-server target/release/kolimi-sync /out/

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /out/kolimi-server /usr/local/bin/kolimi-server
COPY --from=build /out/kolimi-sync /usr/local/bin/kolimi-sync
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
