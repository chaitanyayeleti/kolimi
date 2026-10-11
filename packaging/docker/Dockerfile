# Kolimi container image: build from the repo root.
#   docker build -f packaging/docker/Dockerfile -t kolimi .
#   docker run -d -p 8080:8080 -v kolimi-data:/data kolimi
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p kolimi-server -p kolimi-sync

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
