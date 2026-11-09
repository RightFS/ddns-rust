FROM rust:slim-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY web ./web
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN groupadd --gid 10001 ddns && useradd --uid 10001 --gid ddns --no-create-home ddns \
    && mkdir /data && chown ddns:ddns /data
COPY --from=builder /build/target/release/ddns-rust /usr/local/bin/ddns-rust
USER 10001:10001
WORKDIR /data
EXPOSE 9876
ENTRYPOINT ["ddns-rust", "--config", "/data/config.toml"]
ENV DDNS_RUST_DEFAULT_LISTEN=0.0.0.0:9876
CMD ["serve"]
