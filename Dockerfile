FROM rust:1.86-bookworm AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --locked

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10001 sentirum

WORKDIR /app
COPY --from=builder /app/target/release/sentirum-lb /usr/local/bin/sentirum-lb

USER sentirum
EXPOSE 9999 9998
ENTRYPOINT ["/usr/local/bin/sentirum-lb"]
