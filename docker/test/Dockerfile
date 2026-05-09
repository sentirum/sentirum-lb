FROM rust:1.94-bookworm AS builder
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        perl \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

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
