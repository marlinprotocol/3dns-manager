FROM rust:1.86-slim AS builder

WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev
COPY . .

RUN cargo build --release

FROM debian:bookworm-slim

WORKDIR /app
COPY --from=builder /app/target/release/dns-manager /app/

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

CMD ["/app/dns-manager"]
