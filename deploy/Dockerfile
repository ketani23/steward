# Steward Agent — Multi-stage Docker build
# See docs/architecture.md Ring 0 (Infrastructure Isolation) for hardening requirements.

# Stage 1: Build
FROM rust:1.93-bookworm AS builder

WORKDIR /app
COPY . .

RUN cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/steward /usr/local/bin/steward
COPY config/ /etc/steward/config/

# TODO: Read-only root filesystem with ephemeral tmpfs at /tmp/workspace
# TODO: Non-root user
# TODO: Network egress allowlisting

EXPOSE 8080

CMD ["steward"]
