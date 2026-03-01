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
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root service user
RUN groupadd --gid 10001 steward \
    && useradd --uid 10001 --gid steward --shell /usr/sbin/nologin --no-create-home steward

COPY --from=builder /app/target/release/steward /usr/local/bin/steward
COPY --chown=steward:steward config/ /etc/steward/config/

RUN mkdir -p /tmp/workspace && chown steward:steward /tmp/workspace

USER steward

EXPOSE 8080

CMD ["steward"]
