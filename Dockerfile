# syntax=docker/dockerfile:1
# ── Stage 1: Build Binary in Rust 2024 ──────────────────────────────────────
FROM rust:latest AS builder

WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Build optimized release binary with stripped debug symbols
RUN cargo build --release && strip target/release/stenio

# ── Stage 2: Minimal Production Runtime ─────────────────────────────────────
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy stripped native binary
COPY --from=builder /app/target/release/stenio /usr/local/bin/stenio

# Expose default MCP SSE Server port
EXPOSE 9099

# Native Healthcheck against Stenio's /health route
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://127.0.0.1:9099/health || exit 1

ENTRYPOINT ["stenio"]
CMD ["--mcp-sse", "--mcp-host", "0.0.0.0", "--mcp-port", "9099"]
