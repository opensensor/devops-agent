FROM lukemathwalker/cargo-chef:latest-rust-linux AS chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-file recipe.json

FROM chef AS builder
WORKDIR /app
COPY --from=planner /app/recipe.json recipe.json

# Build dependencies
RUN cargo chef cook --release --recipe-file recipe.json

# Build application
COPY . .
RUN cargo build --release --bin devops-agent

# Runtime stage
FROM debian:bookworm-slim AS runtime
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/devops-agent /app/devops-agent
COPY --from=builder /app/config /app/config

EXPOSE 8080

ENTRYPOINT ["/app/devops-agent"]
