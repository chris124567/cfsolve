# ========================================================
# Stage 1: Build stage
# ========================================================
FROM rust:bookworm AS builder

# Install build dependencies for BoringSSL and bindgen
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    clang \
    libclang-dev \
    nasm \
    pkg-config \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency specifications and vendored libraries
COPY Cargo.toml Cargo.lock ./
COPY vendor ./vendor

# Heroku's dyno hosts are AMD EPYC (Zen 1+), all of which implement the x86-64-v3
# feature set (AVX2, BMI2, FMA). Targeting it lets SHA-2 and the SWC/VM hot loops
# use them. This must be set before the stub build so both cargo layers build with
# the same flags and the dependency layer-cache stays valid. If a deployment
# target predates EPYC or runs on old Intel, remove this line and rebuild rather
# than shipping illegal instructions.
ENV RUSTFLAGS="-C target-cpu=x86-64-v3"

# Build every dependency against stub sources first. This layer only depends on the manifest,
# lockfile, and vendored crates, so editing src/ reuses it instead of recompiling SWC and BoringSSL.
RUN mkdir -p src/bin/server \
 && echo 'fn main() {}' > src/main.rs \
 && : > src/lib.rs \
 && echo 'fn main() {}' > src/bin/server/main.rs \
 && cargo build --release --bin server \
 && rm -rf src

# Copy source code and profiles
COPY src ./src
COPY profiles ./profiles

# COPY preserves source mtimes, and locally those are older than the stub files
# the previous layer just created. Cargo assumes mtimes never go backward, so it
# would consider every real source unchanged and ship the stub binary. Refresh
# them so the real build always recompiles.
RUN find src profiles -type f -exec touch {} +

# Build the API server. Dependency artifacts from the stub layer are reused.
RUN cargo build --release --bin server

# ========================================================
# Stage 2: Minimal runtime image
# ========================================================
FROM debian:bookworm-slim AS runner

# Install TLS certificates for outgoing challenge requests
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tzdata \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the compiled server from builder
COPY --from=builder /app/target/release/server /usr/local/bin/server

# Copy browser profiles and data files
COPY profiles ./profiles

# Copy entrypoint runner
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
# Windows checkouts store CRLF endings; strip uppercase so /bin/sh can exec it.
RUN sed -i 's/\r$//' /usr/local/bin/docker-entrypoint.sh \
 && chmod +x /usr/local/bin/docker-entrypoint.sh

# Server port
EXPOSE 8742

# Default configuration environment variables
ENV LISTEN="0.0.0.0:8742"
ENV FINGERPRINT="profiles/safari-26-ios.json"
# `auto` uses the container's available CPUs. Set CONCURRENCY explicitly only
# when the platform under-reports them (for example Heroku).
ENV CONCURRENCY="auto"
ENV CFSOLVE_QUEUE_TIMEOUT_SECS="15"

ENTRYPOINT ["docker-entrypoint.sh"]
