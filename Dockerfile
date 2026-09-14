# Multi-stage build for the Rust bootintel-cli.
#
# Stage 1: Build in a full Rust image with libudev for serialport.
# Stage 2: Copy the static-ish binary into a distroless image.
#
# Distroless has no shell, no package manager, no unnecessary
# libraries — smaller attack surface than alpine or debian:slim.
# The image is ~80 MB total; the binary itself is ~3 MB.
#
# Building: docker build -t bootintel-cli .
# Running:  docker run --rm -i bootintel-cli scan - < boot.log

# ─────────────────────────────────────────────────────────────────────
# MSRV is declared in Cargo.toml workspace.package.rust-version.
# Pin the builder to a specific point release so a passing CI build
# today keeps passing tomorrow; bump deliberately when Rust ships a
# new stable AND our declared MSRV is bumped to match.
FROM rust:1.90-bookworm AS builder

WORKDIR /build

# Install libudev-dev for the serialport crate's Linux backend.
# Keep it in the builder image only; distroless final has no udev.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libudev-dev \
    pkg-config \
 && rm -rf /var/lib/apt/lists/*

# Copy workspace + build with release + tui feature (matches what
# users get from the install.sh path).
COPY . .

RUN cargo build --release --features tui

# ─────────────────────────────────────────────────────────────────────
FROM gcr.io/distroless/cc-debian12:nonroot

LABEL org.opencontainers.image.title="bootintel-cli"
LABEL org.opencontainers.image.description="Interactive UART capture + streaming boot-log analysis"
LABEL org.opencontainers.image.source="https://github.com/bootintel/cli"
LABEL org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /build/target/release/bootintel /usr/local/bin/bootintel

ENTRYPOINT ["/usr/local/bin/bootintel"]
CMD ["--help"]
