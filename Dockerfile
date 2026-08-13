###################################################
# Test harness for remote signer from Tendermint

# Pinned by digest for reproducibility. Note this image only publishes `latest`
# and `v0.31.7`, so the harness is a Tendermint 0.31 signer.
FROM tendermint/tm-signer-harness:v0.31.7@sha256:a12ba671edd41fc124e31ce70a435a38a9ffae1a1ce927d914a2e156c449f382 AS harness

USER root

RUN mkdir -p /harness

# We need this script to generate configuration for the KMS
COPY tests/support/gen-validator-integration-cfg.sh /harness/

# Generate the base configuration data for the Tendermint validator for use
# during integration testing. This will generate the data, by default, in the
# /tendermint directory.
RUN tendermint init --home=/harness && \
    tm-signer-harness extract_key --tmhome=/harness --output=/harness/signing.key && \
    cd /harness && \
    chmod +x gen-validator-integration-cfg.sh && \
    TMHOME=/harness sh ./gen-validator-integration-cfg.sh

###################################################
# Tendermint KMS development image
#
# Provides the toolchain and test harness for building and testing tmkms; the
# source tree is expected to be mounted in. Pinned by digest so rebuilds are
# reproducible.

FROM rust:1.90-bookworm@sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f AS build

# Build dependencies: libudev/libusb for YubiHSM and Ledger support, clang for
# bindgen, cmake for native builds
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    cmake \
    libudev-dev \
    libusb-1.0-0-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add rustfmt clippy

# Unprivileged user to build and run as
RUN useradd --create-home --shell /bin/bash developer

# We need the generated harness and Tendermint configuration
COPY --from=harness /harness /harness

# We need the test harness binary
COPY --from=harness /usr/bin/tm-signer-harness /usr/bin/tm-signer-harness

# We need a secret connection key
COPY tests/support/secret_connection.key /harness/

RUN chown -R developer /harness

# Configure Rust environment variables.
#
# `-Ctarget-feature=+aes,+ssse3` is recommended for x86_64 builds (see README) but
# is not valid on other architectures, so it is left for the caller to set.
ENV RUST_BACKTRACE=full

USER developer
WORKDIR /home/developer
