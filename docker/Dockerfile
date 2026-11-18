# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e

# Distribution source selection.
# - TAR_FILE set (preferred, used by CI): copy the pre-built distribution from the build context.
# - TAR_FILE unset/empty: build the distribution inside Docker with ./gradlew distTar (no local Java needed).
# DIST_FROM_TAR/DIST_SOURCE are derived internally; do not set them.
ARG TAR_FILE
ARG DIST_FROM_TAR=${TAR_FILE:+tar}
ARG DIST_SOURCE=${DIST_FROM_TAR:-gradle}

# Build the distribution from source. Runs on the build host's platform: the
# distribution is architecture-independent (jblst ships natives for all arches).
# The source tree is bind-mounted (not copied) so it never lands in a layer; .git
# must be in the build context for correct version information, and the version
# calculation runs the git CLI, which the JDK image does not ship.
FROM --platform=$BUILDPLATFORM eclipse-temurin:25-jdk@sha256:884a2f8692cc1e2c7e21f95914adf0ae0eafee9a7eb663a12169cc44468256ec AS dist-gradle
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN --mount=type=bind,target=/src,rw \
    --mount=type=cache,id=web3signer-gradle,target=/root/.gradle,sharing=locked \
    ./gradlew --no-daemon distTar && \
    mkdir -p /dist && \
    cp build/distributions/web3signer-*.tar.gz /dist/web3signer.tar.gz

# Use a pre-built distribution from the build context.
FROM alpine@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS dist-tar
ARG TAR_FILE
COPY ${TAR_FILE} /dist/web3signer.tar.gz

FROM dist-${DIST_SOURCE} AS dist

# Validate and extract the distribution
FROM alpine@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS app-extract
COPY --from=dist /dist/web3signer.tar.gz /tmp/web3signer.tar.gz
RUN gzip -t /tmp/web3signer.tar.gz || (echo "ERROR: web3signer distribution is not a valid gzip archive" && exit 1) && \
    mkdir -p /opt/web3signer && \
    tar -xzf /tmp/web3signer.tar.gz -C /opt/web3signer --strip-components=1 && \
    rm /tmp/web3signer.tar.gz

# Final image with Ubuntu base for latest security patches
FROM ubuntu:26.04@sha256:d66b366dac61b575bee2aef07e9c26e8070096fbe84a3d4d3eb0da069b5d76db

ARG BUILD_DATE
ARG VCS_REF
ARG VERSION

LABEL org.opencontainers.image.created=$BUILD_DATE \
      org.opencontainers.image.title="Web3Signer" \
      org.opencontainers.image.description="Ethereum 2.0 Signing Service" \
      org.opencontainers.image.url="https://docs.web3signer.consensys.net" \
      org.opencontainers.image.documentation="https://docs.web3signer.consensys.net" \
      org.opencontainers.image.source="https://github.com/Consensys-Incorporated/web3signer" \
      org.opencontainers.image.revision=$VCS_REF \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.vendor="Consensys" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="ubuntu:26.04"

ENV JAVA_HOME="/opt/java/openjdk" \
    PATH="/opt/java/openjdk/bin:${PATH}" \
    WEB3SIGNER_HTTP_LISTEN_HOST="0.0.0.0" \
    WEB3SIGNER_METRICS_HOST="0.0.0.0"

# Apply all security updates, install dependencies and create user.
# Also drop Pebble, the service manager the rock-built Ubuntu base ships outside dpkg. Web3Signer never runs
# it, and its bundled Go stdlib carries CVE-2026-78667, CVE-2026-78669, CVE-2026-97031 and CVE-2026-111943.
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /usr/bin/pebble /var/lib/pebble && \
    useradd --system --no-create-home --shell /bin/false web3signer

# Copy full JRE from Eclipse Temurin (no module complexity, all features available)
COPY --from=eclipse-temurin:25-jre@sha256:945247f9d092703e0c6be92243ef3c51640229e23ab34d353c8dcdc73e6cd4e6 /opt/java/openjdk /opt/java/openjdk
COPY --from=app-extract --chown=web3signer:web3signer /opt/web3signer /opt/web3signer

USER web3signer
WORKDIR /opt/web3signer

EXPOSE 9000 9001

ENTRYPOINT ["/opt/web3signer/bin/web3signer"]
