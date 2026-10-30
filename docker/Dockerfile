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
FROM --platform=$BUILDPLATFORM eclipse-temurin:25-jdk@sha256:83f4a7fc27df94dcc7b8de04d14cbbba8da14406f921e966969c3b09000aa507 AS dist-gradle
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
FROM alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS dist-tar
ARG TAR_FILE
COPY ${TAR_FILE} /dist/web3signer.tar.gz

FROM dist-${DIST_SOURCE} AS dist

# Validate and extract the distribution
FROM alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS app-extract
COPY --from=dist /dist/web3signer.tar.gz /tmp/web3signer.tar.gz
RUN gzip -t /tmp/web3signer.tar.gz || (echo "ERROR: web3signer distribution is not a valid gzip archive" && exit 1) && \
    mkdir -p /opt/web3signer && \
    tar -xzf /tmp/web3signer.tar.gz -C /opt/web3signer --strip-components=1 && \
    rm /tmp/web3signer.tar.gz

# Final image with Ubuntu base for latest security patches
FROM ubuntu:26.04@sha256:6a06111c3b0a8600feadb270aec771dc239bf407b25625f93f44ab00e11f4d3c

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
COPY --from=eclipse-temurin:25-jre@sha256:ecdc0adb37bde1a281c4d245a3cd535004b1fc8322d560f5b09463b248c81df0 /opt/java/openjdk /opt/java/openjdk
COPY --from=app-extract --chown=web3signer:web3signer /opt/web3signer /opt/web3signer

USER web3signer
WORKDIR /opt/web3signer

EXPOSE 9000 9001

ENTRYPOINT ["/opt/web3signer/bin/web3signer"]
