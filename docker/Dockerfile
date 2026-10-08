# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

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
# must be in the build context for correct version information.
FROM --platform=$BUILDPLATFORM eclipse-temurin:25.0.4_7-jdk@sha256:97014c4b396021f9ddb7d592a7dbedb0c4e4215c29e03dc01c393558aefb71c2 AS dist-gradle
WORKDIR /src
RUN --mount=type=bind,target=/src,rw \
    --mount=type=cache,id=web3signer-gradle,target=/root/.gradle,sharing=locked \
    ./gradlew --no-daemon distTar && \
    mkdir -p /dist && \
    cp build/distributions/web3signer-*.tar.gz /dist/web3signer.tar.gz

# Use a pre-built distribution from the build context.
FROM alpine@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS dist-tar
ARG TAR_FILE
COPY ${TAR_FILE} /dist/web3signer.tar.gz

FROM dist-${DIST_SOURCE} AS dist

# Validate and extract the distribution
FROM alpine@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS app-extract
COPY --from=dist /dist/web3signer.tar.gz /tmp/web3signer.tar.gz
RUN gzip -t /tmp/web3signer.tar.gz || (echo "ERROR: web3signer distribution is not a valid gzip archive" && exit 1) && \
    mkdir -p /opt/web3signer && \
    tar -xzf /tmp/web3signer.tar.gz -C /opt/web3signer --strip-components=1 && \
    rm /tmp/web3signer.tar.gz

# Final image with Ubuntu base for latest security patches
FROM ubuntu:26.04@sha256:da6fc2be547864451aa253836dd926da33623312df4a9a243e35dc877c378a78

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

# Apply all security updates, install dependencies and create user
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --system --no-create-home --shell /bin/false web3signer

# Copy full JRE from Eclipse Temurin (no module complexity, all features available)
COPY --from=eclipse-temurin:25.0.4_7-jre@sha256:bb036ed6cfdc57e3da7c22634d15f1b840d2caf76183861c80e81ca4b5104abb /opt/java/openjdk /opt/java/openjdk
COPY --from=app-extract --chown=web3signer:web3signer /opt/web3signer /opt/web3signer

USER web3signer
WORKDIR /opt/web3signer

EXPOSE 9000 9001

ENTRYPOINT ["/opt/web3signer/bin/web3signer"]
