# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e

# Stage 1: Validate and extract application
FROM alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS app-extract
ARG TAR_FILE
RUN test -n "$TAR_FILE" || (echo "ERROR: TAR_FILE build argument is required" && exit 1)
COPY ${TAR_FILE} /tmp/web3signer.tar.gz
RUN gzip -t /tmp/web3signer.tar.gz || (echo "ERROR: TAR_FILE is not a valid gzip archive" && exit 1) && \
    mkdir -p /opt/web3signer && \
    tar -xzf /tmp/web3signer.tar.gz -C /opt/web3signer --strip-components=1 && \
    rm /tmp/web3signer.tar.gz

# Stage 2: Fetch the Eclipse Temurin JRE release tarball and verify it against
# the SHA-256 published by Adoptium for that release. The official
# eclipse-temurin Docker image lags the binary release, so the JRE is pulled
# straight from the Adoptium GitHub release instead of an eclipse-temurin tag.
FROM alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS jre-fetch
ARG TARGETARCH
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) JRE_ARCH=x64;     JRE_SHA256=6fac98f0c8202efc3135a9e9e42aa61963ec42d1c5cbb40caf231e7b14a24ef6 ;; \
      arm64) JRE_ARCH=aarch64; JRE_SHA256=963931723891302ebb2687178532c3d793d71e2577cd058061c7efb396140a86 ;; \
      *) echo "Unsupported TARGETARCH=$TARGETARCH" >&2; exit 1 ;; \
    esac; \
    wget -q -O /tmp/jre.tar.gz \
      "https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.5%2B8/OpenJDK25U-jre_${JRE_ARCH}_linux_hotspot_25.0.5_8.tar.gz"; \
    echo "${JRE_SHA256}  /tmp/jre.tar.gz" | sha256sum -c -; \
    mkdir -p /opt/java/openjdk; \
    tar -xzof /tmp/jre.tar.gz -C /opt/java/openjdk --strip-components=1; \
    rm /tmp/jre.tar.gz

# Stage 3: Final image with Ubuntu base for latest security patches
FROM ubuntu:26.04@sha256:c098726dd9b9733f3e885f8de0ef375206a311b0a317eadc40d347b1115fb944

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

# Copy full Eclipse Temurin JRE 25.0.5+8 (no module complexity, all features available)
COPY --from=jre-fetch /opt/java/openjdk /opt/java/openjdk
COPY --from=app-extract --chown=web3signer:web3signer /opt/web3signer /opt/web3signer

USER web3signer
WORKDIR /opt/web3signer

EXPOSE 9000 9001

ENTRYPOINT ["/opt/web3signer/bin/web3signer"]
