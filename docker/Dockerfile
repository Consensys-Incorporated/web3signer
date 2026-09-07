# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89

# Stage 1: Validate and extract application
FROM alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS app-extract
ARG TAR_FILE
RUN test -n "$TAR_FILE" || (echo "ERROR: TAR_FILE build argument is required" && exit 1)
COPY ${TAR_FILE} /tmp/web3signer.tar.gz
RUN gzip -t /tmp/web3signer.tar.gz || (echo "ERROR: TAR_FILE is not a valid gzip archive" && exit 1) && \
    mkdir -p /opt/web3signer && \
    tar -xzf /tmp/web3signer.tar.gz -C /opt/web3signer --strip-components=1 && \
    rm /tmp/web3signer.tar.gz

# Stage 2: Final image with Ubuntu base for latest security patches
FROM ubuntu:26.04@sha256:3131b4cc82a783df6c9df078f86e01819a13594b865c2cad47bd1bca2b7063bb

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
COPY --from=eclipse-temurin:25.0.3_9-jre@sha256:681c543d6f36c50f45e9b5226930a46203dcfa351d3670e9d0bdf0dabae53539 /opt/java/openjdk /opt/java/openjdk
COPY --from=app-extract --chown=web3signer:web3signer /opt/web3signer /opt/web3signer

USER web3signer
WORKDIR /opt/web3signer

EXPOSE 9000 9001

ENTRYPOINT ["/opt/web3signer/bin/web3signer"]
