## Web3Signer Docker images

Web3Signer is published as two Docker image variants. Both ship Eclipse Temurin JRE 25 and the same Web3Signer application; they differ in the base image and how Web3Signer is launched.

| Variant | Tag suffix | Base image | Shell / package manager | Read-only filesystem |
| ------- | ---------- | ---------- | ----------------------- | -------------------- |
| Default (`docker/Dockerfile`) | *(none)* e.g. `consensys/web3signer:latest` | `ubuntu:24.04` + `eclipse-temurin:25-jre` | Yes | Requires a writable `/tmp` |
| Distroless (`docker/Dockerfile.distroless`) | `-distroless` e.g. `consensys/web3signer:latest-distroless` | `gcr.io/distroless/java25-debian13:nonroot` | No | Works with `--read-only` out of the box |

Pick the distroless variant when you want a smaller attack surface (no shell, no package manager), non-root execution by default, and the ability to run under a read-only root filesystem.

## Building locally

From the root of the project:

```sh
./gradlew distTar

# Default image
docker build --no-cache --pull \
  --build-arg TAR_FILE=./build/distributions/web3signer-develop.tar.gz \
  -f ./docker/Dockerfile -t web3signer:develop .

# Distroless image
docker build --no-cache --pull \
  --build-arg TAR_FILE=./build/distributions/web3signer-develop.tar.gz \
  -f ./docker/Dockerfile.distroless -t web3signer:develop-distroless .

docker run --rm -it web3signer:develop --version
docker run --rm -it web3signer:develop-distroless --version
```

## Running the distroless image

Default run — works exactly like the standard image:

```sh
docker run -p 9000:9000 consensys/web3signer:latest-distroless eth2 ...
```

Hardened run with a read-only root filesystem:

```sh
docker run --read-only -p 9000:9000 \
  consensys/web3signer:latest-distroless \
  eth2 --slashing-protection-enabled=false
```

`--read-only` works without any `--tmpfs /tmp` mount because:

- `-XX:-UsePerfData` disables the JVM's `hsperfdata_*` writes to `/tmp`.
- `libblst.so` is pre-extracted to `/opt/web3signer/native-libs/` at image build time and pointed to by `-Djava.library.path`, so jblst never unpacks it at startup.
- The other shaded native libraries in the classpath (Netty native transports, netty-tcnative, jffi, conscrypt) are not exercised by Web3Signer's runtime because Vert.x uses its NIO transport by default.

If you add your own tooling or dependencies that do touch `/tmp`, add `--tmpfs /tmp:rw,size=64m` (or, in Kubernetes, an `emptyDir` volume with `medium: Memory` mounted at `/tmp`) alongside `--read-only`.

### Using the Key Manager API under `--read-only`

Importing a keystore via the Key Manager API normally writes a `.json` file into the configured key-config-path, which fails on a read-only rootfs. Pass the experimental hidden flag `--Xkey-manager-skip-keystore-storage=true` on the `eth2` subcommand to keep imported keys in memory only:

```sh
docker run --read-only -p 9000:9000 \
  consensys/web3signer:latest-distroless \
  eth2 --key-manager-api-enabled=true --Xkey-manager-skip-keystore-storage=true ...
```

Tradeoff: keys imported at runtime are lost on restart, so operators must have their own re-import or backup strategy.

### Passing JVM options to the distroless image

The default image reads the `JAVA_OPTS` environment variable in its shell launcher. The distroless image has no shell and invokes `java` directly, so `JAVA_OPTS` is ignored. To pass JVM options (heap size, GC flags, system properties, JMX, etc.), use one of the environment variables the JVM launcher itself honors:

- **`JDK_JAVA_OPTIONS`** (JDK 9+, preferred) — only read by the `java` launcher; prints `NOTE: Picked up JDK_JAVA_OPTIONS: ...` once at start.
- **`JAVA_TOOL_OPTIONS`** — read by every JVM-based tool; prints `Picked up JAVA_TOOL_OPTIONS: ...` on every JVM start (including short-lived tools). Useful if the same env needs to work for both the default and distroless variants.

Example:

```sh
docker run -p 9000:9000 \
  -e JDK_JAVA_OPTIONS='-Xmx3g -Xms2g -XX:+UseG1GC' \
  consensys/web3signer:latest-distroless eth2 ...
```

Both `-D...` system properties and JMX flags work the same way:

```sh
-e JDK_JAVA_OPTIONS='-Xmx3g -Dlog4j.configurationFile=/var/config/log4j2.xml -Dcom.sun.management.jmxremote.port=9010 ...'
```

Note: quoting rules differ from shell — values containing spaces need backslash-escaping (e.g. `-Dfoo=bar\ baz`). For the usual web3signer flags this rarely matters.

### Writable mounts for application data

As with the default image, a writable mount is still required for any on-disk data path (file-based slashing-protection DB, file logs). Mount those paths as volumes; only the container's root filesystem is read-only.

## Verifying image signatures and attestations

Published images (both variants, both `linux/amd64` and `linux/arm64`) are:

- **Signed** with [cosign](https://docs.sigstore.dev/) using keyless signing (GitHub Actions OIDC + Sigstore transparency log — no private keys involved).
- Shipped with **SLSA provenance** and an **SPDX SBOM** attached as OCI referrers.

Verify a signature:

```sh
cosign verify consensys/web3signer:<tag> \
  --certificate-identity-regexp '^https://github\.com/Consensys-Incorporated/web3signer/\.github/workflows/ci_main\.yml@refs/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Inspect the attestations:

```sh
# SLSA provenance (includes source repo, commit, build invocation)
docker buildx imagetools inspect consensys/web3signer:<tag> --format '{{json .Provenance}}'

# SPDX SBOM (consumable by Docker Scout, Trivy, Grype, etc.)
docker buildx imagetools inspect consensys/web3signer:<tag> --format '{{json .SBOM}}'
```
