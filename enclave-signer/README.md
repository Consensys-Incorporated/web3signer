# Enclave signer

`enclave-signer` is the program that runs inside the enclave. It holds the BLS secret keys and
signs for Web3Signer over the protocol described in
[`enclave-protocol/README.md`](../enclave-protocol/README.md). How to deploy it:
[`deployments/aws-nitro/README.md`](../deployments/aws-nitro/README.md).

## What runs in the enclave

The enclave image (`docker/Dockerfile.enclave`, assembled by
`./gradlew :enclave-signer:enclaveImage`) holds:

- a `jlink` runtime with `java.base` only;
- this module's jar and the `enclave-protocol` jar, nothing else. `verifyEnclaveClasspath` fails the
  build when `runtimeClasspath` holds any other dependency;
- `native/libblst.so`, taken from the `tech.pegasys:jblst` jar for the target architecture
  (`-PenclaveArch=amd64|arm64`).

The signer loads `libblst.so` from `--blst-library=<path>`. The library needs `libstdc++.so.6`,
`libgcc_s.so.1` and `libc.so.6`, which is why the image is based on `distroless/cc`.

## BLS through FFM, not jblst

`Blst` binds the blst C functions it needs (`blst_sign_pk_in_g1`, `blst_hash_to_g2` and five
others) with the Foreign Function and Memory API. It does not use jblst's Java classes.

The native code is the same in both cases. The `libblst.so` that jblst ships exports both its JNI
wrappers (`Java_supranational_*`) and the blst C API (`blst_*`). The enclave calls the C API of the
same binary that Web3Signer calls through JNI, and a signature costs the same through either path.

Using jblst's classes in the enclave would bring:

- **Another dependency on the trusted classpath.** jblst's POM declares a runtime dependency on
  Guava, which this repository resolves to its current Guava version. jblst's classes do not use
  it, but it would have to be excluded on every upgrade to keep `verifyEnclaveClasspath` passing.
- **jblst's library loader.** On first use, `supranational.blst.blstJNI` copies the native library
  for the current platform out of the jar into a new temporary directory and loads it from there.
  `docker/Dockerfile.distroless` works around this for Web3Signer: it extracts `libblst.so` at
  image build time, removes it from the jar, sets `java.library.path` and
  `-Dsupranational.blst.jniResource=/__stripped__`. With FFM the enclave never loads `blstJNI`, so
  it needs none of that.
- **Natives for every platform.** The jblst jar carries libraries for five platforms. The enclave
  image takes the one `libblst.so` it runs.

The cost is a binding to maintain: the signatures in `Blst` must match the blst version that jblst
ships. `BlstTest` checks the binding against Teku's `BLS.sign` for random keys and signing roots,
so a jblst upgrade that changes the C API fails that test.
