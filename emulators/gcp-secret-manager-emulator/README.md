# GCP Secret Manager emulator for testing

The GCP Secret Manager acceptance tests can run against
[gcp-secret-manager-emulator](https://github.com/blackwell-systems/gcp-secret-manager-emulator),
an offline implementation of the Secret Manager API. This is what GitHub CI uses, so no GCP
credentials are needed there. Alternatively the tests can run against real Google Cloud, see below.

## Running against the emulator

Start the emulator. It listens on port 9090 for gRPC, which is the protocol Web3Signer uses.

```bash
docker compose up
```

Use `CTRL-C` or run `docker compose down` from the same directory but from another shell instance.

Export the following environment variables before running the tests. `GCP_PROJECT_ID` can be any
name: the emulator keeps secrets under whatever project it is asked for.

```bash
export GCP_PROJECT_ID=web3signer-ci
export GCP_EMULATOR_HOST=localhost:9090
```

When `GCP_EMULATOR_HOST` is set, Web3Signer's GCP Secret Manager client connects to the emulator at
that `host:port` over plaintext gRPC without credentials, instead of Google Cloud. Both the
acceptance test, which creates the secrets, and the Web3Signer process it starts, which inherits the
test's environment, read it. Leave the variable unset to talk to real GCP.

To import above in IntelliJ IDEA Run configurations:
```
GCP_PROJECT_ID=web3signer-ci
GCP_EMULATOR_HOST=localhost:9090
```

Run the acceptance tests.

```bash
./gradlew :acceptance-tests:acceptanceTest --tests '*GcpSecretManagerAcceptanceTest*'
```

The emulator does not model project authorization, so
`healthCheckErrorCountWhenInvalidCredentialsAreUsed` is skipped when
`GCP_EMULATOR_HOST` is set. It runs against real Google Cloud only.

## Running against real Google Cloud

The test project must allow creating and deleting secrets, and needs the Secret Manager API
enabled. Use application default credentials, for example:

```bash
gcloud auth application-default login
export GCP_PROJECT_ID=<your-gcp-project-id>
unset GCP_EMULATOR_HOST
./gradlew :acceptance-tests:acceptanceTest --tests '*GcpSecretManagerAcceptanceTest*'
```

The tests create secrets named `signers-gcp-integration-<uuid>...` and delete them afterwards.
