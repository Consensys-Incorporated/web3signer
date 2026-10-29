## Acceptance Tests

Following instructions are required to setup environment for running acceptance tests for external vault providers:

### Azure Key Vault

All Azure Key Vault acceptance tests run automatically against a local Testcontainers instance of
the image pinned by `azureKeyVaultEmulatorImage` in `gradle/versions.gradle`, requiring no manual
setup, credentials, or Azure subscription.

### Hashicorp Vault

Hashicorp Vault acceptance tests start a fresh Testcontainers instance of the image pinned by
`hashicorpVaultImage` in `gradle/versions.gradle` for every test, requiring no manual setup.

### GCP Secret Manager

The GCP Secret Manager acceptance tests run automatically against a local Testcontainers instance of
[gcp-secret-manager-emulator](https://github.com/blackwell-systems/gcp-secret-manager-emulator),
pinned by `gcpSecretManagerEmulatorImage` in `gradle/versions.gradle`, requiring no manual
setup, credentials, or GCP project. Web3Signer reaches the emulator through an nginx container
(`gcpSecretManagerTlsProxyImage`) terminating TLS, configured only with the
`--Xgcp-endpoint-override` option and a throwaway service-account key.

The throwaway key reaches Web3Signer through the `GOOGLE_APPLICATION_CREDENTIALS` environment
variable, which only a Web3Signer subprocess receives. The `acceptanceTest` Gradle task sets
`acctests.runWeb3SignerAsProcess=true`; when running from an IDE, set
`-Dacctests.runWeb3SignerAsProcess=true` too, otherwise the tests are skipped rather than letting
Web3Signer fall back to your real application default credentials.

To run them against real Google Cloud instead, set `GCP_PROJECT_ID` to a project that allows
creating and deleting secrets, has the Secret Manager API enabled, and is reachable with application
default credentials, for example:

```bash
gcloud auth application-default login
export GCP_PROJECT_ID=<your-gcp-project-id>
./gradlew :acceptance-tests:acceptanceTest --tests '*GcpSecretManagerAcceptanceTest*'
```

The tests create secrets named `signers-gcp-integration-<uuid>...` and delete them afterwards.
