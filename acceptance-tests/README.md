## Acceptance Tests

Following instructions are required to setup environment for running acceptance tests for external vault providers:

### Azure Key Vault

All Azure Key Vault acceptance tests run automatically against a local Testcontainers instance of
the image pinned by `azureKeyVaultEmulatorImage` in `gradle/versions.gradle`, requiring no manual
setup, credentials, or Azure subscription.

### GCP Secret Manager

The GCP Secret Manager acceptance tests run automatically against a local Testcontainers instance of
[gcp-secret-manager-emulator](https://github.com/blackwell-systems/gcp-secret-manager-emulator),
pinned by `gcpSecretManagerEmulatorImage` in `gradle/versions.gradle`, requiring no manual
setup, credentials, or GCP project. Web3Signer reaches the emulator through an nginx container
(`gcpSecretManagerTlsProxyImage`) terminating TLS, configured only with the
`--Xgcp-endpoint-override` option and a throwaway service-account key. As the emulator does not
model authorization, the same nginx container also serves an endpoint answering every call with
HTTP 403 (gRPC `PERMISSION_DENIED`), standing in for real Google Cloud denying access to a project.

To run them against real Google Cloud instead, set `GCP_PROJECT_ID` to a project that allows
creating and deleting secrets, has the Secret Manager API enabled, and is reachable with application
default credentials, for example:

```bash
gcloud auth application-default login
export GCP_PROJECT_ID=<your-gcp-project-id>
./gradlew :acceptance-tests:acceptanceTest --tests '*GcpSecretManagerAcceptanceTest*'
```

The tests create secrets named `signers-gcp-integration-<uuid>...` and delete them afterwards.
