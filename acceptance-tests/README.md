## Acceptance Tests

Following instructions are required to setup environment for running acceptance tests for external vault providers:

### Azure Key Vault

All Azure Key Vault acceptance tests run automatically against a local Testcontainers instance of
the image pinned by `azureKeyVaultEmulatorImage` in the root `gradle.properties`, requiring no
manual setup, credentials, or Azure subscription.
