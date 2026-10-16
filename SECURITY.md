# Security Policy

This policy applies to the Web3Signer repository and supplements the
[Consensys-Incorporated organization security policy](https://github.com/Consensys-Incorporated/.github/blob/main/SECURITY.md).
Where the two differ, this document takes precedence for Web3Signer.

## Reporting a vulnerability

Report vulnerabilities privately, using either:

- **GitHub private vulnerability reporting:** open the
  [Security tab](https://github.com/Consensys-Incorporated/web3signer/security/advisories)
  and select **Report a vulnerability**, or
- **Email:** [Security-Report@Consensys.com](mailto:Security-Report@Consensys.com)

Do not report security issues through public issues, pull requests, or discussions.

### What to include

- The Web3Signer version, tag, or commit you tested, and how it was deployed: Docker image or
  distribution archive, subcommand (`eth1` or `eth2`), and configuration flags.
- A description of the issue and its potential impact.
- Steps to reproduce, or a proof of concept.
- How we can reach you, and whether and how you would like to be credited.

## What to expect

- We acknowledge reports within **[3 business days]**.
- We aim to complete initial triage within **[10 business days]** and will keep you informed
  through triage and remediation.
- We agree a coordinated disclosure timeline with you. Our default window is **90 days** from the
  report, shorter for issues being actively exploited.
- We credit reporters who wish to be named, in the published advisory.
- Confirmed issues are published as GitHub Security Advisories, with a CVE where appropriate.

## Supported versions

Security fixes are provided for **the latest release only**. Please test against the latest
release before reporting.

## Threat model and deployment assumptions

Web3Signer signs with the keys it loads: BLS validator keys in `eth2` mode and SECP256K1 keys in
`eth1` mode. Please read the
[key best practices](https://docs.web3signer.consensys.com/get-started/key-best-practices)
before assessing impact.

- **Web3Signer does not authenticate or authorize API requests.** There are no API tokens or
  per-endpoint permissions on any HTTP interface: signing endpoints, the Key Manager API, the
  Commit Boost API, the `eth1` JSON-RPC endpoint (including requests it forwards to the
  execution client), `/reload`, and metrics. Optional
  [mutual TLS](https://docs.web3signer.consensys.com/how-to/configure-tls) restricts which
  clients can connect, but a connected client can use every enabled endpoint. The Key Manager
  API does not check the bearer token described in the Ethereum keymanager API specification.
- **Access is expected to be restricted at the network layer** (bind address, firewall rules,
  private networks, or equivalent). Anyone who can reach an enabled interface is treated as
  trusted. Web3Signer must not be exposed to untrusted networks.
- **Defaults:** the HTTP API listens on `127.0.0.1:9000`; the Docker images listen on `0.0.0.0`.
  The Key Manager API (`--key-manager-api-enabled`), the Commit Boost API
  (`--commit-boost-api-enabled`) and metrics (`--metrics-enabled`) are disabled by default.
  Slashing protection is enabled by default in `eth2` mode.

## Scope

### In scope

The following are in scope even when exploiting them requires access to the API:

- Slashing protection bypass or corruption: a slashable block or attestation signed while
  slashing protection is enabled, or its database corrupted through the API or an interchange
  import.
- Exposure or leakage of key material, keystore passwords, keystore contents, or vault and cloud
  credentials, for example through API responses, errors, logs, or metrics.
- Forged or unauthorized signatures: signing with a key the request did not identify, over data
  other than the request describes, or a transaction for a chain ID other than the configured
  `--chain-id`.
- Path traversal or arbitrary file read, write, or deletion through API requests (such as Key
  Manager import and delete, or Commit Boost proxy key generation) or through loaded key data.
- Bypass of TLS client authentication.
- Vulnerabilities that remain exploitable when the deployment follows the documented network
  restrictions.
- Reachable vulnerabilities in dependencies that affect Web3Signer's security.

### Treated as hardening

Reports whose only impact is something a client that can reach Web3Signer is already able to do
by design are generally treated as hardening, for example:

- Missing authentication or authorization on the HTTP interfaces.
- Resource exhaustion or denial of service by a client that can already reach those interfaces.
- Findings that depend on the operator exposing Web3Signer to an untrusted network.

This does not cover the in-scope issues above. We still welcome these reports and will usually fix
worthwhile ones as normal improvements, but we may not publish an advisory or CVE for them. When we
assess severity, we do so in the context of the documented deployment model, not by raw CVSS score
alone.

If you are unsure whether something qualifies, report it privately and we will decide during
triage.

## Good-faith research

Consensys will not pursue or support legal action against researchers who act in good faith and in
accordance with this policy and the organization policy. In particular, please:

- Only access, modify, or store data that is your own or that you have explicit permission to test
  with. Never test against keys or validators that you do not own.
- Avoid privacy violations, data destruction, and degradation or disruption of services.
- Do not use social engineering, phishing, or physical attacks.
- Stop testing and report immediately if you encounter personal or otherwise sensitive data.

## Other notes

- Report vulnerabilities in third-party dependencies to their maintainers, unless Web3Signer's use
  of the dependency creates a distinct issue.
- This policy does not by itself establish a bug bounty program.
- For bugs without a security impact, use the
  [issue tracker](https://github.com/Consensys-Incorporated/web3signer/issues). For support
  questions, use [GitHub Discussions](https://github.com/Consensys-Incorporated/web3signer/discussions).
