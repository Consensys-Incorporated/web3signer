#!/usr/bin/env bash
# Starts the Web3Signer enclave signer in a Nitro Enclave, provisions it with the sealed key
# bundle, then stays in the foreground until the enclave is gone, so that systemd restarts the
# whole sequence.
set -euo pipefail

: "${ENCLAVE_NAME:=web3signer-enclave}"
: "${ENCLAVE_CID:=16}"
: "${ENCLAVE_PORT:=5000}"
: "${ENCLAVE_CPUS:=2}"
: "${ENCLAVE_MEMORY_MIB:=1024}"
: "${EIF:=/opt/web3signer-enclave/web3signer-enclave.eif}"
: "${BUNDLE:=/etc/web3signer-enclave/keys.bundle.json}"
: "${AWS_REGION:=us-east-1}"
: "${WEB3SIGNER:=/opt/web3signer/bin/web3signer}"

nitro-cli terminate-enclave --enclave-name "$ENCLAVE_NAME" >/dev/null 2>&1 || true
nitro-cli run-enclave --enclave-name "$ENCLAVE_NAME" --eif-path "$EIF" \
  --cpu-count "$ENCLAVE_CPUS" --memory "$ENCLAVE_MEMORY_MIB" --enclave-cid "$ENCLAVE_CID"

"$WEB3SIGNER" enclave provision --address="vsock:$ENCLAVE_CID:$ENCLAVE_PORT" --bundle="$BUNDLE" \
  --aws-region="$AWS_REGION" --wait-seconds=60

running() {
  nitro-cli describe-enclaves |
    jq -e --arg n "$ENCLAVE_NAME" 'any(.[]; .EnclaveName == $n and .State == "RUNNING")' >/dev/null
}
while running; do sleep 5; done
echo "enclave $ENCLAVE_NAME is no longer running" >&2
exit 1
