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

# 0: running, 1: not running, 2: could not tell (nitro-cli or jq failed)
enclave_state() {
  local out rc=0
  out=$(nitro-cli describe-enclaves) || return 2
  jq -e --arg n "$ENCLAVE_NAME" 'any(.[]; .EnclaveName == $n and .State == "RUNNING")' \
    >/dev/null <<<"$out" || rc=$?
  case "$rc" in
    0 | 1) return "$rc" ;;
    *) return 2 ;;
  esac
}

# A failed query says nothing about the enclave: only a successful query that does not list it
# ends this script, so that a nitro-cli hiccup never makes systemd replace a healthy enclave.
while true; do
  rc=0
  enclave_state || rc=$?
  if [ "$rc" -eq 1 ]; then
    break
  fi
  if [ "$rc" -eq 2 ]; then
    echo "could not query the state of enclave $ENCLAVE_NAME; trying again" >&2
  fi
  sleep 5
done
echo "enclave $ENCLAVE_NAME is no longer running" >&2
exit 1
