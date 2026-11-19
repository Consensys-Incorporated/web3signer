/*
 * Copyright 2026 Consensys Incorporated.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package tech.pegasys.web3signer.enclave.protocol;

import java.io.Closeable;
import java.io.IOException;
import java.util.List;

/**
 * One pinned connection for {@code ATTEST}, {@code UNWRAP_DEK} and {@code LOAD_KEYS}. The enclave
 * keeps the provisioning state per connection, so nothing here is ever retried. Not thread safe.
 */
public final class ProvisioningSession implements Closeable {
  private final EnclaveClient client;
  private final Connection connection;

  ProvisioningSession(final EnclaveClient client, final Connection connection) {
    this.client = client;
    this.connection = connection;
  }

  public EnclaveStatus status() {
    return Payloads.decodeStatus(call(Protocol.STATUS, Payloads.statusRequest()));
  }

  /**
   * Asks the enclave for an attestation document bound to a fresh RSA key of its own.
   *
   * @param nonce at most 64 bytes, echoed in the document
   */
  public byte[] attest(final byte[] nonce) {
    return Payloads.decodeAttestation(call(Protocol.ATTEST, Payloads.attestRequest(nonce)));
  }

  /** Hands the release blob for the last attestation key to the enclave. */
  public void unwrapDek(final int format, final byte[] blob) {
    Payloads.decodeUnwrapDek(call(Protocol.UNWRAP_DEK, Payloads.unwrapDekRequest(format, blob)));
  }

  /**
   * Loads sealed keys in chunks of at most {@link Protocol#MAX_LOAD_KEYS} and adds up the counts.
   */
  public LoadResult loadKeys(final List<SealedKey> keys) {
    LoadResult total = LoadResult.EMPTY;
    for (int from = 0; from < keys.size(); from += Protocol.MAX_LOAD_KEYS) {
      final List<SealedKey> chunk =
          keys.subList(from, Math.min(keys.size(), from + Protocol.MAX_LOAD_KEYS));
      total =
          total.plus(
              Payloads.decodeLoadKeys(call(Protocol.LOAD_KEYS, Payloads.loadKeysRequest(chunk))));
    }
    return total;
  }

  private byte[] call(final int opcode, final byte[] payload) {
    try {
      return EnclaveClient.exchange(connection, client.nextRequestId(), opcode, payload).payload();
    } catch (final IOException e) {
      connection.close();
      throw new EnclaveUnavailableException(
          "Provisioning connection to " + client.target() + " failed", e);
    }
  }

  @Override
  public void close() {
    connection.close();
  }
}
