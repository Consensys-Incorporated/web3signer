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
package tech.pegasys.web3signer.enclave.client;

import tech.pegasys.web3signer.enclave.client.EnclaveClient.BodyDecoder;
import tech.pegasys.web3signer.enclave.protocol.Messages;
import tech.pegasys.web3signer.enclave.protocol.Messages.Evidence;
import tech.pegasys.web3signer.enclave.protocol.Messages.LoadResult;
import tech.pegasys.web3signer.enclave.protocol.Messages.SealedKey;
import tech.pegasys.web3signer.enclave.protocol.Messages.Status;
import tech.pegasys.web3signer.enclave.protocol.Messages.UnwrapDekRequest;
import tech.pegasys.web3signer.enclave.protocol.Protocol;
import tech.pegasys.web3signer.enclave.transport.Connection;

import java.io.Closeable;
import java.io.IOException;
import java.util.List;

/**
 * One pinned connection for {@code GET_EVIDENCE}, {@code UNWRAP_DEK} and {@code LOAD_KEYS}. The
 * enclave keeps the provisioning state per connection, so nothing here is ever retried. An I/O
 * error or a malformed answer closes the session. Not thread safe.
 */
public final class ProvisioningSession implements Closeable {
  private final EnclaveClient client;
  private final Connection connection;

  ProvisioningSession(final EnclaveClient client, final Connection connection) {
    this.client = client;
    this.connection = connection;
  }

  public Status status() {
    return send(Protocol.STATUS, Messages.encodeStatusRequest(), Messages::decodeStatus);
  }

  /**
   * Asks the enclave for evidence bound to a fresh release key of its own.
   *
   * @param nonce at most {@value Protocol#MAX_NONCE_SIZE} bytes, bound into the evidence
   */
  public Evidence getEvidence(final byte[] nonce) {
    return send(
        Protocol.GET_EVIDENCE, Messages.encodeEvidenceRequest(nonce), Messages::decodeEvidence);
  }

  /** Hands the release blob for the release key of the last {@code GET_EVIDENCE} to the enclave. */
  public void unwrapDek(final int format, final byte[] blob) {
    send(
        Protocol.UNWRAP_DEK,
        Messages.encodeUnwrapDekRequest(new UnwrapDekRequest(format, blob)),
        body -> {
          Messages.decodeUnwrapDekResponse(body);
          return null;
        });
  }

  /**
   * Loads sealed keys in requests of at most {@value Protocol#MAX_LOAD_KEYS} and adds up the
   * counts.
   *
   * @throws PartialLoadException when a request fails after earlier ones loaded keys; those keys
   *     stay in the enclave, and the exception carries their counts
   */
  public LoadResult loadKeys(final List<SealedKey> keys) {
    LoadResult total = LoadResult.EMPTY;
    for (int from = 0; from < keys.size(); from += Protocol.MAX_LOAD_KEYS) {
      final List<SealedKey> chunk =
          keys.subList(from, Math.min(keys.size(), from + Protocol.MAX_LOAD_KEYS));
      try {
        total =
            total.plus(
                send(
                    Protocol.LOAD_KEYS,
                    Messages.encodeLoadKeysRequest(chunk),
                    Messages::decodeLoadResult));
      } catch (final EnclaveException | EnclaveUnavailableException e) {
        if (from == 0) {
          throw e;
        }
        throw new PartialLoadException(total, e);
      }
    }
    return total;
  }

  private <T> T send(final int opcode, final byte[] body, final BodyDecoder<T> decoder) {
    try {
      return decoder.decode(client.exchange(connection, opcode, body));
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
